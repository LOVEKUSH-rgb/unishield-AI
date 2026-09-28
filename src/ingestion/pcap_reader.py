"""
UniShield AI — PCAP Reader (Passive)
=====================================
Reads PCAP files using Scapy in read-only mode and yields
NetworkEvent objects containing ONLY observable metadata.

PASSIVE-ONLY GUARANTEES:
  [PASS] No packets are transmitted
  [PASS] No active probing or scanning
  [PASS] No connections initiated
  [PASS] No TCP handshakes completed
  [PASS] No payload bytes stored
  [PASS] No payload decryption attempted

The reader is a Python generator — packets are processed
one at a time without loading the entire PCAP into memory.

Usage (CLI):
    python -m src.ingestion.pcap_reader path/to/capture.pcap

Usage (library):
    from src.ingestion.pcap_reader import PcapReader
    for event in PcapReader("capture.pcap").stream():
        process(event)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

from src.ingestion.models import DNSInfo, NetworkEvent, TLSInfo, TCPFlags
from src.utils.logging import get_logger
from src.utils.metrics import pipeline_metrics

logger = get_logger(__name__)


# ----------------------------------------------------------------
# Scapy imports — lazy to keep import time fast when Scapy is not
# needed (e.g. unit tests that use synthetic events directly).
# ----------------------------------------------------------------

def _import_scapy():
    """Import Scapy layers. Raises ImportError with a helpful message if missing."""
    try:
        from scapy.all import rdpcap, PcapReader as ScapyPcapReader  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP, ICMP              # type: ignore
        from scapy.layers.inet6 import IPv6                           # type: ignore
        from scapy.layers.dns import DNS, DNSQR, DNSRR               # type: ignore
        from scapy.layers.tls.all import TLS                          # type: ignore
        return {
            "ScapyPcapReader": ScapyPcapReader,
            "IP": IP, "TCP": TCP, "UDP": UDP, "ICMP": ICMP,
            "IPv6": IPv6,
            "DNS": DNS, "DNSQR": DNSQR, "DNSRR": DNSRR,
            "TLS": TLS,
        }
    except ImportError as exc:
        raise ImportError(
            "Scapy is required for PCAP ingestion. "
            "Install with: pip install scapy"
        ) from exc


# ----------------------------------------------------------------
# Processing statistics (reset per reader instance)
# ----------------------------------------------------------------

@dataclass
class IngestionStats:
    """Counters accumulated during a single PCAP processing run."""
    packets_processed: int = 0
    packets_skipped: int = 0
    events_produced: int = 0
    parse_errors: int = 0
    malformed_packets: int = 0
    dns_events: int = 0
    tls_events: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed_seconds(self) -> float:
        return max(time.time() - self.start_time, 1e-9)

    @property
    def packets_per_second(self) -> float:
        return self.packets_processed / self.elapsed_seconds

    def to_dict(self) -> dict:
        return {
            "packets_processed": self.packets_processed,
            "packets_skipped": self.packets_skipped,
            "events_produced": self.events_produced,
            "parse_errors": self.parse_errors,
            "malformed_packets": self.malformed_packets,
            "dns_events": self.dns_events,
            "tls_events": self.tls_events,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "packets_per_second": round(self.packets_per_second, 2),
        }


# ----------------------------------------------------------------
# Main reader
# ----------------------------------------------------------------

class PcapReader:
    """
    Passive PCAP reader.

    Streams packets from a PCAP file, extracts observable metadata,
    and yields NetworkEvent objects.

    Parameters
    ----------
    pcap_path:
        Path to the PCAP file.
    max_packets:
        If set, stop after processing this many packets.
    """

    def __init__(
        self,
        pcap_path: str | Path,
        max_packets: Optional[int] = None,
    ) -> None:
        self.pcap_path = Path(pcap_path)
        self.max_packets = max_packets
        self.stats = IngestionStats()

        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
        if not self.pcap_path.is_file():
            raise ValueError(f"Not a regular file: {self.pcap_path}")

        logger.info(
            "PcapReader initialised",
            path=str(self.pcap_path),
            max_packets=max_packets,
        )

    # ----------------------------------------------------------------
    # Main generator
    # ----------------------------------------------------------------

    def stream(self) -> Generator[NetworkEvent, None, None]:
        """
        Yield NetworkEvent objects one at a time from the PCAP.

        This is the primary interface. The caller drives iteration;
        no buffering occurs inside this generator beyond one packet.

        Yields
        ------
        NetworkEvent
            Normalised metadata for each parseable packet.
        """
        layers = _import_scapy()
        ScapyPcapReader = layers["ScapyPcapReader"]

        logger.info("Starting PCAP stream", path=str(self.pcap_path))
        self.stats = IngestionStats()

        try:
            with ScapyPcapReader(str(self.pcap_path)) as reader:
                for raw_packet in reader:
                    if (
                        self.max_packets is not None
                        and self.stats.packets_processed >= self.max_packets
                    ):
                        logger.debug(
                            "Reached max_packets limit",
                            limit=self.max_packets,
                        )
                        break

                    self.stats.packets_processed += 1
                    pipeline_metrics.record_packet()

                    event = self._parse_packet(raw_packet, layers)
                    if event is not None:
                        self.stats.events_produced += 1
                        pipeline_metrics.record_packet()
                        yield event
                    else:
                        self.stats.packets_skipped += 1

        except Exception as exc:
            logger.error(
                "Fatal error reading PCAP",
                path=str(self.pcap_path),
                error=str(exc),
            )
            raise

        finally:
            logger.info(
                "PCAP stream complete",
                **self.stats.to_dict(),
            )

    # ----------------------------------------------------------------
    # Packet parser
    # ----------------------------------------------------------------

    def _parse_packet(self, pkt, layers: dict) -> Optional[NetworkEvent]:
        """
        Extract observable metadata from a single Scapy packet.

        Returns None for packets that cannot be parsed or have no
        relevant network-layer information (e.g. pure L2 frames).

        PASSIVE AUDIT: No bytes of packet payload are stored.
        """
        IP = layers["IP"]
        IPv6 = layers["IPv6"]
        TCP = layers["TCP"]
        UDP = layers["UDP"]

        try:
            # ---- Timestamp ----
            try:
                timestamp = float(pkt.time)
            except (AttributeError, TypeError):
                self.stats.malformed_packets += 1
                logger.debug("Packet missing timestamp — skipping")
                return None

            # ---- IP layer ----
            src_ip = dst_ip = None
            ip_version = ip_ttl = None

            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ip_version = 4
                ip_ttl = ip.ttl
            elif pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                ip_version = 6
                ip_ttl = ip6.hlim
            else:
                # Non-IP frame — skip (not relevant to our analytics)
                self.stats.packets_skipped += 1
                return None

            # ---- Transport layer ----
            src_port = dst_port = None
            protocol = None
            tcp_flags = tcp_seq = tcp_ack = tcp_win = None
            payload_len = 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = 6
                tcp_flags = int(tcp.flags)
                tcp_seq = tcp.seq
                tcp_ack = tcp.ack
                tcp_win = tcp.window
                payload_len = len(tcp.payload)

            elif pkt.haslayer(layers["UDP"]):
                udp = pkt[layers["UDP"]]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = 17
                payload_len = len(udp.payload)

            elif pkt.haslayer(layers["ICMP"]):
                protocol = 1
            else:
                # Try to get protocol from IP header
                if pkt.haslayer(IP):
                    protocol = pkt[IP].proto

            # ---- Packet length ----
            try:
                pkt_len = len(pkt)
            except Exception:
                pkt_len = None

            # ---- DNS metadata ----
            dns_info = self._extract_dns(pkt, layers)
            if dns_info:
                self.stats.dns_events += 1

            # ---- TLS metadata ----
            tls_info = self._extract_tls(pkt, layers)
            if tls_info:
                self.stats.tls_events += 1

            return NetworkEvent(
                timestamp=timestamp,
                source_ip=src_ip,
                destination_ip=dst_ip,
                ip_version=ip_version,
                ip_ttl=ip_ttl,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_length=pkt_len,
                payload_length=payload_len,
                tcp_flags=tcp_flags,
                tcp_sequence=tcp_seq,
                tcp_ack=tcp_ack,
                tcp_window=tcp_win,
                dns=dns_info,
                tls=tls_info,
                ingestion_source="pcap",
            )

        except Exception as exc:
            self.stats.parse_errors += 1
            logger.warning(
                "Failed to parse packet",
                error=str(exc),
                packet_num=self.stats.packets_processed,
            )
            return None

    # ----------------------------------------------------------------
    # DNS extractor
    # ----------------------------------------------------------------

    def _extract_dns(self, pkt, layers: dict) -> Optional[DNSInfo]:
        """
        Extract observable DNS metadata.

        Returns None if no DNS layer present.
        PASSIVE: Only reads query/response metadata — no payload decryption.
        """
        DNS = layers["DNS"]
        DNSQR = layers["DNSQR"]

        if not pkt.haslayer(DNS):
            return None

        try:
            dns = pkt[DNS]
            query_name = query_type = query_class = None
            response_code = None
            answer_count = None

            # Query record
            if dns.haslayer(DNSQR):
                qr = dns[DNSQR]
                try:
                    raw_name = qr.qname
                    query_name = (
                        raw_name.decode("utf-8", errors="replace").rstrip(".")
                        if isinstance(raw_name, bytes)
                        else str(raw_name).rstrip(".")
                    )
                except Exception:
                    query_name = None

                try:
                    qt = int(qr.qtype)
                    _TYPE_MAP = {
                        1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
                        12: "PTR", 15: "MX", 16: "TXT",
                        28: "AAAA", 33: "SRV", 255: "ANY",
                    }
                    query_type = _TYPE_MAP.get(qt, str(qt))
                except Exception:
                    query_type = None

            # Response code
            try:
                _RCODE_MAP = {
                    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
                    3: "NXDOMAIN", 5: "REFUSED",
                }
                rcode = int(dns.rcode)
                response_code = _RCODE_MAP.get(rcode, str(rcode))
            except Exception:
                response_code = None

            # Answer count
            try:
                answer_count = int(dns.ancount)
            except Exception:
                answer_count = None

            return DNSInfo(
                query_name=query_name,
                query_type=query_type,
                response_code=response_code,
                answer_count=answer_count,
                is_query=bool(dns.qr == 0),
                transaction_id=int(dns.id) if dns.id is not None else None,
            )

        except Exception as exc:
            logger.debug("DNS extraction failed", error=str(exc))
            return None

    # ----------------------------------------------------------------
    # TLS extractor (NO decryption)
    # ----------------------------------------------------------------

    def _extract_tls(self, pkt, layers: dict) -> Optional[TLSInfo]:
        """
        Extract TLS metadata from handshake records ONLY.

        PASSIVE: No decryption. Only reads cleartext handshake fields
        (ClientHello SNI, TLS version, cipher suite).
        """
        TLS = layers["TLS"]

        if not pkt.haslayer(TLS):
            return None

        try:
            tls_layer = pkt[TLS]
            version_str = None
            sni = None

            # Try to read TLS version
            try:
                v = tls_layer.version
                _VER_MAP = {
                    0x0300: "SSL 3.0",
                    0x0301: "TLS 1.0",
                    0x0302: "TLS 1.1",
                    0x0303: "TLS 1.2",
                    0x0304: "TLS 1.3",
                }
                version_str = _VER_MAP.get(v, f"0x{v:04x}" if v else None)
            except Exception:
                version_str = None

            # Try to extract SNI from ClientHello extensions
            try:
                if hasattr(tls_layer, "msg") and tls_layer.msg:
                    for msg in tls_layer.msg:
                        if hasattr(msg, "ext"):
                            for ext in msg.ext:
                                if hasattr(ext, "servernames"):
                                    for sn in ext.servernames:
                                        if hasattr(sn, "servername"):
                                            raw = sn.servername
                                            sni = (
                                                raw.decode("utf-8", errors="replace")
                                                if isinstance(raw, bytes)
                                                else str(raw)
                                            )
                                            break
            except Exception:
                sni = None

            if version_str is None and sni is None:
                return None

            return TLSInfo(version=version_str, sni=sni)

        except Exception as exc:
            logger.debug("TLS extraction failed", error=str(exc))
            return None


# ----------------------------------------------------------------
# Module-level CLI
# ----------------------------------------------------------------

def _run_cli(pcap_path: str, max_packets: Optional[int] = None) -> None:
    """
    CLI entry point: process a PCAP and print processing statistics.

    Metrics reported are actual runtime measurements — nothing invented.
    """
    from src.utils.logging import configure_logging
    configure_logging(level="INFO")

    reader = PcapReader(pcap_path, max_packets=max_packets)

    event_count = 0
    dns_count = 0
    tls_count = 0

    for event in reader.stream():
        event_count += 1
        if event.dns:
            dns_count += 1
        if event.tls:
            tls_count += 1

    stats = reader.stats
    print("\n" + "=" * 50)
    print("  UniShield AI — PCAP Ingestion Summary")
    print("=" * 50)
    print(f"  File             : {pcap_path}")
    print(f"  Packets read     : {stats.packets_processed}")
    print(f"  Packets skipped  : {stats.packets_skipped}")
    print(f"  Events produced  : {stats.events_produced}")
    print(f"  Parse errors     : {stats.parse_errors}")
    print(f"  DNS events       : {stats.dns_events}")
    print(f"  TLS events       : {stats.tls_events}")
    print(f"  Processing time  : {stats.elapsed_seconds:.3f} s")
    print(f"  Throughput       : {stats.packets_per_second:.1f} pkt/s")
    print("=" * 50)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="UniShield AI — Passive PCAP Reader"
    )
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop after N packets (default: read all)",
    )
    args = parser.parse_args()
    _run_cli(args.pcap, max_packets=args.max_packets)
