"""
UniShield AI — Zeek Log Reader (Adapter)
=========================================
Reads Zeek-generated TSV log files and converts them into the same
NetworkEvent model produced by the PCAP reader.

Supported log types:
  - conn.log      — connection records (5-tuple + counters)
  - dns.log       — DNS query/response records
  - ssl.log       — TLS/SSL session metadata (NO decryption)
  - http.log      — HTTP metadata (future)

Design:
  The adapter normalises Zeek field names to UniShield's internal model.
  Any field missing from a given Zeek log line is safely set to None.
  Zeek's "-" placeholder (absent value) is treated as None.

PASSIVE AUDIT:
  [PASS] Reads log files only — no network interaction
  [PASS] No active probing
  [PASS] No payload decryption
  [PASS] TLS metadata from ssl.log only (cleartext handshake fields)

Usage:
    from src.ingestion.flow_reader import ZeekLogReader
    for event in ZeekLogReader("conn.log", log_type="conn").stream():
        process(event)
"""

from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import Generator, Iterator, Optional

from src.ingestion.models import DNSInfo, NetworkEvent, TLSInfo
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Zeek uses "-" to represent absent fields
_ZEEK_ABSENT = {"-", "(empty)", ""}

# ----------------------------------------------------------------
# Zeek protocol number mapping (from Zeek's conn.log "proto" field)
# ----------------------------------------------------------------
_ZEEK_PROTO = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "icmp6": 58,
}

# ----------------------------------------------------------------
# DNS record type mapping
# ----------------------------------------------------------------
_DNS_QTYPE = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA",
    "12": "PTR", "15": "MX", "16": "TXT",
    "28": "AAAA", "33": "SRV", "255": "ANY",
}


def _z(value: Optional[str]) -> Optional[str]:
    """Convert a Zeek field to None if it is absent ('-' etc.)."""
    if value is None or value.strip() in _ZEEK_ABSENT:
        return None
    return value.strip()


def _zi(value: Optional[str]) -> Optional[int]:
    """Convert a Zeek field to int, returning None on failure."""
    v = _z(value)
    if v is None:
        return None
    try:
        return int(float(v))  # Zeek sometimes writes "80.0"
    except (ValueError, TypeError):
        return None


def _zf(value: Optional[str]) -> Optional[float]:
    """Convert a Zeek field to float, returning None on failure."""
    v = _z(value)
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def _zb(value: Optional[str]) -> Optional[bool]:
    """Convert a Zeek boolean field ('T'/'F') to Python bool."""
    v = _z(value)
    if v == "T":
        return True
    if v == "F":
        return False
    return None


# ----------------------------------------------------------------
# Zeek log header parser
# ----------------------------------------------------------------

class ZeekTSVReader:
    """
    Reads a Zeek TSV log file, handling the #fields / #types header.

    Zeek TSV logs have comment lines starting with '#' that describe
    column names and types. This reader strips those and provides
    dictionaries keyed by Zeek field names.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fields: list[str] = []

    def _parse_header(self, fh) -> None:
        """Read header lines to extract field names."""
        for line in fh:
            line = line.strip()
            if line.startswith("#fields"):
                self._fields = line.split("\t")[1:]
                return
            if line.startswith("#separator"):
                continue
            if not line.startswith("#"):
                break

    def rows(self) -> Generator[dict, None, None]:
        """Yield each data row as a dict keyed by Zeek field name."""
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            self._parse_header(fh)
            if not self._fields:
                logger.warning("Zeek log has no #fields header", path=str(self.path))
                # Attempt auto-header by reading the first non-comment line
                # (some Zeek versions omit headers)

            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if self._fields:
                    row = dict(zip(self._fields, parts))
                else:
                    row = {str(i): v for i, v in enumerate(parts)}
                yield row


# ----------------------------------------------------------------
# Zeek conn.log parser
# ----------------------------------------------------------------

def _parse_conn_row(row: dict) -> Optional[NetworkEvent]:
    """Convert one Zeek conn.log row to a NetworkEvent."""
    ts = _zf(row.get("ts"))
    if ts is None:
        return None

    proto_str = _z(row.get("proto")) or ""
    protocol = _ZEEK_PROTO.get(proto_str.lower())

    # TCP flags from Zeek history string (e.g. "ShADadfF")
    # We convert Zeek's history to a bitmask approximation.
    tcp_flags = None
    history = _z(row.get("history")) or ""
    if protocol == 6 and history:
        tcp_flags = _zeek_history_to_flags(history)

    return NetworkEvent(
        timestamp=ts,
        source_ip=_z(row.get("id.orig_h")),
        destination_ip=_z(row.get("id.resp_h")),
        source_port=_zi(row.get("id.orig_p")),
        destination_port=_zi(row.get("id.resp_p")),
        protocol=protocol,
        packet_length=None,                     # conn.log has bytes not pkt_len
        payload_length=_zi(row.get("orig_bytes")),
        tcp_flags=tcp_flags,
        ingestion_source="zeek_conn",
    )


def _zeek_history_to_flags(history: str) -> int:
    """
    Approximate TCP flags bitmask from Zeek connection history string.

    Zeek history characters:
      S = SYN (lowercase = responder, uppercase = originator)
      H = SYN-ACK
      A = ACK
      F = FIN
      R = RST
    """
    flags = 0
    h = history.upper()
    if "S" in h:
        flags |= 0x02  # SYN
    if "A" in h:
        flags |= 0x10  # ACK
    if "F" in h:
        flags |= 0x01  # FIN
    if "R" in h:
        flags |= 0x04  # RST
    return flags


# ----------------------------------------------------------------
# Zeek dns.log parser
# ----------------------------------------------------------------

def _parse_dns_row(row: dict) -> Optional[NetworkEvent]:
    """Convert one Zeek dns.log row to a NetworkEvent with DNSInfo."""
    ts = _zf(row.get("ts"))
    if ts is None:
        return None

    qtype_raw = _z(row.get("qtype")) or ""
    qtype_str = _DNS_QTYPE.get(qtype_raw, _z(row.get("qtype_name")) or qtype_raw or None)

    rcode_str = _z(row.get("rcode_name"))

    dns_info = DNSInfo(
        query_name=_z(row.get("query")),
        query_type=qtype_str,
        response_code=rcode_str,
        answer_count=_zi(row.get("answers")) or 0,
        is_query=(not bool(_zb(row.get("QR")))),  # Zeek QR: 0=query, 1=response
        transaction_id=_zi(row.get("trans_id")),
        ttl=_zi(row.get("TTLs")),
    )

    return NetworkEvent(
        timestamp=ts,
        source_ip=_z(row.get("id.orig_h")),
        destination_ip=_z(row.get("id.resp_h")),
        source_port=_zi(row.get("id.orig_p")),
        destination_port=_zi(row.get("id.resp_p")),
        protocol=17,   # DNS is UDP (typically)
        dns=dns_info,
        ingestion_source="zeek_dns",
    )


# ----------------------------------------------------------------
# Zeek ssl.log parser  (NO decryption)
# ----------------------------------------------------------------

def _parse_ssl_row(row: dict) -> Optional[NetworkEvent]:
    """
    Convert one Zeek ssl.log row to a NetworkEvent with TLSInfo.

    PASSIVE: ssl.log only contains cleartext handshake metadata:
    version, cipher, SNI, cert subject — nothing decrypted.
    """
    ts = _zf(row.get("ts"))
    if ts is None:
        return None

    tls_info = TLSInfo(
        version=_z(row.get("version")),
        sni=_z(row.get("server_name")),
        cipher_suite=_z(row.get("cipher")),
        ja3_fingerprint=_z(row.get("ja3")),
        ja3s_fingerprint=_z(row.get("ja3s")),
        cert_subject=_z(row.get("subject")),
        cert_issuer=_z(row.get("issuer")),
        cert_not_before=_z(row.get("not_valid_before")),
        cert_not_after=_z(row.get("not_valid_after")),
        resumed=_zb(row.get("resumed")),
    )

    return NetworkEvent(
        timestamp=ts,
        source_ip=_z(row.get("id.orig_h")),
        destination_ip=_z(row.get("id.resp_h")),
        source_port=_zi(row.get("id.orig_p")),
        destination_port=_zi(row.get("id.resp_p")),
        protocol=6,    # TLS runs over TCP
        tls=tls_info,
        ingestion_source="zeek_ssl",
    )


# ----------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------

_LOG_PARSERS = {
    "conn": _parse_conn_row,
    "dns":  _parse_dns_row,
    "ssl":  _parse_ssl_row,
}


class ZeekLogReader:
    """
    Reads a Zeek log file and yields NetworkEvent objects.

    Parameters
    ----------
    log_path:
        Path to the Zeek log file (conn.log, dns.log, ssl.log).
    log_type:
        One of: "conn", "dns", "ssl".
        Auto-detected from file name if not provided.
    """

    def __init__(
        self,
        log_path: str | Path,
        log_type: Optional[str] = None,
    ) -> None:
        self.log_path = Path(log_path)
        if not self.log_path.exists():
            raise FileNotFoundError(f"Zeek log not found: {self.log_path}")

        # Auto-detect log type from filename
        if log_type is None:
            stem = self.log_path.stem.lower()
            for known in ("conn", "dns", "ssl", "http"):
                if known in stem:
                    log_type = known
                    break

        if log_type not in _LOG_PARSERS:
            raise ValueError(
                f"Unsupported log type: '{log_type}'. "
                f"Supported: {list(_LOG_PARSERS.keys())}"
            )

        self.log_type = log_type
        self._parser = _LOG_PARSERS[log_type]
        logger.info(
            "ZeekLogReader initialised",
            path=str(self.log_path),
            log_type=log_type,
        )

    def stream(self) -> Generator[NetworkEvent, None, None]:
        """Yield NetworkEvent objects from the Zeek log file."""
        processed = 0
        skipped = 0
        errors = 0

        tsv = ZeekTSVReader(self.log_path)

        for row in tsv.rows():
            try:
                event = self._parser(row)
                if event is not None:
                    processed += 1
                    yield event
                else:
                    skipped += 1
            except Exception as exc:
                errors += 1
                logger.warning(
                    "Failed to parse Zeek row",
                    log_type=self.log_type,
                    error=str(exc),
                )

        logger.info(
            "Zeek log stream complete",
            log_type=self.log_type,
            processed=processed,
            skipped=skipped,
            errors=errors,
        )
