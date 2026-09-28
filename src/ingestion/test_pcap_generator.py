"""
UniShield AI -- Synthetic Test PCAP Generator
=============================================
Generates a small, clearly-labelled synthetic PCAP file for unit testing.

IMPORTANT:
  This data is SYNTHETIC and DOES NOT represent real attack traffic.
  It is generated solely to enable unit tests without requiring a
  real network capture file.

Contents generated:
  - Normal HTTP-like TCP connections
  - DNS queries and responses
  - A short UDP flow
  - Packets with various TCP flag combinations
  - A few packets with missing/minimal headers for robustness testing

Output: data/samples/test_synthetic.pcap

Usage:
    python -m src.ingestion.test_pcap_generator
    python -c "from src.ingestion.test_pcap_generator import generate; generate()"
"""

from __future__ import annotations

from pathlib import Path
from typing import List


def generate(output_path=None) -> Path:
    """
    Generate a synthetic PCAP for unit testing.

    Parameters
    ----------
    output_path:
        Where to write the PCAP. Defaults to data/samples/test_synthetic.pcap.

    Returns
    -------
    Path
        The path to the generated PCAP file.

    Note
    ----
    Uses Scapy to construct packets in memory and write them.
    NO packets are transmitted to the network.
    Uses raw IP packets (no Ethernet frame) to avoid needing WinPcap/Npcap.
    """
    # Suppress Scapy's noisy startup warnings on Windows
    import logging as _logging
    _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
    _logging.getLogger("scapy.loading").setLevel(_logging.ERROR)

    import warnings
    warnings.filterwarnings("ignore")

    from scapy.all import wrpcap  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore

    if output_path is None:
        project_root = Path(__file__).parents[2]
        output_path = project_root / "data" / "samples" / "test_synthetic.pcap"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packets = []
    base_ts = 1_700_000_000.0  # Fixed timestamp for reproducibility

    # ----------------------------------------------------------------
    # Scenario 1: Normal TCP HTTP connection (SYN -> SYN-ACK -> ACK -> FIN)
    # ----------------------------------------------------------------
    client = "192.168.1.100"
    server = "10.0.0.1"

    # SYN
    p = IP(src=client, dst=server, ttl=64) / TCP(
        sport=54321, dport=80, flags="S", seq=1000
    )
    p.time = base_ts
    packets.append(p)

    # SYN-ACK
    p = IP(src=server, dst=client, ttl=64) / TCP(
        sport=80, dport=54321, flags="SA", seq=2000, ack=1001
    )
    p.time = base_ts + 0.002
    packets.append(p)

    # ACK
    p = IP(src=client, dst=server, ttl=64) / TCP(
        sport=54321, dport=80, flags="A", seq=1001, ack=2001
    )
    p.time = base_ts + 0.004
    packets.append(p)

    # Data (PSH+ACK) -- NOTE: payload content not stored in NetworkEvent
    p = IP(src=client, dst=server, ttl=64) / TCP(
        sport=54321, dport=80, flags="PA", seq=1001, ack=2001
    ) / b"GET / HTTP/1.1\r\n\r\n"
    p.time = base_ts + 0.010
    packets.append(p)

    # FIN
    p = IP(src=client, dst=server, ttl=64) / TCP(
        sport=54321, dport=80, flags="FA", seq=1050, ack=2001
    )
    p.time = base_ts + 0.100
    packets.append(p)

    # ----------------------------------------------------------------
    # Scenario 2: DNS query/response (UDP port 53)
    # ----------------------------------------------------------------
    dns_client = "192.168.1.101"
    dns_server = "8.8.8.8"

    # DNS query
    p = IP(src=dns_client, dst=dns_server, ttl=64) / UDP(
        sport=12345, dport=53
    ) / DNS(
        id=0xABCD,
        qr=0,
        rd=1,
        qd=DNSQR(qname="example.com.", qtype="A"),
    )
    p.time = base_ts + 0.200
    packets.append(p)

    # DNS response
    p = IP(src=dns_server, dst=dns_client, ttl=128) / UDP(
        sport=53, dport=12345
    ) / DNS(
        id=0xABCD,
        qr=1,
        aa=0,
        rd=1,
        ra=1,
        qd=DNSQR(qname="example.com.", qtype="A"),
        an=DNSRR(rrname="example.com.", rdata="93.184.216.34", ttl=300),
    )
    p.time = base_ts + 0.205
    packets.append(p)

    # ----------------------------------------------------------------
    # Scenario 3: UDP flow (non-DNS, e.g. syslog)
    # ----------------------------------------------------------------
    for i in range(5):
        p = IP(src="192.168.1.102", dst="10.0.0.2", ttl=64) / UDP(
            sport=9999, dport=514
        ) / b"SYNTHETIC LOG"
        p.time = base_ts + 0.300 + i * 0.050
        packets.append(p)

    # ----------------------------------------------------------------
    # Scenario 4: RST (abrupt connection close)
    # ----------------------------------------------------------------
    p = IP(src=client, dst=server, ttl=64) / TCP(
        sport=54322, dport=443, flags="S", seq=5000
    )
    p.time = base_ts + 0.500
    packets.append(p)

    p = IP(src=server, dst=client, ttl=64) / TCP(
        sport=443, dport=54322, flags="R", seq=0, ack=5001
    )
    p.time = base_ts + 0.502
    packets.append(p)

    # ----------------------------------------------------------------
    # Scenario 5: Multi-port SYN sweep from single source (fan-out test)
    # ----------------------------------------------------------------
    scanner_ip = "192.168.1.200"
    for port in [22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432]:
        p = IP(src=scanner_ip, dst="10.0.0.5", ttl=64) / TCP(
            sport=40000 + port, dport=port, flags="S", seq=1000
        )
        p.time = base_ts + 1.0 + port * 0.001
        packets.append(p)

    # ----------------------------------------------------------------
    # Write PCAP
    # ----------------------------------------------------------------
    wrpcap(str(output_path), packets)

    count = len(packets)
    print(f"[SYNTHETIC DATA] Generated {count} packets -> {output_path}")
    print("  WARNING: This PCAP is synthetic test data only.")
    print("  Do NOT use these packets as real benchmark data.")
    return output_path


if __name__ == "__main__":
    path = generate()
    print(f"Written to: {path}")
