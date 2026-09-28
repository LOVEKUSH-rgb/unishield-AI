"""
UniShield AI — Normalized Network Event Model
=============================================
A NetworkEvent is the common internal representation produced by ALL
ingestion sources (PCAP reader, Zeek log adapter, future live capture).

Design principles:
  - Metadata only: no payload bytes stored
  - All fields optional except timestamp (not every protocol has every field)
  - Pydantic v2 for strict validation and JSON serialization
  - Immutable once created (frozen=True)

The ingestion layer produces NetworkEvents.
The flow engine consumes NetworkEvents to build FlowRecords.
"""

from __future__ import annotations

from enum import IntFlag
from typing import Optional
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator, model_validator


# ----------------------------------------------------------------
# TCP flag constants (bitmask)
# ----------------------------------------------------------------

class TCPFlags(IntFlag):
    """TCP flag bitmask — matches Scapy and Zeek conventions."""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    @classmethod
    def from_int(cls, value: int) -> "TCPFlags":
        """Safely convert an integer to TCPFlags, ignoring unknown bits."""
        try:
            return cls(value & 0xFF)
        except ValueError:
            return cls(0)

    def to_dict(self) -> dict[str, bool]:
        return {
            "SYN": bool(self & TCPFlags.SYN),
            "ACK": bool(self & TCPFlags.ACK),
            "FIN": bool(self & TCPFlags.FIN),
            "RST": bool(self & TCPFlags.RST),
            "PSH": bool(self & TCPFlags.PSH),
            "URG": bool(self & TCPFlags.URG),
        }


# ----------------------------------------------------------------
# Protocol constants
# ----------------------------------------------------------------

class Protocol:
    """Well-known IP protocol numbers."""
    TCP = 6
    UDP = 17
    ICMP = 1
    ICMPV6 = 58

    _NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}

    @classmethod
    def name(cls, number: int) -> str:
        return cls._NAMES.get(number, str(number))


# ----------------------------------------------------------------
# DNS sub-model
# ----------------------------------------------------------------

class DNSInfo(BaseModel):
    """Observable DNS metadata — no payload content."""

    model_config = {"frozen": True}

    query_name: Optional[str] = None          # FQDN queried
    query_type: Optional[str] = None          # A, AAAA, TXT, MX, CNAME, etc.
    query_class: Optional[str] = None         # IN, CHAOS, etc.
    response_code: Optional[str] = None       # NOERROR, NXDOMAIN, SERVFAIL, etc.
    answer_count: Optional[int] = None        # number of answers
    is_query: Optional[bool] = None           # True=query, False=response
    transaction_id: Optional[int] = None      # DNS txid (for correlation)
    ttl: Optional[int] = None                 # answer TTL (first record)


# ----------------------------------------------------------------
# TLS sub-model  (NO decryption — handshake metadata only)
# ----------------------------------------------------------------

class TLSInfo(BaseModel):
    """
    Observable TLS/QUIC metadata extracted from handshake records ONLY.

    IMPORTANT: NO payload decryption. All fields come from cleartext
    handshake messages or PCAP-observable record headers.
    """

    model_config = {"frozen": True}

    version: Optional[str] = None             # e.g. "TLS 1.3", "TLS 1.2"
    sni: Optional[str] = None                 # Server Name Indication (cleartext)
    cipher_suite: Optional[str] = None        # cipher suite from ServerHello
    ja3_fingerprint: Optional[str] = None     # JA3 hash (from Zeek/tshark)
    ja3s_fingerprint: Optional[str] = None    # JA3S hash
    cert_subject: Optional[str] = None        # cert CN (if visible, no decryption)
    cert_issuer: Optional[str] = None         # cert issuer
    cert_not_before: Optional[str] = None
    cert_not_after: Optional[str] = None
    is_self_signed: Optional[bool] = None     # True if cert is self-signed
    resumed: Optional[bool] = None            # True if session resumption observed


# ----------------------------------------------------------------
# Core NetworkEvent model
# ----------------------------------------------------------------

class NetworkEvent(BaseModel):
    """
    Normalized network event — the common currency of the ingestion layer.

    Produced by: PcapReader, ZeekLogReader
    Consumed by: FlowManager, FeaturePipeline

    PASSIVE-ONLY AUDIT:
      [PASS] No raw payload stored
      [PASS] No active probing performed
      [PASS] No outbound packet generated
      [PASS] Read-only observation of metadata
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Required
    # ------------------------------------------------------------------
    timestamp: float = Field(
        ...,
        description="UNIX epoch timestamp (seconds, float) from packet header",
    )
    correlation_id: str = Field(
        default_factory=lambda: __import__('uuid').uuid4().hex,
        description="Unique trace identifier for this event",
    )

    # ------------------------------------------------------------------
    # Network layer
    # ------------------------------------------------------------------
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    ip_version: Optional[int] = None          # 4 or 6
    ip_ttl: Optional[int] = None              # TTL / hop limit

    # ------------------------------------------------------------------
    # Transport layer
    # ------------------------------------------------------------------
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[int] = None            # IP protocol number (6=TCP, 17=UDP …)

    # ------------------------------------------------------------------
    # Packet metadata
    # ------------------------------------------------------------------
    packet_length: Optional[int] = None       # total IP packet length in bytes
    payload_length: Optional[int] = None      # transport payload length (bytes)
                                               # NOTE: content NOT stored

    # ------------------------------------------------------------------
    # TCP-specific
    # ------------------------------------------------------------------
    tcp_flags: Optional[int] = None           # raw TCP flags byte (0–255)
    tcp_sequence: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None

    # ------------------------------------------------------------------
    # Application layer metadata
    # ------------------------------------------------------------------
    dns: Optional[DNSInfo] = None
    tls: Optional[TLSInfo] = None

    # ------------------------------------------------------------------
    # Source tracking
    # ------------------------------------------------------------------
    ingestion_source: str = "pcap"            # "pcap" | "zeek_conn" | "zeek_dns" …
    interface: Optional[str] = None           # capture interface name if known
    zeek_uid: Optional[str] = None            # UID from Zeek logs for correlation

    # ------------------------------------------------------------------
    # Aggregation Support (Zeek)
    # ------------------------------------------------------------------
    is_aggregated: bool = False
    aggregated_duration: Optional[float] = None
    aggregated_packet_count: Optional[int] = None
    aggregated_byte_count: Optional[int] = None

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("source_port", "destination_port")
    @classmethod
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 65535):
            raise ValueError(f"Port {v} out of range 0–65535")
        return v

    @field_validator("ip_version")
    @classmethod
    def validate_ip_version(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v not in (4, 6):
            raise ValueError(f"ip_version must be 4 or 6, got {v}")
        return v

    @field_validator("tcp_flags")
    @classmethod
    def validate_tcp_flags(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 255):
            raise ValueError(f"tcp_flags {v} out of byte range")
        return v

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def datetime_utc(self) -> datetime:
        """Return the event timestamp as a UTC-aware datetime."""
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    @property
    def protocol_name(self) -> str:
        """Return a human-readable protocol name."""
        return Protocol.name(self.protocol) if self.protocol is not None else "UNKNOWN"

    @property
    def tcp_flags_parsed(self) -> Optional[TCPFlags]:
        if self.tcp_flags is None:
            return None
        return TCPFlags.from_int(self.tcp_flags)

    @property
    def flow_key(self) -> tuple:
        """
        Return a canonical 5-tuple flow key.

        For bidirectional matching, always puts the numerically smaller
        (ip, port) pair first so that A→B and B→A map to the same key.
        """
        src = (self.source_ip or "", self.source_port or 0)
        dst = (self.destination_ip or "", self.destination_port or 0)
        proto = self.protocol or 0
        if src <= dst:
            return (src[0], src[1], dst[0], dst[1], proto)
        return (dst[0], dst[1], src[0], src[1], proto)

    def is_tcp_syn(self) -> bool:
        """True if this is a TCP SYN (and not SYN-ACK)."""
        if self.tcp_flags is None:
            return False
        flags = TCPFlags.from_int(self.tcp_flags)
        return bool(flags & TCPFlags.SYN) and not bool(flags & TCPFlags.ACK)

    def is_tcp_syn_ack(self) -> bool:
        """True if this is a TCP SYN-ACK."""
        if self.tcp_flags is None:
            return False
        flags = TCPFlags.from_int(self.tcp_flags)
        return bool(flags & TCPFlags.SYN) and bool(flags & TCPFlags.ACK)

    def to_summary(self) -> str:
        """Return a compact one-line summary for logging."""
        return (
            f"{self.datetime_utc.strftime('%H:%M:%S.%f')} "
            f"{self.source_ip}:{self.source_port} → "
            f"{self.destination_ip}:{self.destination_port} "
            f"[{self.protocol_name}] {self.packet_length}B"
        )
