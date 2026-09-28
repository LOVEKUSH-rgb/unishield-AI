"""
UniShield AI — FlowRecord
==========================
A FlowRecord tracks all observable metadata for a single network flow,
identified by a canonical 5-tuple key.

Design:
  - FlowRecord is intentionally MUTABLE — it is updated as packets arrive
  - All heavy statistics (IAT, packet sizes) are stored as lists for
    later feature extraction; the lists are bounded by max_samples from config
  - Flow direction is normalised at creation time
  - Completed flows are sealed (frozen for the feature pipeline)

PASSIVE AUDIT:
  [PASS] No packets transmitted
  [PASS] Only observes packet metadata — no payload stored
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from src.ingestion.models import NetworkEvent, TCPFlags
from src.utils.time import duration_seconds, safe_divide
from src.utils.config import get_config


# Load limits from config once
def _max_samples() -> int:
    try:
        return get_config()["features"]["timing"]["iat_max_samples"]
    except (KeyError, TypeError):
        return 1000


# ----------------------------------------------------------------
# TCP flag counters
# ----------------------------------------------------------------

@dataclass
class TCPFlagCounts:
    """Counts of each TCP flag type observed across the flow."""
    syn: int = 0
    syn_ack: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0

    def update(self, flags_int: int) -> None:
        """Update counts from a raw TCP flags byte."""
        flags = TCPFlags.from_int(flags_int)
        if flags & TCPFlags.SYN and flags & TCPFlags.ACK:
            self.syn_ack += 1
        elif flags & TCPFlags.SYN:
            self.syn += 1
        if flags & TCPFlags.ACK and not (flags & TCPFlags.SYN):
            self.ack += 1
        if flags & TCPFlags.FIN:
            self.fin += 1
        if flags & TCPFlags.RST:
            self.rst += 1
        if flags & TCPFlags.PSH:
            self.psh += 1
        if flags & TCPFlags.URG:
            self.urg += 1

    def to_dict(self) -> dict:
        return {
            "syn": self.syn,
            "syn_ack": self.syn_ack,
            "ack": self.ack,
            "fin": self.fin,
            "rst": self.rst,
            "psh": self.psh,
            "urg": self.urg,
        }


# ----------------------------------------------------------------
# FlowRecord
# ----------------------------------------------------------------

@dataclass
class FlowRecord:
    """
    Tracks all observable metadata for a single network flow.

    A flow is identified by its 5-tuple key:
      (src_ip, src_port, dst_ip, dst_port, protocol)

    FlowRecords are created by FlowManager and updated as
    matching packets arrive. They are "completed" when the flow
    times out or a FIN/RST is observed.

    Attributes
    ----------
    flow_id:
        UUID string uniquely identifying this flow instance.
    flow_key:
        Canonical 5-tuple (src_ip, src_port, dst_ip, dst_port, proto).
    source_ip, destination_ip, source_port, destination_port, protocol:
        The authoritative 5-tuple as observed.
    start_time:
        UNIX timestamp of first packet.
    last_seen:
        UNIX timestamp of most recent packet.
    packet_count:
        Total packets observed.
    byte_count:
        Total bytes observed.
    packet_sizes:
        List of per-packet lengths (bounded by max_samples).
    inter_arrival_times:
        List of IAT values in seconds (bounded by max_samples).
    tcp_flags:
        Per-flag counters for TCP flows.
    completed:
        True if the flow has been closed (FIN/RST or timeout).
    """

    flow_id: str
    flow_key: tuple
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[int]

    start_time: float
    last_seen: float
    correlation_id: str = field(default_factory=lambda: __import__('uuid').uuid4().hex)

    packet_count: int = 0
    byte_count: int = 0

    # Bounded lists for feature extraction
    packet_sizes: List[int] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)

    tcp_flags: TCPFlagCounts = field(default_factory=TCPFlagCounts)
    completed: bool = False
    
    last_dns_event: Optional[Any] = field(default=None, repr=False)
    last_tls_event: Optional[Any] = field(default=None, repr=False)

    # ------------------------------------------------------------------
    # Class-level max sample size (read from config at import time)
    # ------------------------------------------------------------------
    _max_samples: int = field(default_factory=_max_samples, init=False, repr=False)

    @classmethod
    def from_event(cls, event: NetworkEvent) -> "FlowRecord":
        """
        Create a new FlowRecord from the first packet of a flow.

        Parameters
        ----------
        event:
            The first NetworkEvent for this flow.

        Returns
        -------
        FlowRecord
            Initialised with packet 1 already recorded.
        """
        flow = cls(
            flow_id=str(uuid.uuid4()),
            flow_key=event.flow_key,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            start_time=event.timestamp,
            last_seen=event.timestamp,
            correlation_id=event.correlation_id,
        )
        flow.update(event)
        return flow

    # ------------------------------------------------------------------
    # Incremental update
    # ------------------------------------------------------------------

    def update(self, event: NetworkEvent) -> None:
        """
        Update the flow with a new packet's metadata.

        Parameters
        ----------
        event:
            A NetworkEvent belonging to this flow.
        """
        if event.is_aggregated:
            self.packet_count = event.aggregated_packet_count or 0
            self.byte_count = event.aggregated_byte_count or 0
            self.last_seen = event.timestamp + (event.aggregated_duration or 0.0)
            self.completed = True
        else:
            # Compute IAT before updating last_seen
            if self.packet_count > 0:
                iat = event.timestamp - self.last_seen
                if len(self.inter_arrival_times) < self._max_samples:
                    self.inter_arrival_times.append(max(0.0, iat))

            self.last_seen = event.timestamp
            self.packet_count += 1

            pkt_len = event.packet_length or 0
            self.byte_count += pkt_len
            if len(self.packet_sizes) < self._max_samples:
                self.packet_sizes.append(pkt_len)

        # TCP flags
        if event.tcp_flags is not None:
            self.tcp_flags.update(event.tcp_flags)

        # Check for FIN/RST — signals flow completion
        if event.tcp_flags is not None:
            flags = TCPFlags.from_int(event.tcp_flags)
            if flags & TCPFlags.FIN or flags & TCPFlags.RST:
                self.completed = True

        if getattr(event, "dns", None) is not None:
            self.last_dns_event = event
        if getattr(event, "tls", None) is not None:
            self.last_tls_event = event

    # ------------------------------------------------------------------
    # Derived statistics (computed on demand)
    # ------------------------------------------------------------------

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return duration_seconds(self.start_time, self.last_seen)

    @property
    def packets_per_second(self) -> float:
        return safe_divide(self.packet_count, self.duration)

    @property
    def bytes_per_second(self) -> float:
        return safe_divide(self.byte_count, self.duration)

    @property
    def mean_packet_size(self) -> float:
        if not self.packet_sizes:
            return 0.0
        return sum(self.packet_sizes) / len(self.packet_sizes)

    @property
    def min_packet_size(self) -> Optional[int]:
        return min(self.packet_sizes) if self.packet_sizes else None

    @property
    def max_packet_size(self) -> Optional[int]:
        return max(self.packet_sizes) if self.packet_sizes else None

    @property
    def flow_id_str(self) -> str:
        """Human-readable flow identifier for logging."""
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(self.protocol or 0, "?")
        return (
            f"{self.source_ip}:{self.source_port}"
            f"->{self.destination_ip}:{self.destination_port}"
            f"/{proto_name}"
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable summary of this flow."""
        return {
            "flow_id": self.flow_id,
            "correlation_id": self.correlation_id,
            "flow_key": list(self.flow_key),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration_seconds": round(self.duration, 6),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packets_per_second": round(self.packets_per_second, 4),
            "bytes_per_second": round(self.bytes_per_second, 4),
            "mean_packet_size": round(self.mean_packet_size, 2),
            "min_packet_size": self.min_packet_size,
            "max_packet_size": self.max_packet_size,
            "tcp_flags": self.tcp_flags.to_dict(),
            "completed": self.completed,
        }
