"""
UniShield AI -- Behavioral Features
======================================
Aggregates network behavior statistics over configurable time windows,
grouped by source IP and destination IP.

Features produced PER SOURCE IP (window-based):

  uniq_dst_hosts_Xs       -- unique destination hosts in X-second window
  uniq_dst_ports_Xs       -- unique destination ports in X-second window
  conn_count_Xs           -- connection (flow) count
  bytes_out_Xs            -- total outbound bytes
  pkts_out_Xs             -- total outbound packets
  avg_flow_duration_Xs    -- average flow duration
  src_entropy_Xs          -- entropy of destination IP distribution

Features produced PER DESTINATION IP (window-based):

  uniq_src_hosts_Xs       -- unique source hosts
  src_concentration_Xs    -- 1 - normalised_entropy of source IPs
                             (high = traffic concentrated from few sources)
  dst_conn_count_Xs       -- number of connections to this destination

These features will be used by:
  - DDoS detector (conn_count, bytes_out, uniq_src_hosts)
  - Recon detector (uniq_dst_hosts, uniq_dst_ports)
  - Exfiltration detector (bytes_out, avg_flow_duration)
  - C2 detector (conn_count, uniq_dst_hosts patterns)

IMPORTANT: This module aggregates observations. It does NOT classify.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from src.features.entropy_features import ip_set_entropy, normalised_entropy
from src.features.windowing import TimeWindow, WindowSet
from src.utils.config import get_config
from src.utils.logging import get_logger
import ipaddress

logger = get_logger(__name__)

def _get_subnet(ip_str: str) -> str:
    """Returns /24 for IPv4 or /64 for IPv6, safely."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return str(ipaddress.IPv4Network(f"{ip_str}/24", strict=False))
        else:
            return str(ipaddress.IPv6Network(f"{ip_str}/64", strict=False))
    except ValueError:
        return ip_str  # fallback for invalid IPs


def _get_window_sizes() -> List[float]:
    """Read configured window sizes."""
    try:
        w = get_config()["flows"]["sliding_window_seconds"]
        if isinstance(w, list):
            return [float(x) for x in w]
        return [float(w)]
    except (KeyError, TypeError, ValueError):
        return [10.0, 30.0, 60.0]


# ----------------------------------------------------------------
# Per-flow observation packed into windows
# ----------------------------------------------------------------

@dataclass
class FlowObservation:
    """Lightweight record of one flow stored inside a time window."""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: int
    byte_count: int
    packet_count: int
    duration: float
    timestamp: float


# ----------------------------------------------------------------
# Per-source aggregator
# ----------------------------------------------------------------

class SourceProfile:
    """
    Maintains sliding-window behavioral statistics for one source IP.

    Parameters
    ----------
    src_ip:
        The source IP being tracked.
    window_sizes:
        Window sizes in seconds to maintain simultaneously.
    """

    def __init__(self, src_ip: str, window_sizes: Optional[List[float]] = None) -> None:
        self.src_ip = src_ip
        self._sizes = window_sizes or _get_window_sizes()
        # Each window stores FlowObservation objects
        self._windows = WindowSet(self._sizes)

    def record_flow(self, obs: FlowObservation) -> None:
        """Add a new flow observation to all windows."""
        self._windows.add(obs.timestamp, obs)

    def get_features(self, window_seconds: float, current_time: float) -> dict:
        """
        Compute behavioral features for this source over the given window.

        Returns an empty dict if the window size is not configured.
        """
        try:
            obs_list: List[FlowObservation] = self._windows.items(
                window_seconds, current_time
            )
        except KeyError:
            return {}

        n = len(obs_list)
        suffix = f"{int(window_seconds)}s"

        if n == 0:
            return {
                f"src_uniq_dst_hosts_{suffix}": 0,
                f"src_uniq_dst_ports_{suffix}": 0,
                f"src_conn_count_{suffix}": 0,
                f"src_bytes_out_{suffix}": 0,
                f"src_pkts_out_{suffix}": 0,
                f"src_avg_flow_dur_{suffix}": None,
                f"src_dst_entropy_{suffix}": 0.0,
                f"src_uniq_dst_subnets_{suffix}": 0,
                f"src_uniq_host_port_pairs_{suffix}": 0,
            }

        dst_ips = [o.dst_ip for o in obs_list]
        dst_ports = [o.dst_port for o in obs_list]
        subnets = [_get_subnet(ip) for ip in dst_ips]
        host_port_pairs = [(o.dst_ip, o.dst_port) for o in obs_list]
        durations = [o.duration for o in obs_list if o.duration > 0]
        bytes_out = sum(o.byte_count for o in obs_list)
        pkts_out = sum(o.packet_count for o in obs_list)

        avg_dur = statistics.mean(durations) if durations else None

        return {
            f"src_uniq_dst_hosts_{suffix}": len(set(dst_ips)),
            f"src_uniq_dst_ports_{suffix}": len(set(dst_ports)),
            f"src_conn_count_{suffix}": n,
            f"src_bytes_out_{suffix}": bytes_out,
            f"src_pkts_out_{suffix}": pkts_out,
            f"src_avg_flow_dur_{suffix}": avg_dur,
            f"src_dst_entropy_{suffix}": ip_set_entropy(dst_ips),
            f"src_uniq_dst_subnets_{suffix}": len(set(subnets)),
            f"src_uniq_host_port_pairs_{suffix}": len(set(host_port_pairs)),
        }

    def get_all_features(self, current_time: float) -> dict:
        """Compute features for all configured window sizes."""
        result = {}
        for size in self._sizes:
            result.update(self.get_features(size, current_time))
        return result


# ----------------------------------------------------------------
# Per-destination aggregator
# ----------------------------------------------------------------

class DestinationProfile:
    """
    Maintains sliding-window statistics for traffic targeting one IP.

    Parameters
    ----------
    dst_ip:
        The destination IP being tracked.
    window_sizes:
        Window sizes in seconds.
    """

    def __init__(self, dst_ip: str, window_sizes: Optional[List[float]] = None) -> None:
        self.dst_ip = dst_ip
        self._sizes = window_sizes or _get_window_sizes()
        self._windows = WindowSet(self._sizes)

    def record_flow(self, obs: FlowObservation) -> None:
        self._windows.add(obs.timestamp, obs)

    def get_features(self, window_seconds: float, current_time: float) -> dict:
        try:
            obs_list: List[FlowObservation] = self._windows.items(
                window_seconds, current_time
            )
        except KeyError:
            return {}

        suffix = f"{int(window_seconds)}s"

        if not obs_list:
            return {
                f"dst_uniq_src_hosts_{suffix}": 0,
                f"dst_conn_count_{suffix}": 0,
                f"dst_src_concentration_{suffix}": 0.0,
            }

        src_ips = [o.src_ip for o in obs_list]

        # Source concentration: 1 - normalised entropy
        # High concentration means traffic from few sources (DDoS indicator)
        src_conc = 1.0 - normalised_entropy(src_ips)

        return {
            f"dst_uniq_src_hosts_{suffix}": len(set(src_ips)),
            f"dst_conn_count_{suffix}": len(obs_list),
            f"dst_src_concentration_{suffix}": src_conc,
        }

    def get_all_features(self, current_time: float) -> dict:
        result = {}
        for size in self._sizes:
            result.update(self.get_features(size, current_time))
        return result


# ----------------------------------------------------------------
# Global behavioral aggregator
# ----------------------------------------------------------------

class BehavioralAggregator:
    """
    Tracks SourceProfile and DestinationProfile for all observed IPs.

    Call record_flow() for each completed FlowRecord.
    Call get_source_features() / get_destination_features() to retrieve
    the current behavioral feature snapshot for an IP.

    Parameters
    ----------
    window_sizes:
        Window sizes in seconds (read from config if not provided).
    max_tracked_ips:
        Maximum number of IPs to track simultaneously (memory guard).
    """

    def __init__(
        self,
        window_sizes: Optional[List[float]] = None,
        max_tracked_ips: int = 100_000,
    ) -> None:
        self._sizes = window_sizes or _get_window_sizes()
        self._max_ips = max_tracked_ips
        self._sources: Dict[str, SourceProfile] = {}
        self._destinations: Dict[str, DestinationProfile] = {}

    def record_flow(self, flow) -> None:
        """
        Register a completed or in-progress FlowRecord.

        Parameters
        ----------
        flow:
            A FlowRecord object (imported lazily to avoid circular imports).
        """
        if not flow.source_ip or not flow.destination_ip:
            return

        obs = FlowObservation(
            src_ip=flow.source_ip,
            dst_ip=flow.destination_ip,
            dst_port=flow.destination_port or 0,
            protocol=flow.protocol or 0,
            byte_count=flow.byte_count,
            packet_count=flow.packet_count,
            duration=flow.duration,
            timestamp=flow.last_seen,
        )

        # Source profile
        if flow.source_ip not in self._sources:
            if len(self._sources) < self._max_ips:
                self._sources[flow.source_ip] = SourceProfile(
                    flow.source_ip, self._sizes
                )
        if flow.source_ip in self._sources:
            self._sources[flow.source_ip].record_flow(obs)

        # Destination profile
        if flow.destination_ip not in self._destinations:
            if len(self._destinations) < self._max_ips:
                self._destinations[flow.destination_ip] = DestinationProfile(
                    flow.destination_ip, self._sizes
                )
        if flow.destination_ip in self._destinations:
            self._destinations[flow.destination_ip].record_flow(obs)

    def get_source_features(
        self,
        src_ip: str,
        current_time: float,
    ) -> dict:
        """Return all window-based behavioral features for a source IP."""
        profile = self._sources.get(src_ip)
        if profile is None:
            return {}
        return profile.get_all_features(current_time)

    def get_destination_features(
        self,
        dst_ip: str,
        current_time: float,
    ) -> dict:
        """Return all window-based behavioral features for a destination IP."""
        profile = self._destinations.get(dst_ip)
        if profile is None:
            return {}
        return profile.get_all_features(current_time)

    def extract_behavioral_features(self, flow, fv: "FeatureVector") -> None:
        """
        Compute and write behavioral features into a FeatureVector.

        Parameters
        ----------
        flow:
            A FlowRecord whose source/destination should be queried.
        fv:
            The FeatureVector to update in-place.
        """
        from src.features.feature_vector import FeatureVector  # avoid circular at module level

        current_time = flow.last_seen
        features = {}
        features.update(self.get_source_features(flow.source_ip or "", current_time))
        features.update(self.get_destination_features(flow.destination_ip or "", current_time))
        fv.update("behavioral", features)

    @property
    def tracked_sources(self) -> int:
        return len(self._sources)

    @property
    def tracked_destinations(self) -> int:
        return len(self._destinations)
