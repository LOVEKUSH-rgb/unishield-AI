"""
UniShield AI — Flow Manager
============================
Maintains the active flow table and handles flow lifecycle:

  1. New NetworkEvent arrives → look up by 5-tuple key
  2. If found → update existing FlowRecord
  3. If not found → create new FlowRecord
  4. Periodically expire idle flows (configurable timeout)
  5. Completed flows (FIN/RST or timeout) are emitted to a callback

The FlowManager is the heart of the session layer.
It is called by the Sessionizer for every NetworkEvent.

PASSIVE AUDIT:
  [PASS] No packets transmitted
  [PASS] No active probing
  [PASS] Timeout expiry only closes the local tracking record,
         no RST or ICMP unreachable is sent back
"""

from __future__ import annotations

import time
from typing import Callable, Dict, Iterator, List, Optional

from src.flows.flow import FlowRecord
from src.ingestion.models import NetworkEvent
from src.utils.config import get_config
from src.utils.logging import get_logger
from src.utils.metrics import pipeline_metrics

logger = get_logger(__name__)

FlowCallback = Callable[[FlowRecord], None]


def _get_timeout() -> float:
    """Read flow timeout from config, fall back to 120 s."""
    try:
        return float(get_config()["flows"]["timeout_seconds"])
    except (KeyError, TypeError, ValueError):
        return 120.0


def _get_max_flows() -> int:
    """Read maximum active flows from config, fall back to 500 000."""
    try:
        return int(get_config()["flows"]["max_active_flows"])
    except (KeyError, TypeError, ValueError):
        return 500_000


def _get_cleanup_interval() -> float:
    """Read cleanup interval from config, fall back to 10 s."""
    try:
        return float(get_config()["flows"]["cleanup_interval_seconds"])
    except (KeyError, TypeError, ValueError):
        return 10.0


class FlowManager:
    """
    Active flow table with timeout-based expiry.

    Parameters
    ----------
    on_flow_complete:
        Optional callback invoked whenever a flow is completed
        (FIN/RST seen or timeout). Receives the completed FlowRecord.
    timeout_seconds:
        Idle flow timeout. Flows not updated within this window
        are expired. Reads from config if not provided.
    max_active_flows:
        Safety cap on the number of concurrent active flows.
        Oldest flows are expired when this limit is reached.
    cleanup_interval_seconds:
        How often the expired-flow sweep runs (in wall-clock seconds).
    """

    def __init__(
        self,
        on_flow_complete: Optional[FlowCallback] = None,
        timeout_seconds: Optional[float] = None,
        max_active_flows: Optional[int] = None,
        cleanup_interval_seconds: Optional[float] = None,
    ) -> None:
        self._flows: Dict[tuple, FlowRecord] = {}
        self._on_complete = on_flow_complete
        self._timeout = timeout_seconds if timeout_seconds is not None else _get_timeout()
        self._max_flows = max_active_flows if max_active_flows is not None else _get_max_flows()
        self._cleanup_interval = (
            cleanup_interval_seconds
            if cleanup_interval_seconds is not None
            else _get_cleanup_interval()
        )
        self._last_cleanup = time.time()
        self._total_flows_created = 0
        self._total_flows_completed = 0

        logger.info(
            "FlowManager initialised",
            timeout_seconds=self._timeout,
            max_active_flows=self._max_flows,
            cleanup_interval=self._cleanup_interval,
        )

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def process_event(self, event: NetworkEvent) -> FlowRecord:
        """
        Route a NetworkEvent to the correct FlowRecord, creating one
        if it doesn't exist.

        Parameters
        ----------
        event:
            Incoming NetworkEvent from the ingestion layer.

        Returns
        -------
        FlowRecord
            The (possibly updated or newly created) flow.
        """
        # Run periodic cleanup before processing
        self._maybe_cleanup(current_time=event.timestamp)

        key = event.flow_key

        if key in self._flows:
            flow = self._flows[key]
            flow.update(event)
            logger.debug(
                "Flow updated",
                flow=flow.flow_id_str,
                packets=flow.packet_count,
            )
        else:
            # Safety: enforce max_active_flows limit
            if len(self._flows) >= self._max_flows:
                self._expire_oldest()

            flow = FlowRecord.from_event(event)
            self._flows[key] = flow
            self._total_flows_created += 1
            pipeline_metrics.record_flow()
            logger.debug(
                "Flow created",
                flow=flow.flow_id_str,
                flow_id=flow.flow_id,
            )

        # If FIN/RST was seen, close immediately
        if flow.completed:
            self._close_flow(key)

        return flow

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _maybe_cleanup(self, current_time: float) -> None:
        """Run the idle-flow sweep if the cleanup interval has elapsed."""
        wall = time.time()
        if wall - self._last_cleanup >= self._cleanup_interval:
            self._sweep_expired(current_time)
            self._last_cleanup = wall

    def _sweep_expired(self, current_time: float) -> int:
        """
        Expire all flows that have been idle longer than the timeout.

        Parameters
        ----------
        current_time:
            The current packet timestamp (not wall clock) so that
            PCAP replay works correctly regardless of playback speed.

        Returns
        -------
        int
            Number of flows expired.
        """
        expired_keys = [
            key
            for key, flow in self._flows.items()
            if (current_time - flow.last_seen) > self._timeout
        ]

        for key in expired_keys:
            self._close_flow(key, reason="timeout")

        if expired_keys:
            logger.info(
                "Expired idle flows",
                count=len(expired_keys),
                active_flows=len(self._flows),
            )

        return len(expired_keys)

    def _expire_oldest(self) -> None:
        """Expire the single oldest flow to make room (capacity guard)."""
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].start_time)
        self._close_flow(oldest_key, reason="capacity")
        logger.warning(
            "Capacity limit reached — expired oldest flow",
            max_flows=self._max_flows,
        )

    def _close_flow(self, key: tuple, reason: str = "fin_rst") -> None:
        """Remove a flow from the active table and invoke the callback."""
        flow = self._flows.pop(key, None)
        if flow is None:
            return

        flow.completed = True
        self._total_flows_completed += 1

        logger.debug(
            "Flow closed",
            flow=flow.flow_id_str,
            reason=reason,
            packets=flow.packet_count,
            bytes=flow.byte_count,
            duration=round(flow.duration, 3),
        )

        if self._on_complete is not None:
            try:
                self._on_complete(flow)
            except Exception as exc:
                logger.error(
                    "on_flow_complete callback raised",
                    error=str(exc),
                    flow_id=flow.flow_id,
                )

    # ------------------------------------------------------------------
    # Flush — call at end-of-stream to expire all remaining flows
    # ------------------------------------------------------------------

    def flush(self, current_time: Optional[float] = None) -> List[FlowRecord]:
        """
        Expire all currently active flows.

        Should be called at end-of-file / end-of-stream to ensure
        no flows are silently dropped.

        Parameters
        ----------
        current_time:
            Override the expiry timestamp (defaults to time.time()).

        Returns
        -------
        list[FlowRecord]
            All flows that were flushed.
        """
        if current_time is None:
            current_time = time.time()

        flushed = []
        for key in list(self._flows.keys()):
            flow = self._flows.get(key)
            if flow:
                flushed.append(flow)
            self._close_flow(key, reason="end_of_stream")

        logger.info(
            "FlowManager flushed",
            flushed=len(flushed),
            total_created=self._total_flows_created,
            total_completed=self._total_flows_completed,
        )
        return flushed

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def active_flows(self) -> Iterator[FlowRecord]:
        """Iterate over all currently active (not yet completed) flows."""
        yield from self._flows.values()

    @property
    def active_count(self) -> int:
        return len(self._flows)

    @property
    def total_flows_created(self) -> int:
        return self._total_flows_created

    @property
    def total_flows_completed(self) -> int:
        return self._total_flows_completed

    def summary(self) -> dict:
        return {
            "active_flows": self.active_count,
            "total_flows_created": self._total_flows_created,
            "total_flows_completed": self._total_flows_completed,
            "timeout_seconds": self._timeout,
        }
