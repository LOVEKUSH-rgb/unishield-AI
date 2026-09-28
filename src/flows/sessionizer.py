"""
UniShield AI — Sessionizer
===========================
Connects the ingestion stream to the flow manager.

The Sessionizer is the glue between:
  - NetworkEvent producers (PcapReader, ZeekLogReader)
  - FlowManager (active flow table)

It drives the main processing loop and provides completed
FlowRecords for downstream analysis.

Usage:
    from src.flows.sessionizer import Sessionizer
    from src.ingestion.pcap_reader import PcapReader
    from src.flows.flow_manager import FlowManager

    completed = []
    manager = FlowManager(on_flow_complete=completed.append)
    sess = Sessionizer(manager)

    for flow in sess.process(PcapReader("capture.pcap").stream()):
        analyze(flow)   # each completed flow as it is emitted
"""

from __future__ import annotations

from typing import Generator, Iterable, List, Optional

from src.flows.flow import FlowRecord
from src.flows.flow_manager import FlowManager
from src.ingestion.models import NetworkEvent
from src.utils.logging import get_logger

logger = get_logger(__name__)


class Sessionizer:
    """
    Routes NetworkEvents through the FlowManager and yields
    completed FlowRecords.

    Parameters
    ----------
    flow_manager:
        The FlowManager instance to use.
    """

    def __init__(self, flow_manager: FlowManager) -> None:
        self._manager = flow_manager
        self._completed: List[FlowRecord] = []

        # Register a callback so we can yield completed flows
        original_callback = self._manager._on_complete

        def _completion_handler(flow: FlowRecord) -> None:
            self._completed.append(flow)
            if original_callback is not None:
                original_callback(flow)

        self._manager._on_complete = _completion_handler

    def process(
        self,
        events: Iterable[NetworkEvent],
        flush_at_end: bool = True,
    ) -> Generator[FlowRecord, None, None]:
        """
        Process a stream of NetworkEvents and yield completed flows.

        Parameters
        ----------
        events:
            An iterable of NetworkEvent objects.
        flush_at_end:
            If True, expire all remaining active flows at stream end.

        Yields
        ------
        FlowRecord
            Each flow as it completes (FIN/RST or timeout).
        """
        last_ts: Optional[float] = None

        for event in events:
            last_ts = event.timestamp
            self._manager.process_event(event)

            # Yield any flows completed since last iteration
            while self._completed:
                yield self._completed.pop(0)

        # Flush remaining active flows at end of stream
        if flush_at_end:
            flushed = self._manager.flush(current_time=last_ts)
            # Yield the flushed flows (they arrive via the callback)
            while self._completed:
                yield self._completed.pop(0)

        logger.info(
            "Sessionizer complete",
            **self._manager.summary(),
        )

    def process_all(
        self,
        events: Iterable[NetworkEvent],
        flush_at_end: bool = True,
    ) -> List[FlowRecord]:
        """
        Process all events and return the full list of completed flows.

        Convenience wrapper around process() for cases where caller
        does not need streaming flow output.
        """
        return list(self.process(events, flush_at_end=flush_at_end))
