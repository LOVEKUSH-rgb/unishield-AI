"""
UniShield AI — Streaming Dispatcher
=====================================
Connects ingestion sources to downstream consumers (flow manager,
feature pipeline, detectors) in a single streaming loop.

The stream module provides:
  - StreamProcessor: wraps any NetworkEvent source and fans out
    to registered handlers
  - SourceRouter: picks the correct reader for a given input type

PASSIVE AUDIT:
  [PASS] No packets generated or transmitted
  [PASS] Generator-based — processes one event at a time
  [PASS] No active probing
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Generator, Iterable, List, Optional

from src.ingestion.models import NetworkEvent
from src.utils.logging import get_logger

logger = get_logger(__name__)

EventHandler = Callable[[NetworkEvent], None]


class StreamProcessor:
    """
    Fans out a stream of NetworkEvents to registered handlers.

    Handlers are called synchronously in registration order.
    This is intentionally simple — no threading, no buffering.

    Parameters
    ----------
    source:
        An iterable of NetworkEvent objects (e.g. PcapReader.stream()).
    handlers:
        Optional initial list of handler functions.
    """

    def __init__(
        self,
        source: Iterable[NetworkEvent],
        handlers: Optional[List[EventHandler]] = None,
    ) -> None:
        self._source = source
        self._handlers: List[EventHandler] = list(handlers or [])
        self._events_processed = 0
        self._handler_errors = 0

    def add_handler(self, handler: EventHandler) -> None:
        """Register a new event handler."""
        self._handlers.append(handler)

    def run(self) -> int:
        """
        Process the entire source stream.

        Returns
        -------
        int
            Total events processed.
        """
        logger.info("StreamProcessor starting", handlers=len(self._handlers))

        for event in self._source:
            self._events_processed += 1
            for handler in self._handlers:
                try:
                    handler(event)
                except Exception as exc:
                    self._handler_errors += 1
                    logger.warning(
                        "Handler raised exception",
                        handler=handler.__name__,
                        error=str(exc),
                    )

        logger.info(
            "StreamProcessor complete",
            events_processed=self._events_processed,
            handler_errors=self._handler_errors,
        )
        return self._events_processed

    def as_generator(self) -> Generator[NetworkEvent, None, None]:
        """
        Yield events while calling registered handlers as a side effect.

        Useful when the caller also wants to process events directly.
        """
        for event in self._source:
            self._events_processed += 1
            for handler in self._handlers:
                try:
                    handler(event)
                except Exception as exc:
                    self._handler_errors += 1
                    logger.warning(
                        "Handler raised exception",
                        handler=handler.__name__,
                        error=str(exc),
                    )
            yield event

    @property
    def events_processed(self) -> int:
        return self._events_processed

    @property
    def handler_errors(self) -> int:
        return self._handler_errors


def open_source(path: str | Path, source_type: Optional[str] = None):
    """
    Factory: return the appropriate ingestion reader for a given file.

    Auto-detects source type from file extension if not specified.

    Parameters
    ----------
    path:
        Path to PCAP, Zeek conn.log, dns.log, or ssl.log.
    source_type:
        One of: "pcap", "zeek_conn", "zeek_dns", "zeek_ssl".
        Auto-detected if None.

    Returns
    -------
    An object with a .stream() method that yields NetworkEvents.
    """
    path = Path(path)

    if source_type is None:
        suffix = path.suffix.lower()
        stem = path.stem.lower()

        if suffix in (".pcap", ".pcapng", ".cap"):
            source_type = "pcap"
        elif "conn" in stem:
            source_type = "zeek_conn"
        elif "dns" in stem:
            source_type = "zeek_dns"
        elif "ssl" in stem or "tls" in stem:
            source_type = "zeek_ssl"
        elif suffix == ".log":
            source_type = "zeek_conn"  # default for unknown .log files
        else:
            raise ValueError(
                f"Cannot detect source type for '{path}'. "
                "Pass source_type= explicitly."
            )

    if source_type == "pcap":
        from src.ingestion.pcap_reader import PcapReader
        return PcapReader(path)

    zeek_type_map = {
        "zeek_conn": "conn",
        "zeek_dns": "dns",
        "zeek_ssl": "ssl",
    }
    if source_type in zeek_type_map:
        from src.ingestion.flow_reader import ZeekLogReader
        return ZeekLogReader(path, log_type=zeek_type_map[source_type])

    raise ValueError(f"Unknown source_type: '{source_type}'")
