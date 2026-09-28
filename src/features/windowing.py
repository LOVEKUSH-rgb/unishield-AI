"""
UniShield AI -- Time Window Engine
=====================================
Provides configurable sliding and fixed time windows for aggregating
network events and flow statistics.

Design:
  - TimeWindow holds a bounded deque of (timestamp, data) items
  - Items outside the window age-out on each add() call
  - Supports both fixed windows (tumbling) and sliding windows
  - WindowSet manages multiple named windows simultaneously
  - All window sizes are configurable (no hard-coded values)

Windows are used by:
  - BehavioralAggregator (unique_dst_hosts, fan-out, etc.)
  - Future detectors (DDoS burst, C2 periodicity, etc.)

This module does NOT make threat decisions.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Generic, List, Optional, Tuple, TypeVar

from src.utils.config import get_config

T = TypeVar("T")


def _get_default_windows() -> list[int]:
    """Read window sizes from config, fall back to [10, 30, 60]."""
    try:
        w = get_config()["flows"]["sliding_window_seconds"]
        if isinstance(w, list):
            return [int(x) for x in w]
        return [int(w)]
    except (KeyError, TypeError, ValueError):
        return [10, 30, 60]


@dataclass
class WindowedItem(Generic[T]):
    """A single timestamped item in a time window."""
    timestamp: float
    data: T


class TimeWindow(Generic[T]):
    """
    A sliding time window that evicts items older than `window_seconds`.

    Parameters
    ----------
    window_seconds:
        Size of the window in seconds.
    max_items:
        Optional cap on the number of items kept (memory guard).
    """

    def __init__(
        self,
        window_seconds: float,
        max_items: Optional[int] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        self.window_seconds = window_seconds
        self.max_items = max_items
        self._items: Deque[WindowedItem[T]] = deque()

    def add(self, timestamp: float, data: T) -> None:
        """
        Add an item and evict items that have fallen outside the window.

        Parameters
        ----------
        timestamp:
            Packet/event timestamp (UNIX epoch seconds).
        data:
            The item to store.
        """
        self._evict(timestamp)
        self._items.append(WindowedItem(timestamp=timestamp, data=data))

        # Enforce max_items cap (drop oldest)
        if self.max_items and len(self._items) > self.max_items:
            self._items.popleft()

    def _evict(self, current_time: float) -> None:
        """Remove all items older than current_time - window_seconds."""
        cutoff = current_time - self.window_seconds
        while self._items and self._items[0].timestamp < cutoff:
            self._items.popleft()

    def items(self, current_time: Optional[float] = None) -> List[T]:
        """Return all data items currently in the window."""
        if current_time is not None:
            self._evict(current_time)
        return [item.data for item in self._items]

    def timestamps(self) -> List[float]:
        """Return timestamps of all items currently in the window."""
        return [item.timestamp for item in self._items]

    def count(self, current_time: Optional[float] = None) -> int:
        """Return the number of items currently in the window."""
        if current_time is not None:
            self._evict(current_time)
        return len(self._items)

    def oldest_timestamp(self) -> Optional[float]:
        return self._items[0].timestamp if self._items else None

    def newest_timestamp(self) -> Optional[float]:
        return self._items[-1].timestamp if self._items else None

    def clear(self) -> None:
        self._items.clear()


class WindowSet:
    """
    Manages multiple named TimeWindow instances simultaneously.

    Allows tracking the same event type across different window sizes
    without duplicating code.

    Parameters
    ----------
    window_sizes:
        List of window durations in seconds (e.g. [10, 30, 60]).
    max_items_per_window:
        Optional memory cap per window.
    """

    def __init__(
        self,
        window_sizes: Optional[List[float]] = None,
        max_items_per_window: Optional[int] = None,
    ) -> None:
        if window_sizes is None:
            window_sizes = [float(s) for s in _get_default_windows()]

        self._windows: Dict[float, TimeWindow] = {
            size: TimeWindow(size, max_items=max_items_per_window)
            for size in window_sizes
        }

    @property
    def window_sizes(self) -> List[float]:
        return sorted(self._windows.keys())

    def add(self, timestamp: float, data: Any) -> None:
        """Add an item to all windows simultaneously."""
        for window in self._windows.values():
            window.add(timestamp, data)

    def count(self, window_seconds: float, current_time: Optional[float] = None) -> int:
        """Return item count for a specific window size."""
        w = self._windows.get(window_seconds)
        if w is None:
            raise KeyError(f"No window of size {window_seconds}s configured")
        return w.count(current_time)

    def items(self, window_seconds: float, current_time: Optional[float] = None) -> list:
        """Return items for a specific window size."""
        w = self._windows.get(window_seconds)
        if w is None:
            raise KeyError(f"No window of size {window_seconds}s configured")
        return w.items(current_time)

    def counts_all(self, current_time: Optional[float] = None) -> Dict[float, int]:
        """Return item counts for all window sizes."""
        return {
            size: w.count(current_time)
            for size, w in self._windows.items()
        }

    def clear_all(self) -> None:
        for w in self._windows.values():
            w.clear()
