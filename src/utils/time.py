"""
UniShield AI — Timestamp and Time Utilities
===========================================
Centralised time helpers to ensure consistent timezone handling
and timestamp formatting throughout the system.

All internal timestamps are UTC.
All public-facing timestamps are ISO-8601 strings with UTC suffix.
"""

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(tz=timezone.utc)


def utc_timestamp() -> str:
    """Return current UTC time as an ISO-8601 string, e.g. '2025-08-27T18:00:00.000000+00:00'."""
    return utc_now().isoformat()


def from_unix(ts: float) -> datetime:
    """
    Convert a UNIX epoch float to a UTC-aware datetime.

    Parameters
    ----------
    ts:
        Seconds since UNIX epoch (as returned by scapy, Zeek, etc.)

    Returns
    -------
    datetime
        UTC-aware datetime.
    """
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def unix_to_iso(ts: float) -> str:
    """Convert a UNIX epoch float to an ISO-8601 UTC string."""
    return from_unix(ts).isoformat()


def duration_seconds(start: float, end: float) -> float:
    """
    Return elapsed time in seconds between two UNIX timestamps.

    Parameters
    ----------
    start:
        Start time (UNIX epoch seconds).
    end:
        End time (UNIX epoch seconds).

    Returns
    -------
    float
        Elapsed seconds (never negative — returns 0.0 if end < start).
    """
    delta = end - start
    return max(0.0, delta)


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Divide numerator by denominator, returning *default* on division by zero.

    Used throughout the flow and feature engine to avoid ZeroDivisionError.

    Parameters
    ----------
    numerator:
        Value to divide.
    denominator:
        Divisor.
    default:
        Value to return when denominator is zero.

    Returns
    -------
    float
        Result or default.
    """
    if denominator == 0.0:
        return default
    return numerator / denominator
