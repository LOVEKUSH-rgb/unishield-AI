"""
UniShield AI -- Alert Manager
================================
Handles alert deduplication, correlation, and lifecycle.

Design:
  - Alerts are deduplicated by a (threat_class, sub_type, source_ip) key
  - Duplicate alerts within the dedup window update the existing alert
  - Alerts auto-expire if not refreshed within the dedup window
  - AlertManager is the single source of truth for active alerts

PASSIVE AUDIT: Read-only. No network activity.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from src.detectors.base import Alert, DetectionResult, Severity, ThreatClass
from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)

AlertCallback = Callable[[Alert], None]


def _dedup_cfg() -> dict:
    try:
        return get_thresholds().get("ddos", {}).get("deduplication", {})
    except Exception:
        return {}


class AlertManager:
    """
    Manages active alerts with deduplication and expiry.

    Parameters
    ----------
    dedup_window_seconds:
        Two alerts with the same dedup_key within this window
        are merged. Default from config/thresholds.yaml.
    max_active_alerts:
        Maximum number of alerts held in memory simultaneously.
    on_new_alert:
        Optional callback invoked when a NEW alert is created.
    on_alert_updated:
        Optional callback invoked when an existing alert is updated.
    """

    def __init__(
        self,
        dedup_window_seconds: Optional[float] = None,
        max_active_alerts: Optional[int] = None,
        on_new_alert: Optional[AlertCallback] = None,
        on_alert_updated: Optional[AlertCallback] = None,
    ) -> None:
        cfg = _dedup_cfg()
        self._window = dedup_window_seconds or float(cfg.get("window_seconds", 30.0))
        self._max = max_active_alerts or int(cfg.get("max_active_alerts", 1000))
        self._on_new = on_new_alert
        self._on_updated = on_alert_updated

        # OrderedDict preserves insertion order (oldest first for eviction)
        self._active: Dict[str, Alert] = OrderedDict()
        self._total_new = 0
        self._total_updated = 0
        self._total_expired = 0

        logger.info(
            "AlertManager initialised",
            dedup_window=self._window,
            max_alerts=self._max,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, result: DetectionResult) -> Optional[Alert]:
        """
        Process a DetectionResult.

        If an active alert with the same dedup_key exists → update it.
        Otherwise → create a new alert.

        Parameters
        ----------
        result:
            A DetectionResult from a detector.

        Returns
        -------
        Optional[Alert]
            The new or updated alert, or None if the result is suppressed.
        """
        if result.is_suppressed:
            return None

        dedup_key = self._make_key(result)
        now_str = datetime.now(tz=timezone.utc).isoformat()

        # Expire stale alerts before processing
        self._expire_stale()

        if dedup_key in self._active:
            alert = self._active[dedup_key]
            alert.update(result)
            self._total_updated += 1
            logger.debug(
                "Alert updated",
                key=dedup_key,
                count=alert.event_count,
                score=round(alert.detection_score, 3),
            )
            if self._on_updated:
                try:
                    self._on_updated(alert)
                except Exception as exc:
                    logger.warning("on_alert_updated callback error", error=str(exc))
            return alert
        else:
            # Enforce capacity
            if len(self._active) >= self._max:
                oldest_key = next(iter(self._active))
                logger.warning(
                    "Alert capacity reached — dropping oldest",
                    key=oldest_key,
                )
                del self._active[oldest_key]

            alert = Alert(
                dedup_key=dedup_key,
                threat_class=result.threat_class,
                sub_type=result.sub_type,
                severity=result.severity,
                detection_score=result.detection_score,
                confidence=result.confidence,
                source_ip=result.source_ip,
                destination_ip=result.destination_ip,
                first_seen=result.timestamp,
                last_seen=result.timestamp,
                evidence=result.evidence,
            )
            self._active[dedup_key] = alert
            self._total_new += 1

            logger.info(
                "NEW ALERT",
                threat=result.threat_class.value,
                sub_type=result.sub_type,
                severity=result.severity.value if result.severity else "?",
                score=round(result.detection_score, 3),
                confidence=round(result.confidence, 3),
                src=result.source_ip,
                key=dedup_key,
            )
            if self._on_new:
                try:
                    self._on_new(alert)
                except Exception as exc:
                    logger.warning("on_new_alert callback error", error=str(exc))
            return alert

    def expire_alert(self, dedup_key: str) -> None:
        """Manually expire an alert by key."""
        alert = self._active.pop(dedup_key, None)
        if alert:
            alert.active = False
            self._total_expired += 1

    def active_alerts(self) -> List[Alert]:
        """Return all currently active alerts."""
        self._expire_stale()
        return list(self._active.values())

    @property
    def active_count(self) -> int:
        return len(self._active)

    def summary(self) -> dict:
        return {
            "active_alerts": self.active_count,
            "total_new": self._total_new,
            "total_updated": self._total_updated,
            "total_expired": self._total_expired,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(result: DetectionResult) -> str:
        """Build a deduplication key from threat identity fields."""
        parts = [
            result.threat_class.value,
            result.sub_type or "",
            result.source_ip or "",
            result.destination_ip or "",
        ]
        return ":".join(p for p in parts if p)

    def _expire_stale(self) -> None:
        """
        Remove alerts whose last_seen is older than the dedup window.

        This implements the "DDoS ends → alert expires" logic.
        """
        now = datetime.now(tz=timezone.utc)
        to_expire = []
        for key, alert in self._active.items():
            try:
                last_dt = datetime.fromisoformat(alert.last_seen)
                age = (now - last_dt).total_seconds()
                if age > self._window:
                    to_expire.append(key)
            except Exception:
                pass

        for key in to_expire:
            alert = self._active.pop(key, None)
            if alert:
                alert.active = False
                self._total_expired += 1
                logger.debug("Alert expired", key=key)
