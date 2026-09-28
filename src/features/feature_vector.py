"""
UniShield AI -- FeatureVector
==============================
The standardised output of the Feature Pipeline.

Every detector consumes a FeatureVector -- it does not interact
with raw FlowRecords or NetworkEvents directly.

Design goals:
  - Flat, named feature dictionary with typed values
  - Explicit representation of missing/unavailable features (None)
  - Metadata separate from features
  - JSON-serialisable out of the box
  - Extensible: new feature groups can be added without breaking
    existing detectors

IMPORTANT: Features are OBSERVATIONS, not classifications.
           This module must NOT make threat decisions.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Optional, Union
from datetime import datetime, timezone

from pydantic import BaseModel, Field, model_validator

# Feature value types: numeric, boolean, string metadata, or list of these
FeatureValue = Union[float, int, bool, str, list, None]


class FeatureVector(BaseModel):
    """
    Standardised feature representation for one flow or time window.

    Attributes
    ----------
    flow_id:
        UUID of the source FlowRecord.
    timestamp:
        ISO-8601 UTC string of when this vector was computed.
    source_ip / destination_ip / source_port / destination_port / protocol:
        5-tuple identifying the flow.
    window_start / window_end:
        For window-based features, the time bounds (UNIX epoch).
    features:
        Flat dict of feature_name -> value.
        None means "not available / not applicable".
    feature_groups:
        Which extractors contributed features (for transparency).
    """

    model_config = {"frozen": False}   # mutable so pipeline can build incrementally

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    flow_id: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    # ------------------------------------------------------------------
    # 5-tuple (copied from FlowRecord for convenience)
    # ------------------------------------------------------------------
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[int] = None

    # ------------------------------------------------------------------
    # Window bounds (None for per-flow vectors)
    # ------------------------------------------------------------------
    window_start: Optional[float] = None
    window_end: Optional[float] = None

    # ------------------------------------------------------------------
    # Features
    # ------------------------------------------------------------------
    features: Dict[str, FeatureValue] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------
    feature_groups: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def set(self, name: str, value: FeatureValue) -> None:
        """Add or update a single feature value."""
        self.features[name] = value

    def get(self, name: str, default: FeatureValue = None) -> FeatureValue:
        """Retrieve a feature value by name."""
        return self.features.get(name, default)

    def update(self, group_name: str, values: Dict[str, FeatureValue]) -> None:
        """
        Merge a dict of features and record the contributing group.

        Parameters
        ----------
        group_name:
            Name of the feature extractor (e.g. "flow", "timing", "dns").
        values:
            Dict of feature_name -> value.
        """
        self.features.update(values)
        if group_name not in self.feature_groups:
            self.feature_groups.append(group_name)

    def numeric_features(self) -> Dict[str, float]:
        """
        Return only numeric (float/int) features, with None dropped.

        Useful for passing to scikit-learn estimators.
        """
        result = {}
        for k, v in self.features.items():
            if isinstance(v, (int, float)) and math.isfinite(float(v)):
                result[k] = float(v)
        return result

    def has_group(self, name: str) -> bool:
        return name in self.feature_groups

    def to_summary(self) -> str:
        """One-line human-readable summary."""
        n = len([v for v in self.features.values() if v is not None])
        return (
            f"FeatureVector(flow={self.flow_id}, "
            f"groups={self.feature_groups}, "
            f"features={n}/{len(self.features)})"
        )

    def validate_no_infinities(self) -> list[str]:
        """
        Return a list of feature names that contain NaN or infinite values.

        The pipeline should call this and log warnings, not silently ignore.
        """
        bad = []
        for k, v in self.features.items():
            if isinstance(v, float):
                if math.isnan(v) or math.isinf(v):
                    bad.append(k)
        return bad

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "feature_groups": self.feature_groups,
            "features": self.features,
        }
