"""
UniShield AI — Phase 0 Smoke Tests
====================================
These tests verify that the project is correctly set up:
  - directory structure exists
  - configuration files are valid YAML and contain required keys
  - utility modules import cleanly
  - logging system initialises
  - config loader returns expected values
  - time utilities return sensible results
  - metrics module initialises

These tests do NOT require network access, Zeek, or Scapy.

Run with:
    python -m pytest tests/test_phase0.py -v
"""

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

# Project root is added to sys.path by conftest.py
PROJECT_ROOT = Path(__file__).parents[1]


# ==============================================================
# 1. Directory structure
# ==============================================================

class TestDirectoryStructure:
    """Verify the required project tree exists."""

    REQUIRED_DIRS = [
        "config",
        "data/raw",
        "data/processed",
        "data/samples",
        "src",
        "src/ingestion",
        "src/flows",
        "src/features",
        "src/detectors",
        "src/fusion",
        "src/alerts",
        "src/models/trained",
        "src/models/training",
        "src/utils",
        "dashboard",
        "dashboard/components",
        "dashboard/pages",
        "tests",
        "docs",
        "notebooks",
    ]

    REQUIRED_FILES = [
        "requirements.txt",
        "config/config.yaml",
        "config/thresholds.yaml",
        "src/__init__.py",
        "src/utils/__init__.py",
        "src/utils/logging.py",
        "src/utils/time.py",
        "src/utils/metrics.py",
        "src/utils/config.py",
    ]

    @pytest.mark.parametrize("directory", REQUIRED_DIRS)
    def test_directory_exists(self, project_root: Path, directory: str) -> None:
        """Each required directory must exist."""
        target = project_root / directory
        assert target.is_dir(), f"Missing directory: {directory}"

    @pytest.mark.parametrize("filepath", REQUIRED_FILES)
    def test_file_exists(self, project_root: Path, filepath: str) -> None:
        """Each required file must exist."""
        target = project_root / filepath
        assert target.is_file(), f"Missing file: {filepath}"


# ==============================================================
# 2. Configuration files
# ==============================================================

class TestConfiguration:
    """Verify YAML config files are valid and contain required keys."""

    def test_config_yaml_is_valid_yaml(self, config_dir: Path) -> None:
        """config.yaml must be parseable YAML."""
        with (config_dir / "config.yaml").open("r") as fh:
            data = yaml.safe_load(fh)
        assert isinstance(data, dict), "config.yaml should parse to a dict"

    def test_config_yaml_required_sections(self, config_dir: Path) -> None:
        """config.yaml must contain all required top-level sections."""
        with (config_dir / "config.yaml").open("r") as fh:
            data = yaml.safe_load(fh)
        required = ["project", "logging", "database", "ingestion", "flows",
                    "features", "api", "dashboard", "models"]
        for section in required:
            assert section in data, f"config.yaml missing section: '{section}'"

    def test_thresholds_yaml_is_valid_yaml(self, config_dir: Path) -> None:
        """thresholds.yaml must be parseable YAML."""
        with (config_dir / "thresholds.yaml").open("r") as fh:
            data = yaml.safe_load(fh)
        assert isinstance(data, dict), "thresholds.yaml should parse to a dict"

    def test_thresholds_yaml_required_sections(self, config_dir: Path) -> None:
        """thresholds.yaml must contain sections for all six threat categories."""
        with (config_dir / "thresholds.yaml").open("r") as fh:
            data = yaml.safe_load(fh)
        required = ["ddos", "c2_beacon", "dga_dns", "reconnaissance",
                    "exfiltration", "encrypted"]
        for section in required:
            assert section in data, f"thresholds.yaml missing section: '{section}'"

    def test_project_name_in_config(self, config_dir: Path) -> None:
        """Project name must be set in config.yaml."""
        with (config_dir / "config.yaml").open("r") as fh:
            data = yaml.safe_load(fh)
        assert data["project"]["name"] == "UniShield AI"

    def test_sih_problem_in_config(self, config_dir: Path) -> None:
        """SIH problem statement number must be in config."""
        with (config_dir / "config.yaml").open("r") as fh:
            data = yaml.safe_load(fh)
        assert data["project"]["sih_problem"] == "26145"


# ==============================================================
# 3. Config loader
# ==============================================================

class TestConfigLoader:
    """Verify the config loader module works correctly."""

    def test_get_config_returns_dict(self) -> None:
        from src.utils.config import get_config, reload_config
        reload_config()
        cfg = get_config()
        assert isinstance(cfg, dict)
        assert cfg["project"]["name"] == "UniShield AI"

    def test_get_thresholds_returns_dict(self) -> None:
        from src.utils.config import get_thresholds, reload_config
        reload_config()
        thr = get_thresholds()
        assert isinstance(thr, dict)
        assert "ddos" in thr

    def test_config_is_cached(self) -> None:
        """Second call should return the same object (cached)."""
        from src.utils.config import get_config, reload_config
        reload_config()
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2

    def test_reload_clears_cache(self) -> None:
        from src.utils.config import get_config, reload_config
        cfg1 = get_config()
        reload_config()
        cfg2 = get_config()
        # After reload a new dict is created — they should be equal but not the same object
        assert cfg1 == cfg2
        assert cfg1 is not cfg2

    def test_ddos_thresholds_are_positive(self) -> None:
        from src.utils.config import get_thresholds, reload_config
        reload_config()
        ddos = get_thresholds()["ddos"]
        # Config was restructured to nested keys in Phase 3
        assert ddos["syn_flood"]["syn_ratio_threshold"] > 0
        assert ddos["rate"]["pps_absolute_min"] > 0


# ==============================================================
# 4. Time utilities
# ==============================================================

class TestTimeUtilities:
    """Verify timestamp and time helper functions."""

    def test_utc_now_is_timezone_aware(self) -> None:
        from src.utils.time import utc_now
        dt = utc_now()
        assert isinstance(dt, datetime)
        assert dt.tzinfo is not None
        assert dt.tzinfo == timezone.utc

    def test_utc_now_is_recent(self) -> None:
        from src.utils.time import utc_now
        dt = utc_now()
        now = datetime.now(tz=timezone.utc)
        delta = abs((now - dt).total_seconds())
        assert delta < 2.0, "utc_now() should return current time"

    def test_utc_timestamp_is_string(self) -> None:
        from src.utils.time import utc_timestamp
        ts = utc_timestamp()
        assert isinstance(ts, str)
        assert "+00:00" in ts or "Z" in ts  # must contain UTC offset

    def test_from_unix_returns_utc(self) -> None:
        from src.utils.time import from_unix
        epoch = 1_700_000_000.0
        dt = from_unix(epoch)
        assert dt.tzinfo == timezone.utc
        assert dt.timestamp() == pytest.approx(epoch, abs=0.001)

    def test_unix_to_iso_is_string(self) -> None:
        from src.utils.time import unix_to_iso
        result = unix_to_iso(1_700_000_000.0)
        assert isinstance(result, str)
        assert "2023" in result  # epoch 1700000000 is in 2023

    def test_duration_seconds_positive(self) -> None:
        from src.utils.time import duration_seconds
        assert duration_seconds(100.0, 150.0) == pytest.approx(50.0)

    def test_duration_seconds_clamps_to_zero(self) -> None:
        from src.utils.time import duration_seconds
        assert duration_seconds(200.0, 100.0) == 0.0

    def test_safe_divide_normal(self) -> None:
        from src.utils.time import safe_divide
        assert safe_divide(10.0, 2.0) == pytest.approx(5.0)

    def test_safe_divide_by_zero(self) -> None:
        from src.utils.time import safe_divide
        assert safe_divide(10.0, 0.0) == 0.0

    def test_safe_divide_custom_default(self) -> None:
        from src.utils.time import safe_divide
        assert safe_divide(10.0, 0.0, default=-1.0) == -1.0


# ==============================================================
# 5. Logging system
# ==============================================================

class TestLoggingSystem:
    """Verify the logging module initialises without errors."""

    def test_configure_logging_does_not_raise(self) -> None:
        from src.utils.logging import configure_logging
        configure_logging(level="WARNING")

    def test_get_logger_returns_logger(self) -> None:
        from src.utils.logging import get_logger
        logger = get_logger("test.module")
        assert logger is not None

    def test_logger_info_does_not_raise(self) -> None:
        from src.utils.logging import configure_logging, get_logger
        configure_logging(level="WARNING")
        logger = get_logger("test.module")
        # Should not raise — even if log level suppresses output
        logger.warning("Phase 0 smoke test log message")


# ==============================================================
# 6. Metrics module
# ==============================================================

class TestMetrics:
    """Verify the metrics module initialises and tracks correctly."""

    def test_pipeline_metrics_initialises(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        assert m.flows_processed == 0
        assert m.packets_ingested == 0
        assert m.alerts_generated == 0

    def test_record_packet_increments(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        m.record_packet()
        m.record_packet()
        assert m.packets_ingested == 2

    def test_record_flow_increments(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        m.record_flow()
        assert m.flows_processed == 1

    def test_record_alert_increments(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        m.record_alert()
        assert m.alerts_generated == 1

    def test_record_detection_tracks_latency(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        m.record_detection("DDoSDetector", latency_ms=12.5)
        m.record_detection("DDoSDetector", latency_ms=7.5)
        dm = m.detector_metrics["DDoSDetector"]
        assert dm.calls == 2
        assert dm.avg_latency_ms == pytest.approx(10.0)

    def test_flows_per_second_is_non_negative(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        time.sleep(0.01)
        m.record_flow()
        assert m.flows_per_second >= 0.0

    def test_summary_returns_dict(self) -> None:
        from src.utils.metrics import PipelineMetrics
        m = PipelineMetrics()
        summary = m.summary()
        assert isinstance(summary, dict)
        assert "flows_processed" in summary
        assert "packets_ingested" in summary
        assert "alerts_generated" in summary

    def test_avg_latency_none_when_no_calls(self) -> None:
        from src.utils.metrics import DetectorMetrics
        dm = DetectorMetrics("TestDetector")
        assert dm.avg_latency_ms is None


# ==============================================================
# 7. Python version guard
# ==============================================================

class TestEnvironment:
    """Verify the runtime environment meets minimum requirements."""

    def test_python_version_minimum(self) -> None:
        """Python 3.11+ is required per the engineering spec."""
        assert sys.version_info >= (3, 11), (
            f"Python 3.11+ required, running {sys.version}"
        )

    def test_numpy_importable(self) -> None:
        import numpy as np  # noqa: F401

    def test_pandas_importable(self) -> None:
        import pandas as pd  # noqa: F401

    def test_scipy_importable(self) -> None:
        import scipy  # noqa: F401

    def test_sklearn_importable(self) -> None:
        import sklearn  # noqa: F401

    def test_fastapi_importable(self) -> None:
        import fastapi  # noqa: F401

    def test_pydantic_importable(self) -> None:
        import pydantic  # noqa: F401

    def test_yaml_importable(self) -> None:
        import yaml  # noqa: F401

    def test_loguru_importable(self) -> None:
        import loguru  # noqa: F401
