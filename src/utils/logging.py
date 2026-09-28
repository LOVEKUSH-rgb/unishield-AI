"""
UniShield AI — Structured Logging Utility
==========================================
Provides a consistent, structured logger throughout the project.
All components should import get_logger() from here rather than
configuring logging independently.

Log levels:
  DEBUG    — detailed diagnostic output
  INFO     — normal operational events
  WARNING  — something unexpected but recoverable
  ERROR    — something failed; system continues
  CRITICAL — system cannot continue

Usage:
    from src.utils.logging import get_logger
    logger = get_logger(__name__)
    logger.info("Flow processed", flow_id="abc123", packets=42)
"""

import sys
from pathlib import Path
from typing import Optional

from loguru import logger as _loguru_logger


def _load_config() -> dict:
    """Load logging config from config.yaml, fall back to defaults on failure."""
    try:
        import yaml  # type: ignore
        config_path = Path(__file__).parents[2] / "config" / "config.yaml"
        with config_path.open("r") as fh:
            cfg = yaml.safe_load(fh)
        return cfg.get("logging", {})
    except Exception:
        return {}


def configure_logging(level: Optional[str] = None) -> None:
    """
    Configure the global loguru logger.

    Should be called once at application start-up.

    Parameters
    ----------
    level:
        Override log level (DEBUG/INFO/WARNING/ERROR/CRITICAL).
        If not provided, value from config.yaml is used.
    """
    cfg = _load_config()
    log_level = (level or cfg.get("level", "INFO")).upper()
    log_file = cfg.get("log_file", "logs/unishield.log")
    rotation = cfg.get("rotation", "10 MB")
    retention = cfg.get("retention", "7 days")

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove default loguru handler and reconfigure
    _loguru_logger.remove()

    # Console handler — human-readable coloured output
    _loguru_logger.add(
        sys.stderr,
        level=log_level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # File handler — structured JSON-like output for parsing / alerting
    _loguru_logger.add(
        log_file,
        level=log_level,
        rotation=rotation,
        retention=retention,
        format="{message}",
        serialize=True,
        backtrace=True,
        diagnose=False,
    )


def get_logger(name: str):
    """
    Return a loguru logger bound with a module name context.

    Parameters
    ----------
    name:
        Typically pass __name__ from the calling module.

    Returns
    -------
    loguru.Logger
        Bound logger instance.

    Example
    -------
    >>> logger = get_logger(__name__)
    >>> logger.info("Event", key="value")
    """
    cfg = _load_config()
    env = cfg.get("environment", "production")
    service = cfg.get("service_name", "unishield-core")
    return _loguru_logger.bind(module=name, service=service, environment=env)
