"""
UniShield AI — JSONL Reader (Streaming Benchmark)
=================================================
Reads pre-processed FeatureVectors from a JSON Lines file.
Used strictly for high-throughput streaming benchmarks, bypassing
the disk I/O and CPU overhead of PCAP parsing and flow sessionization.

Yields FeatureVector objects directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Generator, Optional

from src.features.feature_vector import FeatureVector
from src.utils.logging import get_logger

logger = get_logger(__name__)


class JsonlReader:
    """
    Incremental streaming reader for JSONL FeatureVectors.

    Parameters
    ----------
    file_path:
        Path to the .jsonl file.
    max_records:
        Stop after processing this many records.
    """

    def __init__(self, file_path: str | Path, max_records: Optional[int] = None):
        self.file_path = Path(file_path)
        self.max_records = max_records

        if not self.file_path.exists():
            raise FileNotFoundError(f"JSONL file not found: {self.file_path}")

        logger.info(
            "JsonlReader initialised",
            path=str(self.file_path),
            max_records=max_records,
        )

    def stream(self) -> Generator[FeatureVector, None, None]:
        """
        Yield FeatureVector objects incrementally one by one.
        """
        logger.info("Starting JSONL stream", path=str(self.file_path))
        
        count = 0
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if self.max_records is not None and count >= self.max_records:
                        break
                        
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        data = json.loads(line)
                        fv = FeatureVector(**data)
                        yield fv
                        count += 1
                    except json.JSONDecodeError as exc:
                        logger.warning("Malformed JSON record", error=str(exc))
                        
        except Exception as exc:
            logger.error("Error reading JSONL", path=str(self.file_path), error=str(exc))
            raise
        finally:
            logger.info("JSONL stream complete", total_records=count)
