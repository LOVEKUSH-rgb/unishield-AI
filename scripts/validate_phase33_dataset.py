"""
Phase 33 — Dataset Validation Tool
====================================
Validates the presence and structure of external PCAP datasets
for Phase 33 evaluation.

Currently supports:
  - CTU-13 (Czech Technical University Botnet Dataset)

Output:
  reports/phase33/dataset_validation.json

Status values:
  AVAILABLE       — files found and parseable
  VALID           — files found, parseable, and contain expected content
  PARTIALLY_AVAILABLE — some files found but not all expected
  INVALID         — files found but corrupt or unreadable
  INSUFFICIENT_DATA — no files found; evaluation cannot proceed

IMPORTANT: This script NEVER fabricates results. All reported values
come from actual file inspection.
"""

from __future__ import annotations

import json
import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, Optional

DATASET_DIR = Path("data/raw/external/ctu13")
PROCESSED_DIR = Path("data/processed/phase33")
REPORT_DIR = Path("reports/phase33")
REPORT_PATH = REPORT_DIR / "dataset_validation.json"

# Minimum expected PCAP magic bytes
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"  # little-endian
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"  # big-endian
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"   # pcapng block


def _inspect_pcap_header(pcap_path: Path) -> Dict[str, Any]:
    """
    Read only the PCAP global header to extract:
      - file format (pcap vs pcapng)
      - link type
      - timestamp precision
    Returns a dict with 'valid', 'format', 'link_type', 'error'.
    """
    try:
        with open(pcap_path, "rb") as f:
            magic = f.read(4)

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
            return {"valid": True, "format": "pcap", "magic": magic.hex()}
        elif magic == PCAPNG_MAGIC:
            return {"valid": True, "format": "pcapng", "magic": magic.hex()}
        else:
            return {
                "valid": False,
                "format": "unknown",
                "magic": magic.hex(),
                "error": "Unrecognized file header — not a valid PCAP/PCAPNG file"
            }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _count_pcap_packets_fast(pcap_path: Path, max_packets: int = 10000) -> Dict[str, Any]:
    """
    Count packets by parsing PCAP record headers (fast — no packet decoding).
    Stops at max_packets for large files.
    """
    result = {
        "packets_counted": 0,
        "truncated": False,
        "first_timestamp": None,
        "last_timestamp": None,
        "error": None
    }

    try:
        with open(pcap_path, "rb") as f:
            magic = f.read(4)

            if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
                result["error"] = "Cannot count packets: not a standard PCAP (pcapng counting not implemented)"
                return result

            little_endian = magic == PCAP_MAGIC_LE
            endian = "<" if little_endian else ">"

            # Skip rest of global header (20 bytes after magic)
            f.read(20)

            count = 0
            first_ts = None
            last_ts = None

            while True:
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", rec_hdr)
                ts = ts_sec + ts_usec / 1_000_000.0

                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                # Skip packet data
                f.seek(incl_len, 1)
                count += 1

                if count >= max_packets:
                    result["truncated"] = True
                    break

        result["packets_counted"] = count
        result["first_timestamp"] = first_ts
        result["last_timestamp"] = last_ts
        if first_ts and last_ts:
            result["duration_seconds"] = round(last_ts - first_ts, 3)

    except Exception as e:
        result["error"] = str(e)

    return result


def _check_binetflow(pcap_path: Path) -> Dict[str, Any]:
    """
    Look for the associated .binetflow label file for a given PCAP.
    Returns label availability status.
    """
    binetflow_path = pcap_path.with_suffix(".binetflow")
    if not binetflow_path.exists():
        # Try searching the same directory for any .binetflow file
        binetflows = list(pcap_path.parent.glob("*.binetflow"))
        if binetflows:
            binetflow_path = binetflows[0]
        else:
            return {
                "available": False,
                "path": None,
                "message": "No .binetflow label file found — ground truth unavailable"
            }

    try:
        with open(binetflow_path, "r") as f:
            lines = f.readlines()

        header = lines[0].strip() if lines else ""
        label_count = sum(1 for l in lines[1:] if "flow=Botnet" in l or "flow=Normal" in l)
        botnet_count = sum(1 for l in lines[1:] if "flow=Botnet" in l)
        normal_count = sum(1 for l in lines[1:] if "flow=Normal" in l)

        return {
            "available": True,
            "path": str(binetflow_path),
            "total_rows": len(lines) - 1,
            "labeled_rows": label_count,
            "botnet_flows": botnet_count,
            "normal_flows": normal_count,
            "has_header": "StartTime" in header
        }
    except Exception as e:
        return {"available": True, "path": str(binetflow_path), "error": str(e)}


def validate() -> Dict[str, Any]:
    """Main validation logic. Returns validation report dict."""
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": "CTU-13",
        "dataset_dir": str(DATASET_DIR),
        "status": "INSUFFICIENT_DATA",
        "pcap_files": [],
        "binetflow_files": [],
        "summary": {},
        "notes": []
    }

    if not DATASET_DIR.exists():
        report["notes"].append(
            f"Dataset directory does not exist: {DATASET_DIR}. "
            "Create it and place CTU-13 PCAP files inside."
        )
        return report

    # Find all PCAP files
    pcap_extensions = [".pcap", ".pcapng", ".cap"]
    pcap_files = []
    for ext in pcap_extensions:
        pcap_files.extend(DATASET_DIR.glob(f"**/*{ext}"))

    if not pcap_files:
        report["notes"].append(
            "No PCAP files found in dataset directory. "
            f"Download CTU-13 scenario PCAPs from "
            "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/ "
            f"and place them in {DATASET_DIR}."
        )
        return report

    # Inspect each PCAP
    all_valid = True
    total_packets = 0

    for pcap_path in sorted(pcap_files):
        file_info = {
            "filename": pcap_path.name,
            "path": str(pcap_path),
            "size_bytes": pcap_path.stat().st_size,
        }

        # Header check
        header = _inspect_pcap_header(pcap_path)
        file_info.update(header)

        if header.get("valid"):
            # Packet count (fast, non-decoding)
            pkt_info = _count_pcap_packets_fast(pcap_path)
            file_info.update(pkt_info)
            total_packets += pkt_info.get("packets_counted", 0)

            # Label file check
            label_info = _check_binetflow(pcap_path)
            file_info["labels"] = label_info
        else:
            all_valid = False
            file_info["status"] = "INVALID"

        report["pcap_files"].append(file_info)

    # Overall status
    valid_files = [f for f in report["pcap_files"] if f.get("valid")]
    labeled_files = [f for f in valid_files if f.get("labels", {}).get("available")]

    if not valid_files:
        report["status"] = "INVALID"
    elif len(valid_files) < len(report["pcap_files"]):
        report["status"] = "PARTIALLY_AVAILABLE"
    elif labeled_files:
        report["status"] = "VALID"
    else:
        report["status"] = "AVAILABLE"
        report["notes"].append(
            "PCAP files found but no .binetflow label files — "
            "evaluation will proceed as INSUFFICIENT_DATA for labeled metrics."
        )

    report["summary"] = {
        "pcap_files_found": len(pcap_files),
        "pcap_files_valid": len(valid_files),
        "pcap_files_labeled": len(labeled_files),
        "total_packets_sampled": total_packets,
        "ground_truth_available": len(labeled_files) > 0
    }

    return report


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print("Phase 33 — Dataset Validation")
    print(f"Checking: {DATASET_DIR.absolute()}")

    report = validate()

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=4, default=str)

    print(f"Status  : {report['status']}")
    print(f"PCAPs   : {report['summary'].get('pcap_files_found', 0)} found, "
          f"{report['summary'].get('pcap_files_valid', 0)} valid")
    print(f"Labels  : {report['summary'].get('pcap_files_labeled', 0)} with binetflow")
    print(f"Packets : {report['summary'].get('total_packets_sampled', 0)} (sampled, <=10k per file)")
    print(f"Report  : {REPORT_PATH}")

    for note in report.get("notes", []):
        print(f"NOTE: {note}")


if __name__ == "__main__":
    main()
