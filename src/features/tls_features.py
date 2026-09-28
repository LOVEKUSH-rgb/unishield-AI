"""
UniShield AI -- TLS/QUIC Features
====================================
Extracts metadata-only features from TLS session information.

CRITICAL CONSTRAINT:
  NO TLS DECRYPTION.
  NO certificate fetching from remote servers.
  NO active connections.
  ALL features come from locally observable cleartext handshake
  metadata or from per-flow packet statistics.

Features produced:

  From TLSInfo (handshake metadata):
    tls_version_is_tls13     -- 1 if TLS 1.3
    tls_version_is_tls12     -- 1 if TLS 1.2
    tls_version_is_old       -- 1 if TLS 1.0 / SSLv3 (anomalous)
    tls_has_sni              -- 1 if SNI field present
    tls_sni_length           -- length of SNI string
    tls_has_ja3              -- 1 if JA3 fingerprint present
    tls_has_ja3s             -- 1 if JA3S fingerprint present
    tls_is_self_signed       -- 1 if cert appears self-signed (from Zeek ssl.log)
    tls_resumed              -- 1 if session resumption observed
    tls_sni_entropy          -- entropy of SNI string characters

  From per-flow packet statistics (already in fv from flow features):
    (The flow features extractor already provides pkt_size_* and iat_*)
    tls_flow_pkt_count       -- alias for total packet count in session
    tls_flow_duration        -- alias for flow duration

  If a field is unavailable (ECH, ESNI, etc.), it is set to None
  rather than inventing a value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from src.features.entropy_features import string_entropy

if TYPE_CHECKING:
    from src.ingestion.models import TLSInfo
    from src.features.feature_vector import FeatureVector

# ----------------------------------------------------------------
# Known TLS version strings
# ----------------------------------------------------------------
_TLS13_STRINGS = {"tls 1.3", "tlsv1.3", "tlsv13", "tls1.3"}
_TLS12_STRINGS = {"tls 1.2", "tlsv1.2", "tlsv12", "tls1.2"}
_OLD_TLS_STRINGS = {"tls 1.0", "tls 1.1", "ssl 3.0", "ssl3.0",
                     "tlsv1", "tlsv1.0", "tlsv1.1", "sslv3"}


def _classify_tls_version(version: Optional[str]) -> tuple[int, int, int]:
    """
    Classify TLS version string into three binary flags.

    Returns (is_tls13, is_tls12, is_old).
    """
    if version is None:
        return 0, 0, 0
    v = version.lower().strip()
    if v in _TLS13_STRINGS:
        return 1, 0, 0
    if v in _TLS12_STRINGS:
        return 0, 1, 0
    if v in _OLD_TLS_STRINGS:
        return 0, 0, 1
    return 0, 0, 0


def extract_tls_features(tls: "TLSInfo", fv: "FeatureVector") -> None:
    """
    Extract TLS metadata features from a TLSInfo object.

    Parameters
    ----------
    tls:
        TLSInfo populated from the PCAP reader or Zeek ssl.log.
    fv:
        FeatureVector to update in-place.

    PASSIVE AUDIT:
      [PASS] No certificate download
      [PASS] No TLS handshake initiated
      [PASS] No decryption — only reads cleartext fields
    """
    features: dict = {}

    # ----------------------------------------------------------------
    # Version classification
    # ----------------------------------------------------------------
    is_13, is_12, is_old = _classify_tls_version(tls.version)
    features["tls_version_is_tls13"] = is_13
    features["tls_version_is_tls12"] = is_12
    features["tls_version_is_old"] = is_old
    features["tls_version_known"] = int(is_13 + is_12 + is_old > 0)
    features["tls_version_str"] = tls.version  # string metadata

    # ----------------------------------------------------------------
    # SNI
    # ----------------------------------------------------------------
    if tls.sni:
        features["tls_has_sni"] = 1
        features["tls_sni_length"] = len(tls.sni)
        features["tls_sni_entropy"] = string_entropy(tls.sni)
    else:
        features["tls_has_sni"] = 0
        features["tls_sni_length"] = None
        features["tls_sni_entropy"] = None

    # ----------------------------------------------------------------
    # JA3/JA3S fingerprints
    # ----------------------------------------------------------------
    features["tls_has_ja3"] = int(bool(tls.ja3_fingerprint))
    features["tls_has_ja3s"] = int(bool(tls.ja3s_fingerprint))
    # Store as string metadata for the detector to look up
    features["tls_ja3"] = tls.ja3_fingerprint
    features["tls_ja3s"] = tls.ja3s_fingerprint

    # ----------------------------------------------------------------
    # Certificate metadata (from Zeek ssl.log — NOT fetched actively)
    # ----------------------------------------------------------------
    features["tls_is_self_signed"] = (
        int(tls.is_self_signed) if tls.is_self_signed is not None else None
    )
    features["tls_resumed"] = (
        int(tls.resumed) if tls.resumed is not None else None
    )

    # Cert subject/issuer available as string metadata
    features["tls_cert_subject"] = tls.cert_subject
    features["tls_cert_issuer"] = tls.cert_issuer

    fv.update("tls", features)
