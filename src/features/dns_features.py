"""
UniShield AI -- DNS Features
==============================
Extracts metadata-only features from DNS query/response information.

Features produced (all from observable metadata, no payload decryption):

  Lexical:
    dns_query_length        -- total character length of FQDN
    dns_label_count         -- number of dot-separated labels
    dns_max_label_length    -- length of longest label
    dns_digit_ratio         -- fraction of digits in FQDN
    dns_alpha_ratio         -- fraction of alphabetic chars
    dns_hyphen_ratio        -- fraction of hyphens
    dns_unique_char_count   -- number of unique characters used
    dns_entropy             -- Shannon entropy of character distribution

  N-gram:
    dns_ngram_entropy       -- entropy of trigram distribution
    (configurable n via ngram_size parameter)

  Record type:
    dns_is_query            -- 1 if query, 0 if response
    dns_query_type_A        -- 1 if type A
    dns_query_type_AAAA     -- 1 if type AAAA
    dns_query_type_TXT      -- 1 if type TXT (often used for tunnelling)
    dns_query_type_MX       -- 1 if type MX
    dns_query_type_NS       -- 1 if type NS
    dns_query_type_other    -- 1 if any other type

  Response:
    dns_answer_count        -- number of answers
    dns_is_nxdomain         -- 1 if NXDOMAIN response

DO NOT classify DGA or tunnelling here.
These are FEATURES only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from src.features.entropy_features import string_entropy, ngram_entropy
from src.utils.config import get_config

if TYPE_CHECKING:
    from src.ingestion.models import DNSInfo
    from src.features.feature_vector import FeatureVector


def _get_ngram_size() -> int:
    """Read n-gram size from config, default 3."""
    try:
        return int(get_config()["features"]["entropy"]["ngram_size"])
    except (KeyError, TypeError, ValueError):
        return 3


_SUSPICIOUS_TYPES = {"TXT", "NULL", "ANY"}
_TUNNEL_TYPES = {"TXT", "NULL"}


def extract_dns_features(dns: "DNSInfo", fv: "FeatureVector") -> None:
    """
    Extract DNS metadata features from a DNSInfo object.

    Parameters
    ----------
    dns:
        Populated DNSInfo extracted from a NetworkEvent.
    fv:
        FeatureVector to update in-place.

    Notes
    -----
    All features are None when the corresponding DNS field is absent.
    No features relate to response content or payload bytes.
    """
    features: dict = {}
    ngram_n = _get_ngram_size()

    # ----------------------------------------------------------------
    # Query is/response flag
    # ----------------------------------------------------------------
    features["dns_is_query"] = int(dns.is_query) if dns.is_query is not None else None

    # ----------------------------------------------------------------
    # Query name lexical features
    # ----------------------------------------------------------------
    qname = dns.query_name

    if qname:
        # Strip trailing dot if present
        qname_clean = qname.rstrip(".")
        features["dns_query_name"] = qname_clean
        features["dns_query_length"] = len(qname_clean)

        labels = [lbl for lbl in qname_clean.split(".") if lbl]
        features["dns_label_count"] = len(labels)
        features["dns_max_label_length"] = max(len(lbl) for lbl in labels) if labels else 0

        # Work on the full domain (without TLD if desired — use full for now)
        full = qname_clean.replace(".", "")

        total = max(len(full), 1)
        digit_count = sum(c.isdigit() for c in full)
        alpha_count = sum(c.isalpha() for c in full)
        hyphen_count = full.count("-")

        features["dns_digit_ratio"] = digit_count / total
        features["dns_alpha_ratio"] = alpha_count / total
        features["dns_hyphen_ratio"] = hyphen_count / total
        features["dns_unique_char_count"] = len(set(full))
        features["dns_entropy"] = string_entropy(full)

        # N-gram entropy on the first (most significant) non-TLD label
        primary_label = labels[0] if labels else qname_clean
        features["dns_ngram_entropy"] = ngram_entropy(primary_label, n=ngram_n)
    else:
        for key in (
            "dns_query_name", "dns_query_length", "dns_label_count", "dns_max_label_length",
            "dns_digit_ratio", "dns_alpha_ratio", "dns_hyphen_ratio",
            "dns_unique_char_count", "dns_entropy", "dns_ngram_entropy",
        ):
            features[key] = None

    # ----------------------------------------------------------------
    # Query type one-hot encoding
    # ----------------------------------------------------------------
    qtype = (dns.query_type or "").upper()
    features["dns_query_type_A"] = int(qtype == "A")
    features["dns_query_type_AAAA"] = int(qtype == "AAAA")
    features["dns_query_type_TXT"] = int(qtype == "TXT")
    features["dns_query_type_MX"] = int(qtype == "MX")
    features["dns_query_type_NS"] = int(qtype == "NS")
    features["dns_query_type_NULL"] = int(qtype == "NULL")
    features["dns_query_type_other"] = int(
        qtype not in ("A", "AAAA", "TXT", "MX", "NS", "NULL", "")
    )
    features["dns_is_suspicious_type"] = int(qtype in _SUSPICIOUS_TYPES)

    # ----------------------------------------------------------------
    # Response features
    # ----------------------------------------------------------------
    if dns.answer_count is not None:
        features["dns_answer_count"] = dns.answer_count
    else:
        features["dns_answer_count"] = None

    features["dns_is_nxdomain"] = int(
        (dns.response_code or "").upper() == "NXDOMAIN"
    )

    fv.update("dns", features)


def compute_query_frequency(
    timestamps: list[float],
    window_seconds: float = 60.0,
) -> float:
    """
    Compute the query rate (queries per second) over a time window.

    Parameters
    ----------
    timestamps:
        List of UNIX epoch timestamps for DNS queries from one source.
    window_seconds:
        Time window for rate computation.

    Returns
    -------
    float
        Query rate in queries/second.
    """
    if not timestamps or window_seconds <= 0.0:
        return 0.0
    if len(timestamps) == 1:
        return 1.0 / window_seconds

    window_start = max(timestamps) - window_seconds
    in_window = [t for t in timestamps if t >= window_start]
    return len(in_window) / window_seconds
