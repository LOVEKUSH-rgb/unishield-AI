"""
UniShield AI -- Entropy Features
==================================
Reusable Shannon entropy functions used across multiple feature
modules (DNS, behavioral, traffic analysis).

The functions here are pure mathematical utilities.
They do NOT make classification decisions.

Shannon entropy H = -sum(p_i * log2(p_i))
  Higher entropy = more uniform/random distribution
  Lower entropy = more concentrated distribution

Uses:
  - dns_features.py:   entropy of domain character distributions
  - behavioral_features.py: entropy of source/destination IP sets
  - dga_dns.py detector (future): entropy threshold for DGA detection

Numerical stability:
  - All probability values clamped to (0, 1]
  - log2(0) protected by the p > 0 guard
  - Empty inputs return 0.0 (not NaN)
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Optional, Sequence, TypeVar

T = TypeVar("T")


def shannon_entropy(values: Iterable[T]) -> float:
    """
    Compute Shannon entropy (in bits) of a sequence of categorical values.

    H = -sum(p_i * log2(p_i)) for all unique values with count > 0.

    Parameters
    ----------
    values:
        Any iterable of hashable items (characters, IP addresses, etc.).

    Returns
    -------
    float
        Entropy in bits. Returns 0.0 for empty or single-unique-value input.

    Examples
    --------
    >>> shannon_entropy("aaaaaa")    # all same -> 0.0
    0.0
    >>> shannon_entropy("abcd")      # 4 equally likely -> 2.0
    2.0
    >>> shannon_entropy([])          # empty -> 0.0
    0.0
    """
    counts = Counter(values)
    total = sum(counts.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    # Guard against floating point noise producing tiny negatives
    return max(0.0, entropy)


def string_entropy(text: str) -> float:
    """
    Compute Shannon entropy of the character distribution in a string.

    Parameters
    ----------
    text:
        Any string (e.g. a domain name, hostname).

    Returns
    -------
    float
        Entropy in bits. 0.0 for empty or single-character strings.
    """
    return shannon_entropy(text.lower()) if text else 0.0


def normalised_entropy(values: Iterable[T]) -> float:
    """
    Shannon entropy normalised to [0, 1] by dividing by log2(n_unique).

    Returns 0.0 when there is only one unique value or input is empty.
    Returns 1.0 when all values are equally likely.

    Parameters
    ----------
    values:
        Any iterable of hashable items.

    Returns
    -------
    float
        Normalised entropy in [0, 1].
    """
    items = list(values)
    if not items:
        return 0.0

    n_unique = len(set(items))
    if n_unique <= 1:
        return 0.0

    raw = shannon_entropy(items)
    max_entropy = math.log2(n_unique)
    if max_entropy == 0.0:
        return 0.0

    result = raw / max_entropy
    return max(0.0, min(1.0, result))


def ip_set_entropy(ip_list: Sequence[str]) -> float:
    """
    Compute Shannon entropy of a sequence of IP addresses.

    A low value indicates most traffic comes from/goes to a small set
    of IPs (concentrated). A high value indicates many different IPs.

    Parameters
    ----------
    ip_list:
        List of IP address strings.

    Returns
    -------
    float
        Entropy in bits.
    """
    return shannon_entropy(ip_list)


def ngram_frequencies(text: str, n: int = 3) -> dict[str, int]:
    """
    Count all n-grams in a string.

    Parameters
    ----------
    text:
        Input string (e.g. domain name without TLD).
    n:
        N-gram length (default 3 for trigrams).

    Returns
    -------
    dict
        Mapping of n-gram string -> count.
    """
    text = text.lower()
    if len(text) < n:
        return {}
    freqs: dict[str, int] = {}
    for i in range(len(text) - n + 1):
        gram = text[i: i + n]
        freqs[gram] = freqs.get(gram, 0) + 1
    return freqs


def ngram_entropy(text: str, n: int = 3) -> float:
    """
    Shannon entropy of n-gram distribution in a string.

    Useful as a feature for DGA detection: DGA domains tend to have
    high n-gram entropy compared to legitimate domain names.

    Parameters
    ----------
    text:
        Domain or label string.
    n:
        N-gram length.

    Returns
    -------
    float
        Entropy in bits.
    """
    freqs = ngram_frequencies(text, n)
    if not freqs:
        return 0.0
    return shannon_entropy(list(freqs.values()))
