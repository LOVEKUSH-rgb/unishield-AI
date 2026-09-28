"""
UniShield AI -- Phase 2 Tests
================================
Comprehensive tests for the entire feature engine.

Covers:
  FeatureVector model
  Flow features (packet stats, rates, TCP flags)
  Timing features (IAT, CV, periodicity, jitter)
  Entropy features (Shannon entropy, n-grams)
  DNS features (lexical, record type, response)
  TLS features (version classification, SNI, JA3)
  Windowing engine (TimeWindow, WindowSet)
  Behavioral aggregator (SourceProfile, DestinationProfile)
  Feature pipeline (end-to-end, stream)

All tests use synthetic data clearly labelled as such.
No network activity is performed during these tests.

Run:
    python -m pytest tests/test_phase2.py -v
"""

from __future__ import annotations

import math
import time
from pathlib import Path
from typing import List

import pytest

PROJECT_ROOT = Path(__file__).parents[1]

# ================================================================
# Helpers
# ================================================================

def _make_flow(
    src="192.168.1.1", dst="10.0.0.1",
    sport=54321, dport=80, proto=6,
    n_packets=5, base_ts=1_700_000_000.0,
    pkt_sizes=None,
    flags_list=None,
    iat=0.1,
) -> "FlowRecord":
    """Build a synthetic FlowRecord with n_packets."""
    from src.ingestion.models import NetworkEvent
    from src.flows.flow import FlowRecord

    if pkt_sizes is None:
        pkt_sizes = [100] * n_packets
    if flags_list is None:
        flags_list = [0x02] + [0x10] * (n_packets - 2) + [0x01]
        if n_packets == 1:
            flags_list = [0x02]

    events = []
    for i in range(n_packets):
        events.append(NetworkEvent(
            timestamp=base_ts + i * iat,
            source_ip=src, destination_ip=dst,
            source_port=sport, destination_port=dport,
            protocol=proto,
            packet_length=pkt_sizes[i % len(pkt_sizes)],
            tcp_flags=flags_list[i % len(flags_list)],
        ))

    flow = FlowRecord.from_event(events[0])
    for e in events[1:]:
        flow.update(e)
    return flow


def _make_dns_event(qname="example.com", qtype="A", is_query=True, nxdomain=False):
    """Build a NetworkEvent with DNSInfo."""
    from src.ingestion.models import NetworkEvent, DNSInfo
    dns = DNSInfo(
        query_name=qname,
        query_type=qtype,
        is_query=is_query,
        response_code="NXDOMAIN" if nxdomain else "NOERROR",
        answer_count=0 if nxdomain else 1,
    )
    return NetworkEvent(timestamp=1_700_000_000.0, dns=dns, protocol=17)


def _make_tls_event(version="TLS 1.3", sni="example.com", ja3="abc123"):
    """Build a NetworkEvent with TLSInfo."""
    from src.ingestion.models import NetworkEvent, TLSInfo
    tls = TLSInfo(version=version, sni=sni, ja3_fingerprint=ja3)
    return NetworkEvent(timestamp=1_700_000_000.0, tls=tls, protocol=6)


# ================================================================
# 1. FeatureVector
# ================================================================

class TestFeatureVector:

    def test_create_empty(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        assert fv.features == {}
        assert fv.feature_groups == []

    def test_set_and_get(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.set("packet_count", 42)
        assert fv.get("packet_count") == 42

    def test_get_default(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        assert fv.get("missing_feature", -1) == -1

    def test_update_merges_features(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.update("flow", {"packets": 10, "bytes": 1000})
        assert fv.features["packets"] == 10
        assert "flow" in fv.feature_groups

    def test_update_no_duplicate_groups(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.update("flow", {"a": 1})
        fv.update("flow", {"b": 2})
        assert fv.feature_groups.count("flow") == 1

    def test_numeric_features_drops_none_and_strings(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.update("test", {"a": 1.5, "b": None, "c": "text", "d": 0.0})
        numeric = fv.numeric_features()
        assert "a" in numeric
        assert "b" not in numeric
        assert "c" not in numeric
        assert "d" in numeric

    def test_validate_no_infinities_detects_nan(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.set("bad_feature", float("nan"))
        bad = fv.validate_no_infinities()
        assert "bad_feature" in bad

    def test_validate_no_infinities_detects_inf(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.set("inf_feature", float("inf"))
        bad = fv.validate_no_infinities()
        assert "inf_feature" in bad

    def test_validate_clean_vector(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.update("test", {"a": 1.0, "b": 0.5})
        assert fv.validate_no_infinities() == []

    def test_to_dict_json_serialisable(self):
        import json
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector(flow_id="test-id", source_ip="1.2.3.4")
        fv.update("flow", {"packets": 10})
        d = fv.to_dict()
        json.dumps(d)  # should not raise

    def test_has_group(self):
        from src.features.feature_vector import FeatureVector
        fv = FeatureVector()
        fv.update("timing", {"iat_mean": 0.1})
        assert fv.has_group("timing")
        assert not fv.has_group("dns")


# ================================================================
# 2. Flow Features
# ================================================================

class TestFlowFeatures:

    def test_basic_extraction(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=5)
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("packet_count") == 5
        assert fv.get("byte_count") == 500

    def test_duration_feature(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=5, iat=1.0)
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("flow_duration") == pytest.approx(4.0, abs=0.01)

    def test_rates_computed_for_multi_packet_flow(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=10, iat=1.0, pkt_sizes=[100])
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("packets_per_second") == pytest.approx(10 / 9.0, abs=0.1)
        assert fv.get("bytes_per_second") is not None

    def test_rates_none_for_zero_duration(self):
        """Single-packet flow has zero duration -> rates undefined."""
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=1)
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("packets_per_second") is None
        assert fv.get("bytes_per_second") is None

    def test_pkt_size_stats(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=4, pkt_sizes=[100, 200, 300, 400])
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("pkt_size_min") == 100.0
        assert fv.get("pkt_size_max") == 400.0
        assert fv.get("pkt_size_mean") == pytest.approx(250.0, abs=1.0)

    def test_pkt_size_std_for_uniform(self):
        """All same size -> std should be 0."""
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=5, pkt_sizes=[100, 100, 100, 100, 100])
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("pkt_size_std") == pytest.approx(0.0, abs=0.001)

    def test_tcp_flag_counts(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        # SYN, ACK, FIN sequence
        flow = _make_flow(n_packets=3, flags_list=[0x02, 0x10, 0x01])
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("tcp_syn_count") == 1
        assert fv.get("tcp_fin_count") == 1

    def test_syn_ratio(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        # All SYN packets
        flow = _make_flow(n_packets=4, flags_list=[0x02, 0x02, 0x02, 0x02])
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert fv.get("tcp_syn_ratio") == pytest.approx(1.0)

    def test_feature_group_recorded(self):
        from src.features.flow_features import extract_flow_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow()
        fv = FeatureVector()
        extract_flow_features(flow, fv)
        assert "flow" in fv.feature_groups


# ================================================================
# 3. Timing Features
# ================================================================

class TestTimingFeatures:

    def test_iat_mean_regular(self):
        from src.features.timing_features import extract_timing_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=5, iat=1.0)
        fv = FeatureVector()
        extract_timing_features(flow, fv)
        assert fv.get("iat_mean") == pytest.approx(1.0, abs=0.01)

    def test_iat_none_for_single_packet(self):
        from src.features.timing_features import extract_timing_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=1)
        fv = FeatureVector()
        extract_timing_features(flow, fv)
        assert fv.get("iat_mean") is None

    def test_iat_min_max(self):
        from src.features.timing_features import extract_timing_features
        from src.features.feature_vector import FeatureVector
        flow = _make_flow(n_packets=4, iat=0.5)
        fv = FeatureVector()
        extract_timing_features(flow, fv)
        assert fv.get("iat_min") == pytest.approx(0.5, abs=0.01)
        assert fv.get("iat_max") == pytest.approx(0.5, abs=0.01)

    def test_coefficient_of_variation_regular(self):
        """Regular IAT -> low CV."""
        from src.features.timing_features import coefficient_of_variation
        iats = [1.0] * 10
        cv = coefficient_of_variation(iats)
        assert cv == pytest.approx(0.0, abs=0.001)

    def test_coefficient_of_variation_irregular(self):
        """Very irregular IAT -> higher CV."""
        from src.features.timing_features import coefficient_of_variation
        iats = [0.1, 10.0, 0.2, 9.0, 0.3]
        cv = coefficient_of_variation(iats)
        assert cv is not None
        assert cv > 0.5

    def test_cv_none_for_single_sample(self):
        from src.features.timing_features import coefficient_of_variation
        assert coefficient_of_variation([1.0]) is None

    def test_cv_none_for_zero_mean(self):
        from src.features.timing_features import coefficient_of_variation
        assert coefficient_of_variation([0.0, 0.0, 0.0]) is None

    def test_periodicity_score_regular(self):
        """Highly regular intervals -> periodicity score close to 1."""
        from src.features.timing_features import periodicity_score
        iats = [1.0] * 20
        score = periodicity_score(iats)
        assert score is not None
        assert score == pytest.approx(1.0, abs=0.01)

    def test_periodicity_score_none_few_samples(self):
        from src.features.timing_features import periodicity_score
        assert periodicity_score([1.0, 2.0]) is None

    def test_periodicity_score_in_unit_interval(self):
        from src.features.timing_features import periodicity_score
        iats = [0.1, 5.0, 0.2, 4.9, 0.3, 5.1, 0.1, 4.8]
        score = periodicity_score(iats)
        if score is not None:
            assert 0.0 <= score <= 1.0

    def test_iat_jitter_regular(self):
        """Regular intervals -> jitter close to 0."""
        from src.features.timing_features import iat_jitter
        iats = [1.0] * 10
        assert iat_jitter(iats) == pytest.approx(0.0, abs=0.001)

    def test_iat_jitter_none_single(self):
        from src.features.timing_features import iat_jitter
        assert iat_jitter([1.0]) is None


# ================================================================
# 4. Entropy Features
# ================================================================

class TestEntropyFeatures:

    def test_uniform_entropy_maximum(self):
        """All unique values -> maximum entropy = log2(n)."""
        from src.features.entropy_features import shannon_entropy
        n = 8
        values = list(range(n))
        h = shannon_entropy(values)
        assert h == pytest.approx(math.log2(n), abs=0.001)

    def test_single_value_entropy_zero(self):
        from src.features.entropy_features import shannon_entropy
        assert shannon_entropy(["a"] * 100) == pytest.approx(0.0)

    def test_empty_entropy_zero(self):
        from src.features.entropy_features import shannon_entropy
        assert shannon_entropy([]) == 0.0

    def test_binary_entropy_one_bit(self):
        """50/50 binary -> H = 1 bit."""
        from src.features.entropy_features import shannon_entropy
        h = shannon_entropy(["a", "b"] * 50)
        assert h == pytest.approx(1.0, abs=0.001)

    def test_string_entropy_high_for_random(self):
        from src.features.entropy_features import string_entropy
        # DGA-like random domain
        h = string_entropy("xkq7mz2nwjp4")
        assert h > 2.0

    def test_string_entropy_low_for_repetitive(self):
        from src.features.entropy_features import string_entropy
        h = string_entropy("aaaaaaa")
        assert h == pytest.approx(0.0)

    def test_normalised_entropy_all_same(self):
        from src.features.entropy_features import normalised_entropy
        assert normalised_entropy(["a"] * 10) == 0.0

    def test_normalised_entropy_all_unique(self):
        from src.features.entropy_features import normalised_entropy
        result = normalised_entropy(list("abcdef"))
        assert result == pytest.approx(1.0, abs=0.001)

    def test_normalised_entropy_in_unit_interval(self):
        from src.features.entropy_features import normalised_entropy
        for _ in range(10):
            values = ["a", "b", "a", "c", "b", "a"]
            r = normalised_entropy(values)
            assert 0.0 <= r <= 1.0

    def test_ip_set_entropy(self):
        from src.features.entropy_features import ip_set_entropy
        # Uniform distribution of IPs -> high entropy
        ips = [f"10.0.0.{i}" for i in range(16)]
        h = ip_set_entropy(ips)
        assert h == pytest.approx(4.0, abs=0.01)

    def test_ngram_frequencies(self):
        from src.features.entropy_features import ngram_frequencies
        freqs = ngram_frequencies("abcabc", n=2)
        assert freqs.get("ab") == 2
        assert freqs.get("bc") == 2
        assert freqs.get("ca") == 1

    def test_ngram_frequencies_short_string(self):
        from src.features.entropy_features import ngram_frequencies
        freqs = ngram_frequencies("ab", n=3)
        assert freqs == {}

    def test_ngram_entropy_dga_like(self):
        from src.features.entropy_features import ngram_entropy
        h = ngram_entropy("xkq7mz2n", n=2)
        assert h >= 0.0

    def test_entropy_numerical_stability(self):
        """Very small probabilities must not produce NaN."""
        from src.features.entropy_features import shannon_entropy
        values = ["x"] * 999 + ["y"] * 1
        h = shannon_entropy(values)
        assert math.isfinite(h)
        assert h > 0.0


# ================================================================
# 5. DNS Features
# ================================================================

class TestDNSFeatures:

    def test_query_length(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("example.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        # dns_query_length = len("example.com") = 11 (full cleaned FQDN)
        assert fv.get("dns_query_length") == len("example.com")

    def test_label_count(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("sub.example.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        assert fv.get("dns_label_count") == 3

    def test_entropy_high_for_dga_like(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("xkq7mz2nwjp4.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        assert fv.get("dns_entropy") > 2.0

    def test_entropy_low_for_clean(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("aaaaaaa.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        # 'aaaaaacom' has 4 unique chars; entropy < DGA-like strings (> 2.0)
        # We just check it's less than the DGA-like case (> 2.0)
        dga_ev = _make_dns_event("xkq7mz2nwjp4.com")
        dga_fv = FeatureVector()
        extract_dns_features(dga_ev.dns, dga_fv)
        assert fv.get("dns_entropy") < dga_fv.get("dns_entropy")

    def test_digit_ratio(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("abc123.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        ratio = fv.get("dns_digit_ratio")
        assert ratio is not None
        assert 0.0 < ratio < 1.0

    def test_alpha_ratio_pure_alpha(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("google.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        ratio = fv.get("dns_alpha_ratio")
        assert ratio == pytest.approx(1.0, abs=0.01)

    def test_txt_query_type_flagged(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event(qtype="TXT")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        assert fv.get("dns_query_type_TXT") == 1
        assert fv.get("dns_is_suspicious_type") == 1

    def test_a_query_type_not_suspicious(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event(qtype="A")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        assert fv.get("dns_query_type_A") == 1
        assert fv.get("dns_is_suspicious_type") == 0

    def test_nxdomain_flagged(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event(nxdomain=True)
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        assert fv.get("dns_is_nxdomain") == 1

    def test_missing_query_name_safe(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        from src.ingestion.models import DNSInfo
        dns = DNSInfo()  # all None
        fv = FeatureVector()
        extract_dns_features(dns, fv)
        assert fv.get("dns_query_length") is None
        assert fv.get("dns_entropy") is None

    def test_query_frequency(self):
        from src.features.dns_features import compute_query_frequency
        # 30 queries in the last 60s window
        ts = [1_700_000_000.0 + i for i in range(30)]
        rate = compute_query_frequency(ts, window_seconds=60.0)
        assert rate == pytest.approx(0.5, abs=0.01)

    def test_ngram_entropy_computed(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        ev = _make_dns_event("google.com")
        fv = FeatureVector()
        extract_dns_features(ev.dns, fv)
        assert fv.get("dns_ngram_entropy") is not None


# ================================================================
# 6. TLS Features
# ================================================================

class TestTLSFeatures:

    def test_tls13_detected(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event(version="TLS 1.3")
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_version_is_tls13") == 1
        assert fv.get("tls_version_is_tls12") == 0
        assert fv.get("tls_version_is_old") == 0

    def test_tls12_detected(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event(version="TLS 1.2")
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_version_is_tls12") == 1

    def test_old_tls_detected(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event(version="TLS 1.0")
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_version_is_old") == 1

    def test_unknown_version_not_classified(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event(version="QUIC")
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_version_is_tls13") == 0
        assert fv.get("tls_version_is_old") == 0
        assert fv.get("tls_version_known") == 0

    def test_sni_features(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event(sni="api.example.com")
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_has_sni") == 1
        assert fv.get("tls_sni_length") == len("api.example.com")
        assert fv.get("tls_sni_entropy") is not None

    def test_no_sni_features_none(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        from src.ingestion.models import TLSInfo
        tls = TLSInfo(version="TLS 1.3")  # no SNI
        from src.ingestion.models import NetworkEvent
        ev = NetworkEvent(timestamp=1.0, tls=tls)
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_has_sni") == 0
        assert fv.get("tls_sni_length") is None

    def test_ja3_presence_flagged(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event(ja3="abc123def456")
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_has_ja3") == 1

    def test_no_ja3_flagged(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        from src.ingestion.models import TLSInfo, NetworkEvent
        tls = TLSInfo(version="TLS 1.2")
        ev = NetworkEvent(timestamp=1.0, tls=tls)
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_has_ja3") == 0

    def test_self_signed_flag(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        from src.ingestion.models import TLSInfo, NetworkEvent
        tls = TLSInfo(version="TLS 1.2", is_self_signed=True)
        ev = NetworkEvent(timestamp=1.0, tls=tls)
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert fv.get("tls_is_self_signed") == 1

    def test_tls_feature_group_recorded(self):
        from src.features.tls_features import extract_tls_features
        from src.features.feature_vector import FeatureVector
        ev = _make_tls_event()
        fv = FeatureVector()
        extract_tls_features(ev.tls, fv)
        assert "tls" in fv.feature_groups


# ================================================================
# 7. Time Windows
# ================================================================

class TestWindowing:

    def test_time_window_add_and_count(self):
        from src.features.windowing import TimeWindow
        w = TimeWindow(60.0)
        w.add(1000.0, "a")
        w.add(1010.0, "b")
        assert w.count(1010.0) == 2

    def test_time_window_evicts_old_items(self):
        from src.features.windowing import TimeWindow
        w = TimeWindow(30.0)
        w.add(1000.0, "old")
        w.add(1040.0, "new")
        # At time 1040, item at 1000 is 40s old -> evicted
        assert w.count(1040.0) == 1
        assert w.items(1040.0) == ["new"]

    def test_time_window_items_in_window(self):
        from src.features.windowing import TimeWindow
        w = TimeWindow(10.0)
        for i in range(5):
            w.add(float(i), i)
        # At time 4.5, items 0..4 are within [4.5-10, 4.5] -> all 5
        assert w.count(4.5) == 5

    def test_time_window_max_items_cap(self):
        from src.features.windowing import TimeWindow
        w = TimeWindow(1000.0, max_items=3)
        for i in range(5):
            w.add(float(i), i)
        assert w.count() <= 3

    def test_time_window_invalid_size_raises(self):
        from src.features.windowing import TimeWindow
        with pytest.raises(ValueError):
            TimeWindow(-1.0)

    def test_window_set_multiple_sizes(self):
        from src.features.windowing import WindowSet
        ws = WindowSet([10.0, 30.0, 60.0])
        ws.add(1000.0, "x")
        ws.add(1050.0, "y")
        # At time 1050, item at 1000 is outside 10s but inside 60s
        assert ws.count(10.0, 1050.0) == 1
        assert ws.count(60.0, 1050.0) == 2

    def test_window_set_counts_all(self):
        from src.features.windowing import WindowSet
        ws = WindowSet([10.0, 60.0])
        ws.add(1000.0, "a")
        counts = ws.counts_all(1000.0)
        assert 10.0 in counts
        assert 60.0 in counts

    def test_window_set_key_error_for_unknown_size(self):
        from src.features.windowing import WindowSet
        ws = WindowSet([10.0])
        with pytest.raises(KeyError):
            ws.count(99.0)

    def test_window_clear(self):
        from src.features.windowing import TimeWindow
        w = TimeWindow(60.0)
        w.add(1000.0, "x")
        w.clear()
        assert w.count() == 0


# ================================================================
# 8. Behavioral Features
# ================================================================

class TestBehavioralFeatures:

    def _make_flow_sequence(self, src, dsts, dports, n=1, base_ts=1_700_000_000.0):
        """Helper to produce multiple flows from the same source."""
        flows = []
        for i, (dst, dport) in enumerate(zip(dsts, dports)):
            f = _make_flow(
                src=src, dst=dst,
                sport=50000 + i, dport=dport,
                n_packets=3, base_ts=base_ts + i * 0.5,
            )
            flows.append(f)
        return flows

    def test_unique_dst_hosts_increments(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        flows = self._make_flow_sequence(
            "192.168.1.1",
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            [80, 443, 22],
        )
        for f in flows:
            agg.record_flow(f)
        feats = agg.get_source_features("192.168.1.1", flows[-1].last_seen)
        assert feats.get("src_uniq_dst_hosts_60s") == 3

    def test_unique_dst_ports(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        flows = self._make_flow_sequence(
            "192.168.1.1",
            ["10.0.0.1"] * 5,
            [22, 80, 443, 8080, 3306],
        )
        for f in flows:
            agg.record_flow(f)
        feats = agg.get_source_features("192.168.1.1", flows[-1].last_seen)
        assert feats.get("src_uniq_dst_ports_60s") == 5

    def test_conn_count(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        flows = self._make_flow_sequence(
            "192.168.1.100",
            ["10.0.0.1"] * 7,
            [80] * 7,
        )
        for f in flows:
            agg.record_flow(f)
        feats = agg.get_source_features("192.168.1.100", flows[-1].last_seen)
        assert feats.get("src_conn_count_60s") == 7

    def test_bytes_out_accumulates(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        flows = self._make_flow_sequence(
            "192.168.1.1",
            ["10.0.0.1"] * 3,
            [80, 443, 22],
        )
        for f in flows:
            agg.record_flow(f)
        feats = agg.get_source_features("192.168.1.1", flows[-1].last_seen)
        assert feats.get("src_bytes_out_60s", 0) > 0

    def test_window_eviction(self):
        """Flows outside the window should not count."""
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[10.0])

        # Old flow (at T=0)
        old = _make_flow(src="1.2.3.4", dst="5.6.7.8", dport=80, base_ts=0.0)
        agg.record_flow(old)

        # New flow (at T=20, outside 10s window)
        new = _make_flow(src="1.2.3.4", dst="5.6.7.9", dport=443, base_ts=20.0)
        agg.record_flow(new)

        feats = agg.get_source_features("1.2.3.4", 20.0)
        # Only new flow should be in 10s window
        assert feats.get("src_conn_count_10s") == 1

    def test_destination_unique_sources(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])

        flows = [
            _make_flow(src=f"10.0.0.{i}", dst="192.168.1.1", dport=80)
            for i in range(1, 6)
        ]
        for f in flows:
            agg.record_flow(f)

        feats = agg.get_destination_features("192.168.1.1", flows[-1].last_seen)
        assert feats.get("dst_uniq_src_hosts_60s") == 5

    def test_dst_src_concentration_uniform(self):
        """Many sources -> low concentration (high diversity)."""
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        # 16 different sources
        for i in range(16):
            f = _make_flow(src=f"10.0.{i}.1", dst="5.5.5.5", dport=80,
                           base_ts=1_700_000_000.0 + i)
            agg.record_flow(f)
        feats = agg.get_destination_features("5.5.5.5", 1_700_000_000.0 + 20)
        conc = feats.get("dst_src_concentration_60s")
        if conc is not None:
            assert conc < 0.5  # low concentration for many sources

    def test_unknown_ip_returns_empty(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        feats = agg.get_source_features("1.2.3.4", 1_700_000_000.0)
        assert feats == {}

    def test_tracked_sources_count(self):
        from src.features.behavioral_features import BehavioralAggregator
        agg = BehavioralAggregator(window_sizes=[60.0])
        for i in range(5):
            f = _make_flow(src=f"10.0.0.{i}", dst="1.1.1.1")
            agg.record_flow(f)
        assert agg.tracked_sources == 5


# ================================================================
# 9. Feature Pipeline (end-to-end)
# ================================================================

class TestFeaturePipeline:

    def test_extract_produces_feature_vector(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=5)
        fv = pipeline.extract(flow)
        assert fv is not None
        assert fv.flow_id == flow.flow_id

    def test_flow_group_always_present(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=5)
        fv = pipeline.extract(flow)
        assert "flow" in fv.feature_groups

    def test_timing_group_present_for_multi_packet(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=5)
        fv = pipeline.extract(flow)
        assert "timing" in fv.feature_groups

    def test_dns_group_present_when_dns_event_provided(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=3)
        dns_ev = _make_dns_event("google.com")
        fv = pipeline.extract(flow, dns_event=dns_ev)
        assert "dns" in fv.feature_groups

    def test_tls_group_present_when_tls_event_provided(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=3)
        tls_ev = _make_tls_event()
        fv = pipeline.extract(flow, tls_event=tls_ev)
        assert "tls" in fv.feature_groups

    def test_dns_group_absent_when_no_dns(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=3)
        fv = pipeline.extract(flow)
        assert "dns" not in fv.feature_groups

    def test_extract_stream_yields_all(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flows = [_make_flow(n_packets=3, base_ts=1_700_000_000.0 + i * 100)
                 for i in range(5)]
        fvs = list(pipeline.extract_stream(iter(flows)))
        assert len(fvs) == 5

    def test_vectors_produced_counter(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        for i in range(3):
            pipeline.extract(_make_flow())
        assert pipeline.vectors_produced == 3

    def test_no_infinities_in_normal_flow(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=10, iat=0.1)
        fv = pipeline.extract(flow)
        bad = fv.validate_no_infinities()
        assert bad == []

    def test_end_to_end_with_synthetic_pcap(self, tmp_path):
        """Full pipeline: PCAP -> events -> flows -> features."""
        import warnings
        warnings.filterwarnings("ignore")

        pcap = tmp_path / "test.pcap"
        from src.ingestion.test_pcap_generator import generate
        generate(output_path=pcap)

        from src.ingestion.pcap_reader import PcapReader
        from src.flows.flow_manager import FlowManager
        from src.flows.sessionizer import Sessionizer
        from src.features.feature_pipeline import FeaturePipeline

        reader = PcapReader(pcap)
        manager = FlowManager(timeout_seconds=60.0)
        sess = Sessionizer(manager)
        pipeline = FeaturePipeline(window_sizes=[60.0])

        fvs = []
        for flow in sess.process(reader.stream()):
            fv = pipeline.extract(flow)
            fvs.append(fv)

        assert len(fvs) >= 1
        # Every vector must have at least the flow group
        for fv in fvs:
            assert "flow" in fv.feature_groups
            assert fv.get("packet_count") is not None
            assert fv.get("packet_count") >= 1

    def test_summary_returns_dict(self):
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        s = pipeline.summary()
        assert isinstance(s, dict)
        assert "vectors_produced" in s


# ================================================================
# 10. Edge cases and validation
# ================================================================

class TestEdgeCases:

    def test_single_packet_flow_no_crash(self):
        """Single-packet flow must produce a valid FeatureVector."""
        from src.features.feature_pipeline import FeaturePipeline
        pipeline = FeaturePipeline(window_sizes=[60.0])
        flow = _make_flow(n_packets=1)
        fv = pipeline.extract(flow)
        assert fv is not None
        assert fv.get("packet_count") == 1

    def test_zero_byte_flow_no_crash(self):
        from src.features.feature_pipeline import FeaturePipeline
        from src.flows.flow import FlowRecord
        from src.ingestion.models import NetworkEvent
        pipeline = FeaturePipeline(window_sizes=[60.0])
        e = NetworkEvent(timestamp=1_700_000_000.0, source_ip="1.1.1.1",
                         destination_ip="2.2.2.2", source_port=1000,
                         destination_port=80, protocol=6,
                         packet_length=0)  # zero length
        flow = FlowRecord.from_event(e)
        fv = pipeline.extract(flow)
        assert fv is not None

    def test_empty_iat_list_timing_features_all_none(self):
        from src.features.timing_features import extract_timing_features
        from src.features.feature_vector import FeatureVector
        from src.flows.flow import FlowRecord
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0, source_ip="1.1.1.1",
                         destination_ip="2.2.2.2", source_port=1000,
                         destination_port=80, protocol=6, packet_length=100)
        flow = FlowRecord.from_event(e)
        fv = FeatureVector()
        extract_timing_features(flow, fv)
        assert fv.get("iat_mean") is None

    def test_empty_dns_info_no_crash(self):
        from src.features.dns_features import extract_dns_features
        from src.features.feature_vector import FeatureVector
        from src.ingestion.models import DNSInfo
        fv = FeatureVector()
        extract_dns_features(DNSInfo(), fv)  # all None fields
        assert fv.get("dns_is_nxdomain") == 0

    def test_malformed_timestamp_in_flow(self):
        """Flows with unusual timestamps should not crash the pipeline."""
        from src.features.feature_pipeline import FeaturePipeline
        from src.flows.flow import FlowRecord
        from src.ingestion.models import NetworkEvent
        pipeline = FeaturePipeline(window_sizes=[60.0])
        e = NetworkEvent(timestamp=0.0, source_ip="1.1.1.1",
                         destination_ip="2.2.2.2", source_port=1,
                         destination_port=1, protocol=6, packet_length=100)
        flow = FlowRecord.from_event(e)
        fv = pipeline.extract(flow)
        assert fv is not None
