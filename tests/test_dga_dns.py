"""
Tests for DGA and DNS Tunnelling detectors.
"""

import math
import pytest
from src.features.feature_vector import FeatureVector
from src.detectors.dns_tracker import DNSTracker, DNSQueryRecord
from src.detectors.dga_dns import DGADetector, DNSTunnelDetector, LexicalEntropySub
from src.features.dns_features import extract_dns_features

# We'll mock the DNSInfo for feature extraction test.
class MockDNSInfo:
    def __init__(self, query_name, is_query=True, query_type="A"):
        self.query_name = query_name
        self.is_query = is_query
        self.query_type = query_type
        self.answer_count = 0
        self.response_code = "NOERROR"


def create_dns_fv(query_name, query_type="A", src_ip="192.168.1.100", start_time=100.0):
    fv = FeatureVector(flow_id="f1", source_ip=src_ip, destination_ip="1.1.1.1")
    fv.features["start_time"] = start_time
    dns = MockDNSInfo(query_name=query_name, query_type=query_type)
    extract_dns_features(dns, fv)
    return fv


class TestDNSTracker:
    def test_tracker_adds_records(self):
        tracker = DNSTracker({"tracking_window_seconds": 300.0})
        for i in range(10):
            fv = create_dns_fv(f"sub{i}.example.com", start_time=100.0 + i)
            tracker.record_from_fv(fv)
            
        feat = tracker.get_features("192.168.1.100")
        assert feat.query_count == 10
        assert feat.unique_query_count == 10
        assert feat.duration == 9.0
        assert feat.query_rate == 10 / 9.0
        
    def test_tracker_evicts_old_records(self):
        tracker = DNSTracker({"tracking_window_seconds": 10.0})
        tracker.record_from_fv(create_dns_fv("a.com", start_time=100.0))
        tracker.record_from_fv(create_dns_fv("b.com", start_time=105.0))
        tracker.record_from_fv(create_dns_fv("c.com", start_time=115.0))
        
        feat = tracker.get_features("192.168.1.100")
        assert feat.query_count == 2
        assert feat.duration == 10.0
        
    def test_tracker_txt_ratio(self):
        tracker = DNSTracker()
        tracker.record_from_fv(create_dns_fv("a.com", query_type="TXT"))
        tracker.record_from_fv(create_dns_fv("a.com", query_type="TXT"))
        tracker.record_from_fv(create_dns_fv("a.com", query_type="A"))
        
        feat = tracker.get_features("192.168.1.100")
        assert math.isclose(feat.txt_null_ratio, 2.0 / 3.0)


class TestDGADetector:
    @pytest.fixture
    def detector(self):
        return DGADetector({
            "entropy_high": 4.2,
            "entropy_moderate": 3.5,
            "ngram_entropy_high": 3.8,
            "ngram_entropy_moderate": 3.2,
            "length_suspicious": 35,
            "digit_ratio_high": 0.30,
            "unique_char_high": 25,
            "weights": {"lexical_entropy": 0.60, "structural_anomaly": 0.40},
            "min_score_to_alert": 0.30,
            "min_confidence_to_alert": 0.40,
            "ml": {"enabled": False}
        })
        
    def test_benign_domain(self, detector):
        fv = create_dns_fv("google.com")
        res = detector.detect(fv)
        assert res.is_suppressed
        assert res.detection_score < 0.30
        
    def test_dga_domain(self, detector):
        # A long domain with many unique chars and high entropy
        fv = create_dns_fv("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z.example.com")
        res = detector.detect(fv)
        assert not res.is_suppressed
        assert res.detection_score > 0.50
        assert res.confidence >= 0.40
        assert any(e.feature == "dns_query_length" for e in res.evidence)
        assert any(e.feature == "dns_entropy" for e in res.evidence)
        assert any(e.feature == "dns_digit_ratio" for e in res.evidence)


class TestDNSTunnellingDetector:
    @pytest.fixture
    def detector(self):
        tracker = DNSTracker({"tracking_window_seconds": 60.0})
        return DNSTunnelDetector(tracker, {
            "min_queries_for_analysis": 10,
            "query_rate_high": 5.0,
            "query_rate_moderate": 2.0,
            "avg_query_length_high": 50,
            "avg_entropy_high": 4.0,
            "unique_subdomain_ratio_high": 0.80,
            "txt_null_ratio_high": 0.50,
            "weights": {"volume": 0.25, "payload": 0.35, "churn": 0.25, "record_type": 0.15},
            "min_score_to_alert": 0.30,
            "min_confidence_to_alert": 0.40
        })
        
    def test_cold_start_suppression(self, detector):
        fv = create_dns_fv("example.com")
        res = detector.detect(fv)
        assert res.is_suppressed
        
    def test_benign_traffic(self, detector):
        for i in range(15):
            fv = create_dns_fv("google.com", start_time=100.0 + i*2)
            res = detector.detect(fv)
        
        assert res.is_suppressed
        
    def test_dns_tunnelling_traffic(self, detector):
        # High rate, long domains, high churn, TXT records
        for i in range(25):
            domain = f"{'a'*40}{i:03d}.tunnel.com"
            fv = create_dns_fv(domain, query_type="TXT", start_time=100.0 + (i*0.1))
            res = detector.detect(fv)
            
        assert not res.is_suppressed
        assert res.detection_score > 0.60
        assert res.confidence >= 0.50
        assert any(e.feature == "query_rate" for e in res.evidence)
        assert any(e.feature == "avg_query_length" for e in res.evidence)
        assert any(e.feature == "unique_subdomain_ratio" for e in res.evidence)
        assert any(e.feature == "txt_null_ratio" for e in res.evidence)
