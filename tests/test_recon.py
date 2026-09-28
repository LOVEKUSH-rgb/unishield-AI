"""
Tests for Reconnaissance Detector (Phase 7).
"""

import pytest
from src.features.feature_vector import FeatureVector
from src.detectors.recon import ReconDetector


@pytest.fixture
def detector():
    return ReconDetector({
        "min_connections": 20,
        "horizontal": {"min_hosts": 20, "max_ports": 5},
        "vertical": {"min_ports": 20, "max_hosts": 2},
        "host_sweep": {"min_host_port_pairs": 30},
        "network_sweep": {"min_subnets": 5},
        "min_score_to_alert": 0.40,
        "min_confidence_to_alert": 0.50,
        "syn_ratio_high": 0.80
    })


def _create_fv(conn=0, hosts=0, ports=0, subnets=0, pairs=0, syn_ratio=0.0):
    fv = FeatureVector(flow_id="f1", source_ip="10.0.0.1", destination_ip="1.1.1.1")
    # Populate the 60s window for testing
    fv.update("behavioral", {
        "src_conn_count_60s": conn,
        "src_uniq_dst_hosts_60s": hosts,
        "src_uniq_dst_ports_60s": ports,
        "src_uniq_dst_subnets_60s": subnets,
        "src_uniq_host_port_pairs_60s": pairs,
    })
    fv.update("flow", {
        "tcp_syn_ratio": syn_ratio
    })
    return fv


def test_normal_traffic(detector):
    # E.g., talking to DNS, HTTPS on 3 hosts, using 5 connections total
    fv = _create_fv(conn=5, hosts=3, ports=2, subnets=1, pairs=3, syn_ratio=0.1)
    res = detector.detect(fv)
    assert res.is_suppressed
    assert res.sub_type is None


def test_vertical_scan(detector):
    # 1 host, 50 ports, 50 connections
    fv = _create_fv(conn=50, hosts=1, ports=50, subnets=1, pairs=50, syn_ratio=0.9)
    res = detector.detect(fv)
    assert not res.is_suppressed
    assert res.sub_type == "VERTICAL_SCAN"
    assert res.confidence >= 0.70
    assert any("VERTICAL_SCAN" in str(res.evidence) or "distinct ports on a small number" in str(e.reason) for e in res.evidence)


def test_horizontal_scan(detector):
    # 50 hosts, 1 port (e.g. 22), 50 connections
    fv = _create_fv(conn=50, hosts=50, ports=1, subnets=1, pairs=50, syn_ratio=0.5)
    res = detector.detect(fv)
    assert not res.is_suppressed
    assert res.sub_type == "HORIZONTAL_SCAN"


def test_network_sweep(detector):
    # 10 hosts across 10 subnets, 1 port, 20 connections
    fv = _create_fv(conn=20, hosts=10, ports=1, subnets=10, pairs=10, syn_ratio=0.9)
    res = detector.detect(fv)
    assert not res.is_suppressed
    assert res.sub_type == "NETWORK_SWEEP"


def test_host_sweep(detector):
    # 10 hosts, 10 ports, but they are distributed across many pairs (e.g., full host sweep)
    fv = _create_fv(conn=100, hosts=10, ports=10, subnets=2, pairs=40, syn_ratio=0.85)
    res = detector.detect(fv)
    assert not res.is_suppressed
    assert res.sub_type == "HOST_SWEEP"


def test_syn_recon(detector):
    # Normal host/port fanout but extremely high SYN count and volume
    fv = _create_fv(conn=100, hosts=3, ports=3, subnets=1, pairs=3, syn_ratio=1.0)
    res = detector.detect(fv)
    assert not res.is_suppressed
    assert res.sub_type == "SYN_RECON"


def test_below_threshold(detector):
    # 15 connections, 15 hosts, 1 port (close but < 20)
    fv = _create_fv(conn=15, hosts=15, ports=1, subnets=1, pairs=15, syn_ratio=1.0)
    res = detector.detect(fv)
    assert res.is_suppressed


def test_slow_scan(detector):
    # Imagine a flow where 10s is normal, but 60s crosses threshold.
    # We simulate this by only putting high values in the 60s window.
    fv = FeatureVector(flow_id="f1", source_ip="10.0.0.1", destination_ip="1.1.1.1")
    fv.update("behavioral", {
        "src_conn_count_10s": 2,
        "src_uniq_dst_hosts_10s": 2,
        "src_uniq_dst_ports_10s": 1,
        
        "src_conn_count_60s": 25,
        "src_uniq_dst_hosts_60s": 25,
        "src_uniq_dst_ports_60s": 1,
        "src_uniq_dst_subnets_60s": 1,
        "src_uniq_host_port_pairs_60s": 25,
    })
    fv.update("flow", {"tcp_syn_ratio": 1.0})
    
    res = detector.detect(fv)
    assert not res.is_suppressed
    assert res.sub_type == "HORIZONTAL_SCAN"
