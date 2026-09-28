import os
import yaml
import pytest
from src.ingestion.models import NetworkEvent
from src.flows.flow import FlowRecord
from src.persistence.models import AlertModel, IncidentModel

def test_prometheus_config_validity():
    prom_path = "monitoring/prometheus/prometheus.yml"
    assert os.path.exists(prom_path)
    with open(prom_path, "r") as f:
        data = yaml.safe_load(f)
        assert "scrape_configs" in data
        assert "global" in data

def test_prometheus_alerts_validity():
    alerts_path = "monitoring/prometheus/rules/unishield_alerts.yml"
    assert os.path.exists(alerts_path)
    with open(alerts_path, "r") as f:
        data = yaml.safe_load(f)
        assert "groups" in data
        
        # Verify specific alerts exist
        alerts = [rule["alert"] for group in data["groups"] for rule in group.get("rules", []) if "alert" in rule]
        assert "UniShieldAPIDown" in alerts
        assert "DatabaseErrorsDetected" in alerts

def test_grafana_provisioning_validity():
    ds_path = "monitoring/grafana/provisioning/datasources/prometheus.yaml"
    assert os.path.exists(ds_path)
    with open(ds_path, "r") as f:
        data = yaml.safe_load(f)
        assert data["datasources"][0]["type"] == "prometheus"
        
    db_path = "monitoring/grafana/provisioning/dashboards/dashboards.yaml"
    assert os.path.exists(db_path)
    with open(db_path, "r") as f:
        data = yaml.safe_load(f)
        assert data["providers"][0]["options"]["path"] == "/var/lib/grafana/dashboards"

def test_grafana_dashboards_exist():
    dashboards = [
        "unishield_overview.json",
        "unishield_ingestion.json",
        "unishield_detection.json",
        "unishield_reliability.json"
    ]
    for db in dashboards:
        assert os.path.exists(f"monitoring/grafana/dashboards/{db}")

def test_correlation_id_full_propagation():
    """
    Verify that a correlation ID can be followed across:
    NetworkEvent -> FlowRecord -> Detection -> Alert -> Incident
    """
    manual_corr_id = "e2e-propagation-12345"
    
    # 1. Ingestion produces NetworkEvent
    event = NetworkEvent(
        timestamp=1000.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=10000,
        destination_port=80,
        protocol=6,
        packet_length=100,
        correlation_id=manual_corr_id
    )
    assert event.correlation_id == manual_corr_id
    
    # 2. Flow Manager creates FlowRecord
    flow = FlowRecord.from_event(event)
    assert flow.correlation_id == manual_corr_id
    
    # 3. Detection generates Alert (mocked persistence model)
    alert = AlertModel(
        id="alert-1",
        timestamp=1000.0,
        detector="test_detector",
        flow_id="key",
        severity="HIGH",
        correlation_id=flow.correlation_id,
        threat_class="test_class"
    )
    assert alert.correlation_id == manual_corr_id
    
    # 4. Correlation generates Incident
    incident = IncidentModel(
        id="inc-1",
        status="NEW",
        risk_level="HIGH",
        correlation_id=alert.correlation_id
    )
    assert incident.correlation_id == manual_corr_id
