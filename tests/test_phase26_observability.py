import pytest
from fastapi.testclient import TestClient
import json
from src.api.app import app
from src.ingestion.models import NetworkEvent
from src.flows.flow import FlowRecord

client = TestClient(app)

def test_prometheus_metrics_endpoint():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    # Verify that python gc or prometheus standard metrics are exported
    assert "python_gc_objects_collected_total" in response.text or "python_info" in response.text or "unishield" in response.text
    
def test_correlation_id_propagation():
    # 1. Generate an event without a correlation ID (it should autogenerate)
    event1 = NetworkEvent(
        timestamp=1000.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=10000,
        destination_port=80,
        protocol=6,
        packet_length=100
    )
    assert event1.correlation_id is not None
    assert len(event1.correlation_id) > 10
    
    # 2. Provide a manual correlation ID
    manual_id = "test-corr-id-123"
    event2 = NetworkEvent(
        timestamp=1001.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=10000,
        destination_port=80,
        protocol=6,
        packet_length=100,
        correlation_id=manual_id
    )
    assert event2.correlation_id == manual_id
    
    # 3. Verify it flows into the FlowRecord
    flow = FlowRecord.from_event(event2)
    assert flow.correlation_id == manual_id
    
def test_health_endpoints():
    response_live = client.get("/health/live")
    assert response_live.status_code == 200
    assert response_live.json()["status"] == "healthy"
    
    response_ready = client.get("/health/ready")
    # Depending on the test environment, redis/db might be unhealthy.
    # We just ensure it returns JSON with a status key.
    data = response_ready.json()
    assert "status" in data
    assert "postgres" in data
    assert "redis" in data
