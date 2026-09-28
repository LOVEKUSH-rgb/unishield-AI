"""
Phase 29: PCAP End-to-End Validation
This script interacts with the LIVE unishield-api container to inject a PCAP,
start the replay, and poll the API until it finishes. Then it verifies that
alerts and incidents were persisted properly.
"""
import time
import requests
import pytest
import os

API_URL = os.environ.get("API_URL", "http://localhost:8000")
ADMIN_USER = "admin"
ADMIN_PASS = "changeme"
VIEWER_USER = "viewer"
VIEWER_PASS = "changeme"

def get_token(username, password):
    resp = requests.post(f"{API_URL}/token", data={"username": username, "password": password})
    resp.raise_for_status()
    return resp.json()["access_token"]

def test_pcap_end_to_end_validation():
    # 1. Login
    admin_token = get_token(ADMIN_USER, ADMIN_PASS)
    viewer_token = get_token(VIEWER_USER, VIEWER_PASS)
    
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    
    # 2. Reset the pipeline
    resp = requests.post(f"{API_URL}/replay/reset", headers=admin_headers)
    resp.raise_for_status()
    
    # 3. Load the PCAP
    resp = requests.post(
        f"{API_URL}/replay/load",
        headers=admin_headers,
        json={"pcap_path": "data/samples/demo_six_threats.pcap"}
    )
    assert resp.status_code == 200, f"Load failed: {resp.text}"
    
    # 4. Set speed to max
    requests.post(f"{API_URL}/replay/speed", headers=admin_headers, json={"speed": 1000.0})
    
    # 5. Play
    resp = requests.post(f"{API_URL}/replay/play", headers=admin_headers)
    resp.raise_for_status()
    
    # 6. Poll for completion
    timeout = 60
    start = time.time()
    completed = False
    stats = {}
    
    while time.time() - start < timeout:
        time.sleep(2)
        r = requests.get(f"{API_URL}/statistics", headers=viewer_headers)
        if r.status_code == 200:
            stats = r.json()
            if stats.get("status") == "STOPPED" and stats.get("packets_processed", 0) > 0:
                completed = True
                break
                
    assert completed, "Replay did not complete within the timeout"
    
    # 7. Verify Ingestion & Flow parsing
    assert stats.get("packets_processed", 0) > 0, "No packets processed"
    assert stats.get("flows_processed", 0) > 0, "No flows generated"
    assert stats.get("alerts_generated", 0) > 0, "No alerts generated"
    
    # 8. Verify Threat Counters (Statistical & ML fallback execution)
    threats_resp = requests.get(f"{API_URL}/threats", headers=viewer_headers)
    assert threats_resp.status_code == 200
    threat_counts = threats_resp.json()
    assert sum(threat_counts.values()) > 0, "Threat counts are zero"
    
    # 9. Verify Dashboard APIs (Database Persistence)
    alerts_resp = requests.get(f"{API_URL}/alerts?limit=10", headers=viewer_headers)
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) > 0, "No alerts persisted to database"
    
    incidents_resp = requests.get(f"{API_URL}/incidents?limit=10", headers=viewer_headers)
    assert incidents_resp.status_code == 200
    incidents = incidents_resp.json()
    assert len(incidents) > 0, "No incidents persisted to database"
    
    analytics_resp = requests.get(f"{API_URL}/analytics/detectors", headers=viewer_headers)
    assert analytics_resp.status_code == 200
    analytics = analytics_resp.json()
    assert len(analytics) > 0, "No detector analytics"
    
    print(f"\\n--- E2E VALIDATION SUCCESS ---")
    print(f"Packets: {stats['packets_processed']}")
    print(f"Flows: {stats['flows_processed']}")
    print(f"Alerts (Redis): {stats['alerts_generated']}")
    print(f"Alerts (DB): {len(alerts)}")
    print(f"Incidents (DB): {len(incidents)}")
    print(f"------------------------------")

if __name__ == "__main__":
    test_pcap_end_to_end_validation()
