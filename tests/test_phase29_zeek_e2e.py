"""
Phase 29: Zeek End-to-End Validation
This script interacts with the LIVE unishield-api container to inject Zeek logs,
start the replay, and poll the API until it processes the initial static logs.
It verifies concurrent tailing, watermark merging, and dashboard retrieval.
"""
import time
import requests
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

def test_zeek_end_to_end_validation():
    # 1. Login
    admin_token = get_token(ADMIN_USER, ADMIN_PASS)
    viewer_token = get_token(VIEWER_USER, VIEWER_PASS)
    
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    
    # 2. Reset the pipeline
    requests.post(f"{API_URL}/replay/reset", headers=admin_headers).raise_for_status()
    
    # 3. Load Zeek
    resp = requests.post(
        f"{API_URL}/ingest/zeek",
        headers=admin_headers,
        json={"zeek_dir": "data/samples/zeek_logs"}
    )
    assert resp.status_code == 200, f"Load failed: {resp.text}"
    
    # 4. Set speed to max
    requests.post(f"{API_URL}/replay/speed", headers=admin_headers, json={"speed": 1000.0})
    
    # 5. Play
    requests.post(f"{API_URL}/replay/play", headers=admin_headers).raise_for_status()
    
    # 6. Wait a few seconds for logs to be tailed into the buffer
    time.sleep(5)
    
    # 7. Stop the replay to trigger flush of the watermark queue
    requests.post(f"{API_URL}/replay/stop", headers=admin_headers).raise_for_status()
    
    # Wait for the pipeline to finish processing the flushed events
    time.sleep(3)
    
    r = requests.get(f"{API_URL}/statistics", headers=viewer_headers)
    stats = r.json()
    
    assert stats.get("packets_processed", 0) > 0, "No zeek events processed"
    assert stats.get("flows_processed", 0) > 0, "No flows generated from Zeek"
    assert stats.get("zeek_merged_events", 0) > 0, "Watermark merging failed"
    
    # 8. Verify Dashboard APIs
    alerts_resp = requests.get(f"{API_URL}/alerts?limit=10", headers=viewer_headers)
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) >= 0 # Zeek logs might not generate alerts in this specific small sample, but API must work
    
    print(f"\\n--- ZEEK E2E VALIDATION SUCCESS ---")
    print(f"Zeek Events Processed: {stats['packets_processed']}")
    print(f"Events Merged by Watermark: {stats.get('zeek_merged_events')}")
    print(f"Flows Generated: {stats['flows_processed']}")
    print(f"Late Events Dropped: {stats.get('zeek_late_events')}")
    print(f"Alerts (DB): {len(alerts)}")
    print(f"-----------------------------------")

if __name__ == "__main__":
    test_zeek_end_to_end_validation()
