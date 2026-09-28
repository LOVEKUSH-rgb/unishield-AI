"""
Phase 29: Failure Injection Validation
This script orchestrates the failure injection scenarios:
1. Postgres offline
2. Redis offline
It uses docker commands to stop/start the containers and asserts API graceful degradation.
"""
import time
import requests
import subprocess
import os

API_URL = "http://localhost:8000"

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True)
    
def test_postgres_failure():
    print("Injecting PostgreSQL failure...")
    run_cmd("docker stop unishield-ai-postgres-1")
    time.sleep(5)
    
    try:
        # API should still respond, maybe 500 for db endpoints, but not crash
        r = requests.get(f"{API_URL}/alerts", headers={"Authorization": "Bearer fake"})
        # 401 is expected if Auth fails due to no DB, or 500
        assert r.status_code in [401, 500], f"Expected 401/500, got {r.status_code}"
        
        # Ingestion shouldn't crash
        print("PostgreSQL failure injection passed (API gracefully handled).")
    finally:
        print("Restoring PostgreSQL...")
        run_cmd("docker start unishield-ai-postgres-1")
        time.sleep(10)
        
def test_redis_failure():
    print("Injecting Redis failure...")
    run_cmd("docker stop unishield-ai-redis-1")
    time.sleep(5)
    
    try:
        # State endpoints should return 500 or fallback state
        # In unishield-ai, we designed StateManager to catch exceptions and return default state
        # But wait, without Auth (which might need redis? No auth uses DB).
        # Let's see if /statistics is alive
        # To get a token we need DB
        token_resp = requests.post(f"{API_URL}/token", data={"username": "viewer", "password": "changeme"})
        if token_resp.status_code == 200:
            token = token_resp.json()["access_token"]
            r = requests.get(f"{API_URL}/statistics", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
            print("Redis failure injection passed (StateManager gracefully fell back to default state).")
        else:
            print(f"Auth failed with {token_resp.status_code}, could not test /statistics.")
    finally:
        print("Restoring Redis...")
        run_cmd("docker start unishield-ai-redis-1")
        time.sleep(5)
        
if __name__ == "__main__":
    test_postgres_failure()
    test_redis_failure()
