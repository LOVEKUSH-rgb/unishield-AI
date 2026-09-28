import requests
import time
import sys

API_URL = "http://127.0.0.1:8000"
PCAP_PATH = "data/samples/demo_scenario.pcap"

def wait_for_api(timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{API_URL}/health", timeout=1)
            if r.status_code == 200:
                print("API is ready!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return False

if __name__ == "__main__":
    print("Waiting for UniShield API to become available...")
    if not wait_for_api():
        print("Error: API did not start in time!")
        sys.exit(1)
        
    print(f"Loading PCAP: {PCAP_PATH}")
    
    print("Authenticating as admin...")
    auth_response = requests.post(f"{API_URL}/token", data={"username": "admin", "password": "changeme"})
    if auth_response.status_code != 200:
        print("Failed to authenticate!", auth_response.text)
        sys.exit(1)
        
    token = auth_response.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    
    r_load = requests.post(f"{API_URL}/replay/load", json={"pcap_path": PCAP_PATH}, headers=headers)
    print("Load Response:", r_load.text)
    
    print("Setting Replay Speed...")
    r_speed = requests.post(f"{API_URL}/replay/speed", json={"speed": 100.0}, headers=headers)
    print("Speed Response:", r_speed.text)
    
    print("Triggering Replay Playback...")
    r_play = requests.post(f"{API_URL}/replay/play", headers=headers)
    print("Play Response:", r_play.text)
    
    print("Playback triggered successfully!")
