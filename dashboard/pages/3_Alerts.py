import streamlit as st
from dashboard.api_client import API_URL, api_get, api_post
import pandas as pd
import os

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="Alert Explorer", page_icon="📡", layout="wide")
from dashboard.components.theme import inject_darktrace_theme
inject_darktrace_theme()
st.title("📡 Alert Explorer")

# --- Filters ---
with st.expander("🔍 Search & Filters", expanded=True):
    f1, f2, f3, f4 = st.columns(4)
    with f1: limit = st.number_input("Limit", min_value=10, max_value=1000, value=100)
    with f2: source_ip = st.text_input("Source IP")
    with f3: severity = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with f4: threat_class = st.selectbox("Threat Class", ["ALL", "DDoS", "C2 Beacon", "DGA DNS", "Encrypted Malware", "Reconnaissance", "Exfiltration"])

def fetch_alerts(limit, source_ip, severity, threat_class):
    params = {"limit": limit}
    if source_ip: params["source_ip"] = source_ip
    if severity and severity != "ALL": params["severity"] = severity
    if threat_class and threat_class != "ALL": params["threat_class"] = threat_class
    
    try:
        res = api_get("/alerts", params=params, timeout=5)
        return res.json() if res.status_code == 200 else []
    except:
        return []

alerts = fetch_alerts(limit, source_ip, severity, threat_class)

if not alerts:
    st.info("No alerts found matching the criteria.")
else:
    df_data = []
    for a in alerts:
        df_data.append({
            "Timestamp": a.get("timestamp", "").replace("T", " ")[:19],
            "Severity": a.get("severity"),
            "Threat": a.get("threat_class"),
            "Detector": a.get("detector"),
            "Confidence": f"{a.get('confidence', 0):.2f}",
            "Source IP": a.get("source_ip"),
            "Dest IP": a.get("destination_ip", ""),
            "Protocol": a.get("protocol", ""),
            "ML": "✅" if a.get("ml_available") else "❌"
        })
        
    df = pd.DataFrame(df_data)
    
    def color_severity(val):
        color = "white"
        if val == "CRITICAL": color = "#f85149"
        elif val == "HIGH": color = "#ff7b72"
        elif val == "MEDIUM": color = "#d2a8ff"
        elif val == "LOW": color = "#3fb950"
        return f'color: {color}; font-weight: bold;'

    st.write(f"Showing {len(alerts)} alerts")
    st.dataframe(
        df.style.map(color_severity, subset=["Severity"]),
        use_container_width=True,
        hide_index=True
    )

if st.session_state.get("live_mode"):
    import time
    time.sleep(5)
    st.rerun()
