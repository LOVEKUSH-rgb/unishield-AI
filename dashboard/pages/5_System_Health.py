import streamlit as st
from dashboard.api_client import API_URL, api_get, api_post
import os

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="System Health", page_icon="⚙️", layout="wide")
from dashboard.components.theme import inject_darktrace_theme
inject_darktrace_theme()
st.title("⚙️ System Health & Ingestion")

def fetch_health():
    try:
        health = api_get("/health/ready", timeout=2).json()
        metrics = api_get("/statistics", timeout=2).json()
        return health, metrics
    except:
        return None, None

health, metrics = fetch_health()

if health is None and metrics is None:
    st.error("Backend unavailable. Cannot retrieve system health.")
    st.stop()

col1, col2 = st.columns(2)

with col1:
    st.subheader("Component Status")
    
    def status_box(name, status_str):
        color = "#3fb950" if status_str.lower() == "healthy" else "#f85149"
        st.markdown(f"""
        <div style="background-color: #161b22; padding: 15px; border-radius: 5px; border: 1px solid #30363d; margin-bottom: 10px; display: flex; justify-content: space-between;">
            <strong style="color: white;">{name}</strong>
            <span style="color: {color}; font-weight: bold;">{status_str.upper()}</span>
        </div>
        """, unsafe_allow_html=True)
        
    status_box("FastAPI Backend", health.get("api", "UNAVAILABLE") if health else "UNAVAILABLE")
    status_box("PostgreSQL Database", health.get("postgres", "UNAVAILABLE") if health else "UNAVAILABLE")
    status_box("Redis Cache", health.get("redis", "UNAVAILABLE") if health else "UNAVAILABLE")
    
with col2:
    st.subheader("Ingestion & Pipeline Metrics")
    
    if metrics:
        mode = metrics.get("ingestion_mode", "pcap").upper()
        status = metrics.get("status", "UNKNOWN")
        
        st.markdown(f"**Ingestion Mode:** `{mode}`")
        st.markdown(f"**Replay Status:** `{status}`")
        
        if mode == "PCAP":
            st.markdown(f"**Current File:** `{metrics.get('current_pcap', 'None')}`")
            st.markdown(f"**Replay Speed:** `{metrics.get('replay_speed', 1.0)}x`")
        elif mode == "ZEEK":
            st.markdown(f"**Log Directory:** `{metrics.get('current_zeek_dir', 'None')}`")
            
        st.markdown("---")
        st.markdown("#### Pipeline Throughput")
        flows = metrics.get("flows_processed", 0)
        packets = metrics.get("packets_processed", 0)
        st.write(f"- **Events Parsed:** {packets:,}")
        st.write(f"- **Flows Constructed:** {flows:,}")
        
        zeek_q = metrics.get("zeek_queue_depth")
        if zeek_q is not None:
            st.write(f"- **Zeek Ingestion Queue Depth:** {zeek_q}")
            st.write(f"- **Zeek Merged Events:** {metrics.get('zeek_merged_events', 0)}")
            st.write(f"- **Zeek Dropped (Late):** {metrics.get('zeek_late_events', 0)}")
        
        latency = metrics.get("detection_latency_ms")
        if latency is not None:
            st.markdown(f"#### Pipeline Latency")
            st.write(f"- **Avg Detection Latency:** {latency:.2f} ms")
    else:
        st.info("No metrics available.")

st.markdown("---")
st.subheader("🧠 Machine Learning Model Registry")

def fetch_models():
    try:
        return api_get("/models", timeout=2).json()
    except:
        return None

models = fetch_models()

if models is None:
    st.warning("Could not retrieve model registry status.")
elif "error" in models:
    st.error(f"Error reading model registry: {models['error']}")
elif not models:
    st.info("No ML models currently loaded in the registry. Detectors are running in STATISTICAL fallback mode.")
else:
    cols = st.columns(len(models))
    for i, (model_name, model_info) in enumerate(models.items()):
        with cols[i % len(cols)]:
            status = model_info.get("status", "NOT_AVAILABLE")
            
            icon = "⚪"
            if status == "LOADED": icon = "🟢"
            elif status == "CANDIDATE": icon = "🟡"
            elif status == "INVALID": icon = "🔴"
            elif status == "STATISTICAL_FALLBACK": icon = "🔵"
            
            st.markdown(f"**{model_name.upper()}**")
            st.markdown(f"- **Status:** {icon} {status}")
            st.markdown(f"- **Version:** `{model_info.get('active_version', 'None')}`")
            st.markdown(f"- **Integrity:** `{model_info.get('integrity', 'UNKNOWN')}`")
            st.markdown(f"- **Schema:** `{model_info.get('schema_version', 'Unknown')}`")
            
            if status != "LOADED":
                st.markdown("- **Fallback:** 🔵 STATISTICAL_FALLBACK ACTIVE")

if st.session_state.get("live_mode"):
    import time
    time.sleep(5)
    st.rerun()
