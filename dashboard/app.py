"""
UniShield AI -- SOC Dashboard Entrypoint (Phase 20)
===================================================
Main entrypoint for the Streamlit multipage application.
Sets up global configuration, theming, and sidebar state.
"""

import streamlit as st
import requests
import os
from dashboard.api_client import API_URL, api_post, api_get

st.set_page_config(
    page_title="UniShield AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
from dashboard.components.theme import inject_darktrace_theme
inject_darktrace_theme()

# Custom CSS for Global Theming
st.markdown("""
<style>
/* Dark SOC Theme */
:root {
    --bg-color: #0e1117;
    --text-color: #c9d1d9;
    --primary-color: #58a6ff;
    --critical-color: #f85149;
    --high-color: #ff7b72;
    --medium-color: #d2a8ff;
    --low-color: #3fb950;
    --border-color: #30363d;
}
.stApp {
    background-color: var(--bg-color);
    color: var(--text-color);
}
.metric-card {
    background-color: #161b22;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 15px;
    text-align: left;
    margin-bottom: 10px;
}
.metric-value {
    font-size: 2rem;
    font-weight: bold;
    color: white;
}
.metric-label {
    font-size: 0.9rem;
    color: #8b949e;
    text-transform: uppercase;
}
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if "live_mode" not in st.session_state:
    st.session_state.live_mode = False

if "token" not in st.session_state:
    st.title("🛡️ UniShield AI SOC - Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        if submit:
            try:
                resp = requests.post(f"{API_URL}/token", data={"username": username, "password": password}, timeout=2)
                if resp.status_code == 200:
                    st.session_state.token = resp.json().get("access_token")
                    st.rerun()
                else:
                    st.error("Invalid credentials or inactive user.")
            except Exception as e:
                st.error(f"Failed to connect to API: {e}")
    st.stop()

# --- SIDEBAR ---
st.sidebar.title("🛡️ UniShield AI")
if st.sidebar.button("Logout"):
    del st.session_state["token"]
    st.rerun()
    
st.sidebar.markdown("---")

st.sidebar.subheader("Live / Replay Controls")
col1, col2 = st.sidebar.columns(2)
try:
    if col1.button("▶️ Play", use_container_width=True):
        api_post("/replay/play", timeout=2)
    if col2.button("⏸️ Pause", use_container_width=True):
        api_post("/replay/pause", timeout=2)

    col3, col4 = st.sidebar.columns(2)
    if col3.button("⏹️ Stop", use_container_width=True):
        api_post("/replay/stop", timeout=2)
    if col4.button("🔄 Reset", use_container_width=True):
        api_post("/replay/reset", timeout=2)

    speed = st.sidebar.select_slider(
        "Replay Speed",
        options=[0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
        value=1.0
    )
    api_post("/replay/speed", json={"speed": speed}, timeout=2)
except Exception:
    st.sidebar.error("Failed to connect to backend.")

st.sidebar.markdown("---")
st.session_state.live_mode = st.sidebar.checkbox("Live Sync (Auto-Refresh)", value=st.session_state.live_mode)

st.sidebar.markdown("---")
st.sidebar.markdown("### Passive Architecture")
st.sidebar.success("READ-ONLY INGEST ✓")
st.sidebar.info("ACTIVE PROBING: DISABLED")

# Landing Page content
st.title("UniShield AI Security Operations Center")
st.markdown("""
Welcome to the UniShield AI SOC Console. 

Please navigate using the sidebar:
- **1 Overview**: High-level security posture and KPIs.
- **2 Incidents**: Prioritize and investigate active security incidents.
- **3 Alerts**: Explore raw detection alerts with filtering.
- **4 Analytics**: Analyze threat distributions and detector performance.
- **5 System Health**: Monitor ingestion and pipeline latency.
""")

if st.session_state.live_mode:
    import time
    time.sleep(5)
    st.rerun()
