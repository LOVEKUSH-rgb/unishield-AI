import streamlit as st
from dashboard.api_client import API_URL, api_get, api_post
import pandas as pd
import altair as alt
import os

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="Threat Analytics", page_icon="📈", layout="wide")
from dashboard.components.theme import inject_darktrace_theme
inject_darktrace_theme()
st.title("🧠 Attack Signal Intelligence")
st.markdown("This dashboard maps network detections to the active phases of the attacker lifecycle using AI-driven behavioral analysis.")

def fetch_analytics():
    try:
        threats = api_get("/threats", timeout=5).json()
        stats = api_get("/analytics/detectors", timeout=5).json()
        alerts = api_get("/alerts?limit=500", timeout=5).json()
        return threats, stats, alerts
    except:
        return None, None, None

threats, stats, alerts = fetch_analytics()

if threats is None and stats is None:
    st.error("Backend unavailable.")
    st.stop()

# --- MITRE ATT&CK Lifecycle Mapping ---
st.markdown("---")
st.subheader("Attacker Lifecycle Progression")

lifecycle_mapping = {
    "Reconnaissance": ["RECON"],
    "Command & Control": ["C2_BEACON", "DNS_DGA", "ENCRYPTED_ANOMALY"],
    "Exfiltration": ["EXFILTRATION"],
    "Impact (DoS)": ["DDOS"]
}

phase_counts = {"Reconnaissance": 0, "Command & Control": 0, "Exfiltration": 0, "Impact (DoS)": 0}

if threats:
    for t_type, count in threats.items():
        for phase, mapped_types in lifecycle_mapping.items():
            if t_type.upper() in mapped_types:
                phase_counts[phase] += count

df_phases = pd.DataFrame(list(phase_counts.items()), columns=["Attack Phase", "Detections"])
phase_chart = alt.Chart(df_phases).mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
    x=alt.X("Attack Phase:N", sort=list(lifecycle_mapping.keys()), title=""),
    y=alt.Y("Detections:Q", title="Signal Volume"),
    color=alt.Color("Attack Phase:N", scale=alt.Scale(
        domain=list(lifecycle_mapping.keys()),
        range=["#8b949e", "#d2a8ff", "#ff7b72", "#f85149"]
    ), legend=None),
    tooltip=["Attack Phase", "Detections"]
).properties(height=250).interactive()

st.altair_chart(phase_chart, use_container_width=True)

# --- TEMPORAL TIMELINE ---
st.markdown("---")
st.subheader("Detection Timeline")
if alerts:
    df_alerts = pd.DataFrame(alerts)
    if "timestamp" in df_alerts.columns:
        df_alerts["timestamp"] = pd.to_datetime(df_alerts["timestamp"])
        df_alerts["Minute"] = df_alerts["timestamp"].dt.floor('Min')
        
        df_chart = df_alerts[["Minute", "severity"]].copy()
        
        timeline_chart = alt.Chart(df_chart).mark_area(opacity=0.6, interpolate='step').encode(
            x=alt.X("Minute:T", title="Time"),
            y=alt.Y("count():Q", title="Alert Volume"),
            color=alt.Color("severity:N", scale=alt.Scale(
                domain=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                range=["#f85149", "#ff7b72", "#d2a8ff", "#3fb950"]
            )),
            tooltip=["Minute:T", "count():Q", "severity:N"]
        ).properties(height=200).interactive()
        
        st.altair_chart(timeline_chart, use_container_width=True)
else:
    st.info("No timeline data available. Run live traffic to populate.")


# --- ML PIPELINE VISIBILITY ---
st.markdown("---")
st.subheader("AI Detection Pipeline Status")

if stats:
    df_stats = []
    for s in stats:
        df_stats.append({
            "Detector": s.get("detector").replace("Detector", "").upper(),
            "Alerts Generated": s.get("count"),
            "Avg Confidence": f"{s.get('avg_confidence', 0)*100:.1f}%",
            "Avg Latency (ms)": f"{s.get('avg_latency', 0):.1f} ms",
            "Pipeline Engine": "🤖 Deep Learning" if s.get("uses_ml") else "📊 Statistical"
        })
        
    df = pd.DataFrame(df_stats)
    
    # Render a stylized table
    st.markdown("""
    <style>
    .ml-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .ml-table th { text-align: left; padding: 8px; border-bottom: 2px solid rgba(0, 229, 255, 0.4); color: #00e5ff; text-transform: uppercase; font-size: 0.8rem; }
    .ml-table td { padding: 8px; border-bottom: 1px solid rgba(0, 229, 255, 0.1); color: #b0c4de; font-family: monospace; }
    .ml-table tr:hover td { background-color: rgba(0, 229, 255, 0.05); }
    </style>
    """, unsafe_allow_html=True)
    
    html_table = "<table class='ml-table'><tr>"
    for col in df.columns: html_table += f"<th>{col}</th>"
    html_table += "</tr>"
    
    for _, row in df.iterrows():
        html_table += "<tr>"
        for val in row: html_table += f"<td>{val}</td>"
        html_table += "</tr>"
    html_table += "</table>"
    
    st.markdown(html_table, unsafe_allow_html=True)
else:
    st.info("No detector stats available.")

if st.session_state.get("live_mode"):
    import time
    time.sleep(5)
    st.rerun()
