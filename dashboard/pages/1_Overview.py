import streamlit as st
from dashboard.api_client import API_URL, api_get, api_post
import pandas as pd
import altair as alt
import os

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="SOC Overview", page_icon="📊", layout="wide")
from dashboard.components.theme import inject_darktrace_theme
inject_darktrace_theme()

def fetch_overview_data():
    try:
        metrics = api_get("/statistics", timeout=2).json()
        incidents = api_get("/incidents?limit=100", timeout=2).json()
        alerts = api_get("/alerts?limit=50", timeout=2).json()
        threats = api_get("/threats", timeout=2).json()
        return metrics, incidents, alerts, threats
    except Exception as e:
        return None, None, None, str(e)

metrics, incidents, alerts, threats = fetch_overview_data()

if metrics is None:
    st.error(f"Backend unavailable — unable to retrieve overview data. Error: {threats}")
    st.stop()

# --- HEADER ---
status_color = "#4CAF50" if metrics.get("status") in ["PLAYING", "ONLINE"] else "#FF9800"
st.markdown(f"""
<div style='display: flex; justify-content: space-between; align-items: center; background-color: #161b22; padding: 15px 25px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 20px;'>
    <div>
        <h2 style='margin:0; padding:0;'>SOC Overview</h2>
    </div>
    <div style='text-align: right;'>
        <div style='font-size: 1.1rem; font-weight: bold;'>System status: <span style='color:{status_color};'>● {metrics.get('status', 'UNKNOWN')}</span></div>
    </div>
</div>
""", unsafe_allow_html=True)

# --- KPIs ---
k1, k2, k3, k4, k5 = st.columns(5)

active_incidents = len([i for i in (incidents or []) if i.get("status") in ["NEW", "INVESTIGATING"]])
critical_incidents = len([i for i in (incidents or []) if i.get("risk_level") == "CRITICAL"])
flows = metrics.get("flows_processed", 0)
alerts_generated = metrics.get("alerts_generated", 0)
latency = metrics.get("detection_latency_ms")

def render_kpi(col, label, value, color="white"):
    col.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color: {color};">{value}</div>
    </div>
    """, unsafe_allow_html=True)

render_kpi(k1, "Active Incidents", active_incidents if active_incidents else "0", color="#ff7b72" if active_incidents > 0 else "white")
render_kpi(k2, "Critical Incidents", critical_incidents if critical_incidents else "0", color="#f85149" if critical_incidents > 0 else "white")
render_kpi(k3, "Alerts Generated", f"{alerts_generated:,}" if alerts_generated else "0")
render_kpi(k4, "Flows Analyzed", f"{flows:,}" if flows else "0")
render_kpi(k5, "Avg Latency", f"{latency:.1f}ms" if latency is not None else "N/A")

st.markdown("---")

# --- VECTRA-INSPIRED HOST PRIORITIZATION (THREAT VS CERTAINTY) ---
st.markdown("---")
st.subheader("Host Prioritization (Attack Signal Intelligence)")

if alerts:
    # 1. Aggregate alerts into Host Entities
    host_profiles = {}
    for a in alerts:
        ip = a.get("source_ip", "Unknown")
        sev = a.get("severity", "LOW")
        score = a.get("score", 0.5)
        threat_class = a.get("threat_class", "UNKNOWN")
        
        if ip not in host_profiles:
            host_profiles[ip] = {"Threat": 0, "Certainty": 0, "AlertCount": 0, "Behaviors": set()}
            
        host_profiles[ip]["AlertCount"] += 1
        host_profiles[ip]["Behaviors"].add(threat_class)
        
        # Vectra-like heuristic: Severity increases Threat, frequency increases Certainty
        threat_bump = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(sev, 5)
        host_profiles[ip]["Threat"] = min(99, host_profiles[ip]["Threat"] + threat_bump)
        
        certainty_bump = score * 15 # Score is usually 0 to 1
        host_profiles[ip]["Certainty"] = min(99, host_profiles[ip]["Certainty"] + certainty_bump)

    # Convert to DataFrame
    data = []
    for ip, profile in host_profiles.items():
        data.append({
            "Host": ip,
            "Threat Score": profile["Threat"],
            "Certainty Score": profile["Certainty"],
            "Total Alerts": profile["AlertCount"],
            "Active Behaviors": ", ".join(profile["Behaviors"])
        })
    df_hosts = pd.DataFrame(data)

    col_quad, col_list = st.columns([3, 2])

    with col_quad:
        st.markdown("**Threat vs. Certainty Quadrant**")
        # Altair Scatterplot (Vectra AI style quadrant)
        quad_chart = alt.Chart(df_hosts).mark_circle(size=200, opacity=0.8).encode(
            x=alt.X("Certainty Score:Q", scale=alt.Scale(domain=[0, 100]), title="Certainty (Confidence)"),
            y=alt.Y("Threat Score:Q", scale=alt.Scale(domain=[0, 100]), title="Threat (Impact)"),
            color=alt.Color("Threat Score:Q", scale=alt.Scale(scheme="redyellowgreen", reverse=True), legend=None),
            tooltip=["Host", "Threat Score", "Certainty Score", "Active Behaviors"]
        ).properties(
            height=350
        ).interactive()
        
        # Add quadrant lines at 50/50
        hline = alt.Chart(pd.DataFrame({'y': [50]})).mark_rule(color='rgba(0, 229, 255, 0.3)', strokeDash=[5,5]).encode(y='y:Q')
        vline = alt.Chart(pd.DataFrame({'x': [50]})).mark_rule(color='rgba(0, 229, 255, 0.3)', strokeDash=[5,5]).encode(x='x:Q')
        
        st.altair_chart(quad_chart + hline + vline, use_container_width=True)

    with col_list:
        st.markdown("**Top Riskiest Entities**")
        df_sorted = df_hosts.sort_values(by=["Threat Score", "Certainty Score"], ascending=[False, False]).head(5)
        
        for _, row in df_sorted.iterrows():
            host = row["Host"]
            threat = row["Threat Score"]
            certainty = row["Certainty Score"]
            behaviors = row["Active Behaviors"]
            
            # Color coding based on quadrant
            if threat > 50 and certainty > 50:
                border_color = "#f85149" # High Threat, High Certainty (Critical)
            elif threat > 50:
                border_color = "#ff7b72" # High Threat, Low Certainty
            else:
                border_color = "#3fb950" # Low Threat
                
            st.markdown(f"""
            <div style="border-left: 4px solid {border_color}; background-color: rgba(11,20,38,0.6); padding: 10px; margin-bottom: 10px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between;">
                    <strong style="color: #00e5ff;">{host}</strong>
                    <span>T: <b style="color:{border_color}">{threat:.0f}</b> | C: <b>{certainty:.0f}</b></span>
                </div>
                <div style="font-size: 0.8rem; color: #8b949e; margin-top: 5px;">
                    {behaviors}
                </div>
            </div>
            """, unsafe_allow_html=True)
else:
    st.info("No network entities have been flagged with malicious behaviors.")

if st.session_state.get("live_mode"):
    import time
    time.sleep(5)
    st.rerun()
