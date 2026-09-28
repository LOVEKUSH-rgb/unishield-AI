import streamlit as st
from dashboard.api_client import API_URL, api_get, api_post
import pandas as pd
import os

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="Incidents", page_icon="🚨", layout="wide")
from dashboard.components.theme import inject_darktrace_theme
inject_darktrace_theme()
st.title("🚨 Incident Management")

# Search and filter
col1, col2 = st.columns([2, 1])
with col1:
    search_ip = st.text_input("Search Source IP", placeholder="e.g. 192.168.1.100")

def fetch_incidents(source_ip=None):
    params = {}
    if source_ip:
        params["source_ip"] = source_ip
    try:
        res = api_get("/incidents", params=params, timeout=5)
        return res.json() if res.status_code == 200 else []
    except:
        return []

def fetch_incident_detail(inc_id):
    try:
        res = api_get("/incidents/{inc_id}", timeout=5)
        return res.json() if res.status_code == 200 else None
    except:
        return None

incidents = fetch_incidents(search_ip if search_ip else None)

if not incidents:
    st.info("No incidents found matching the criteria.")
    st.stop()

# Build DataFrame for table
df_data = []
for inc in incidents:
    df_data.append({
        "Incident ID": inc.get("incident_id"),
        "Risk": inc.get("risk_score", 0),
        "Level": inc.get("risk_level", "UNKNOWN"),
        "Source IP": ", ".join(inc.get("sources", [])),
        "Detectors": " + ".join(inc.get("detectors", [])),
        "Last Seen": inc.get("last_seen", "").replace("T", " ")[:19],
        "Status": inc.get("status")
    })

df = pd.DataFrame(df_data)

# Risk color formatting
def color_risk(val):
    if val >= 90: color = "#f85149"
    elif val >= 70: color = "#ff7b72"
    elif val >= 40: color = "#d2a8ff"
    else: color = "#3fb950"
    return f'color: {color}; font-weight: bold;'

st.write("### Active Incidents")
selected = st.dataframe(
    df.style.map(color_risk, subset=["Risk"]).format({"Risk": "{:.0f}"}),
    use_container_width=True,
    hide_index=True,
    selection_mode="single-row",
    on_select="rerun"
)

# Incident Investigation View
if selected and len(selected.selection.rows) > 0:
    row_idx = selected.selection.rows[0]
    inc_id = df.iloc[row_idx]["Incident ID"]
    
    st.markdown("---")
    st.subheader(f"🔍 Investigating: `{inc_id}`")
    
    detail = fetch_incident_detail(inc_id)
    if not detail:
        st.error("Failed to load incident details. Backend unavailable.")
    else:
        # Layout
        sum_col, ent_col = st.columns(2)
        
        with sum_col:
            st.markdown("#### Summary")
            st.markdown(f"**Risk Score:** {detail.get('risk_score')}/100")
            st.markdown(f"**Risk Level:** {detail.get('risk_level')}")
            st.markdown(f"**Status:** {detail.get('status')}")
            st.markdown(f"**First Seen:** {detail.get('first_seen', '').replace('T', ' ')[:19]}")
            st.markdown(f"**Last Seen:** {detail.get('last_seen', '').replace('T', ' ')[:19]}")
            
        with ent_col:
            st.markdown("#### Entities")
            st.markdown(f"**Sources:** {', '.join(detail.get('sources', []))}")
            st.markdown(f"**Destinations:** {', '.join(detail.get('destinations', []))}")
            st.markdown(f"**Detectors:** {', '.join(detail.get('detectors', []))}")
            if detail.get('potential_progression'):
                st.markdown(f"**Progression Threat:** {detail.get('potential_progression')}")
                
        # Timeline
        st.markdown("#### ⏱️ Detection Timeline & Evidence")
        alerts = detail.get("alerts", [])
        if not alerts:
            st.write("No alerts found for this incident.")
        else:
            for alert in alerts:
                ts = alert.get("timestamp", "").replace("T", " ")[:19]
                st.markdown(f"""
                <div style="border-left: 2px solid #58a6ff; padding-left: 15px; margin-bottom: 10px;">
                    <div style="color: #8b949e; font-size: 0.9rem;">{ts}</div>
                    <div style="font-weight: bold;">{alert.get('threat_class')} (Confidence: {alert.get('confidence', 0):.2f})</div>
                    <div style="font-size: 0.9rem; color: #c9d1d9;">Detector: {alert.get('detector')} | Source: {alert.get('source_ip')}</div>
                """, unsafe_allow_html=True)
                
                # Evidence
                evidence_list = alert.get("evidence", [])
                if evidence_list:
                    with st.expander("View Evidence"):
                        for ev in evidence_list:
                            st.markdown(f"""
                            - **{ev.get('feature')}**: Observed `{ev.get('observed')}` 
                              (Baseline: `{ev.get('baseline', 'N/A')}`)
                              <br><i>Reason: {ev.get('reason')}</i>
                            """, unsafe_allow_html=True)
                
                st.markdown("</div>", unsafe_allow_html=True)

if st.session_state.get("live_mode"):
    import time
    time.sleep(5)
    st.rerun()
