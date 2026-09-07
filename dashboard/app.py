import streamlit as st
import sqlite3
import json
import os
import folium
from streamlit_folium import st_folium
import requests

st.set_page_config(
    page_title="Agentic MX | SOC Investigation Platform",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Agentic MX — Digital Forensics & Threat Intelligence")
st.markdown("Automated RFC 822 Email Forensics, ML Classification & Chain-of-Custody Vault")

# --- Helper Functions ---
def get_report_by_hash(evidence_hash: str):
    db_path = os.path.join("data", "evidence", "threat_logs.db")
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT forensic_data FROM chain_of_custody WHERE evidence_hash = ? LIMIT 1", (evidence_hash,))
    row = cursor.fetchone()
    conn.close()
    return json.loads(row[0]) if row else None

def get_latest_report():
    db_path = os.path.join("data", "evidence", "threat_logs.db")
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT forensic_data FROM chain_of_custody ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return json.loads(row[0]) if row else None

def render_forensic_report(report):
    meta = report.get("metadata", {})
    score_data = report.get("threat_score", {})
    score = score_data.get("score", 0)
    risk_level = score_data.get("risk_level", "LOW")
    ml = report.get("ml_assessment", {})
    infra = report.get("threat_infrastructure", {})
    geo = infra.get("geolocation") or {}
    domain = infra.get("domain_intelligence") or {}
    evidence = report.get("evidence_seal", {})
    ai_brief = report.get("ai_investigative_briefing", {})
    nlp_cues = report.get("nlp_indicators", {})

    st.success("✅ **Live Webmail Incident Loaded Automatically via Cryptographic Seal**")
    
    # 1. Metric Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        color = "red" if score >= 60 else "orange" if score >= 40 else "green"
        st.metric("Threat Score", f"{score}/100", delta=risk_level, delta_color="inverse")
    with c2:
        st.metric("ML Classification", ml.get("ml_classification", "N/A"), f"{ml.get('confidence_score', 0)}% Conf.")
    with c3:
        st.metric("Origin Country", geo.get("country", "Unknown"), geo.get("asn", "Local/Direct"))
    with c4:
        st.metric("Domain Status", "Suspicious" if domain.get("is_newly_registered") else "Active", f"Risk Flags: {len(domain.get('risk_flags', []))}")

    st.divider()

    # 2. Tabs for Deep Analysis
    t1, t2, t3, t4 = st.tabs(["📋 Executive Summary & AI Brief", "🌍 GeoIP & Infrastructure", "🔍 NLP & Social Engineering", "🔐 Evidence & Chain-of-Custody"])

    with t1:
        st.subheader("Executive Incident Briefing")
        st.markdown(f"**Subject:** `{meta.get('subject', 'N/A')}`")
        st.markdown(f"**From:** `{meta.get('from', 'N/A')}`")
        if ai_brief:
            st.info(f"**Executive Threat Assessment:**\n\n{ai_brief.get('executive_threat_assessment', 'No assessment available.')}")
            st.warning(f"**Attack Vector Identified:** {ai_brief.get('attack_vector_identified', 'N/A')}")
            st.markdown(f"**Remediation Recommendation:** {ai_brief.get('recommended_analyst_action', 'N/A')}")

    with t2:
        st.subheader("Origin Infrastructure & Geolocation")
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        if lat and lon:
            m = folium.Map(location=[lat, lon], zoom_start=4)
            folium.Marker(
                [lat, lon],
                popup=f"Origin IP: {geo.get('ip')}<br>ASN: {geo.get('asn')}",
                icon=folium.Icon(color="red" if geo.get("is_cloud_vps") else "blue", icon="shield")
            ).add_to(m)
            st_folium(m, height=350, width=700)
        else:
            st.info("Direct webmail injection without upstream IP hops.")

    with t3:
        st.subheader("Extracted Social Engineering & Urgency Cues")
        for category, cues in nlp_cues.items():
            if cues:
                st.write(f"**{category.replace('_', ' ').title()}:**")
                for cue in cues:
                    st.code(cue, language="text")

    with t4:
        st.subheader("Cryptographic Evidence Vault & Chain-of-Custody")
        st.json({
            "evidence_seal": evidence,
            "forensic_report": report
        })
        st.download_button(
            "📥 Download Forensic Dossier (JSON)",
            data=json.dumps(report, indent=2),
            file_name=f"dossier_{evidence.get('sha256_hash', 'evidence')[:10]}.json",
            mime="application/json"
        )

# --- Routing Logic ---
query_hash = st.query_params.get("hash")
report_to_display = None

if query_hash:
    report_to_display = get_report_by_hash(query_hash)

# Fallback: Check if user uploaded a file manually
if not report_to_display:
    st.sidebar.header("Manual Inspection")
    uploaded_file = st.sidebar.file_uploader("Upload .EML File for Analysis", type=["eml", "txt"])
    if uploaded_file:
        files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "message/rfc822")}
        res = requests.post("http://127.0.0.1:8000/api/v1/analyze/file", files=files)
        if res.status_code == 200:
            report_to_display = res.json().get("report")

if report_to_display:
    render_forensic_report(report_to_display)
else:
    # If opened directly with no query param and no file, show latest activity
    latest = get_latest_report()
    if latest:
        st.info("Displaying most recent incident recorded by Agentic MX:")
        render_forensic_report(latest)
    else:
        st.info("No active threat loaded. Open an email in Gmail or upload a .eml file on the sidebar.")
