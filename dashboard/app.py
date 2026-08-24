import streamlit as st
import requests
import json
import sqlite3
import folium
from streamlit_folium import st_folium
from pathlib import Path

st.set_page_config(
    page_title="Agentic MX - Forensic Dashboard",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://127.0.0.1:8000/api/v1/analyze/file"
DB_PATH = "data/evidence/threat_logs.db"

# Persistent session state for single-page workflow
if "report" not in st.session_state:
    st.session_state["report"] = None
if "last_uploaded_file" not in st.session_state:
    st.session_state["last_uploaded_file"] = None

st.title("🛡️ Agentic MX: AI Threat & Forensic Platform")
st.caption("RFC 822 Email Forensics | Geolocation Tracking | Chain-of-Custody Intelligence")

tab_selection = st.sidebar.radio("Navigation", ["🔍 Live Email Analyzer", "📊 Campaign Intelligence & Case Logs"])

# ================= TAB 1: LIVE ANALYZER =================
if tab_selection == "🔍 Live Email Analyzer":
    st.subheader("Ingest & Analyze Raw Email (.eml)")
    uploaded_file = st.file_uploader("Upload raw email file", type=["eml", "txt"])

    if uploaded_file != st.session_state["last_uploaded_file"]:
        st.session_state["report"] = None
        st.session_state["last_uploaded_file"] = uploaded_file

    if uploaded_file is not None:
        if st.button("🚀 Run Deep Forensics", type="primary"):
            with st.spinner("Executing ML inference, querying OSINT, and synthesizing AI briefing..."):
                try:
                    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "message/rfc822")}
                    response = requests.post(API_URL, files=files)
                    
                    if response.status_code == 200:
                        st.session_state["report"] = response.json().get("report", {})
                    else:
                        st.error(f"Analysis failed: {response.text}")
                except Exception as e:
                    st.error(f"Could not connect to FastAPI backend: {e}")

    # Render analysis findings
    if st.session_state["report"] is not None:
        report = st.session_state["report"]
        
        # --- TOP METRIC CARDS ---
        st.divider()
        col1, col2, col3, col4 = st.columns(4)
        
        threat_data = report.get("threat_score", {})
        score_val = threat_data.get("score", 0)
        risk_val = threat_data.get("risk_level", "UNKNOWN")
        
        ml_pred = report["ml_assessment"]["ml_classification"]
        confidence = report["ml_assessment"]["confidence_score"]
        
        col1.metric("Threat Score", f"{score_val}/100", delta=risk_val, delta_color="inverse" if score_val >= 60 else "normal")
        col2.metric("ML Classification", f"{ml_pred} ({confidence}%)")
        col3.metric("Origin IP", report["routing_forensics"]["origin_ip"] or "Unknown")
        col4.metric("Evidence Seal", report["evidence_seal"]["sha256_hash"][:10] + "...")
        
        # --- AI FORENSIC EXECUTIVE BRIEFING ---
        ai_brief = report.get("ai_investigative_briefing", {})
        st.markdown("### 🧠 AI Forensic Executive Assessment")
        st.info(f"**Investigative Summary:** {ai_brief.get('executive_summary', 'N/A')}")
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Identified Threat Actor Tactics:**")
            for tactic in ai_brief.get("threat_actor_tactics", []):
                st.markdown(f"- ⚠️ {tactic}")
        with c2:
            st.markdown("**Recommended SOC Action Items:**")
            for action in ai_brief.get("recommended_soc_actions", []):
                st.markdown(f"- 🛡️ {action}")

        st.divider()
        col_left, col_right = st.columns([1, 1])
        
        with col_left:
            st.markdown("### 📋 Threat Indicators & NLP Cues")
            st.write("**Subject:**", report["metadata"]["subject"])
            st.write("**From:**", report["metadata"]["from"])
            
            cues = report["nlp_indicators"]
            if any(cues.values()):
                for category, terms in cues.items():
                    if terms:
                        st.warning(f"⚠️ **{category.replace('_', ' ').title()}:** {', '.join(terms)}")
            else:
                st.success("✓ No social engineering urgency patterns detected.")
                
            domain_intel = report["threat_infrastructure"]["domain_intelligence"]
            st.write(f"- **Domain Age:** {domain_intel.get('domain_age_days', 'Unknown')} days")
            st.write(f"- **Valid MX Records:** {domain_intel.get('has_valid_mx')}")
            if domain_intel.get("risk_flags"):
                for flag in domain_intel["risk_flags"]:
                    st.error(f"🚩 Risk Flag: {flag}")
        
        with col_right:
            st.markdown("### 🌍 Origin Geolocation & Infrastructure")
            geo = report["threat_infrastructure"]["geolocation"]
            if geo and geo.get("latitude") and geo.get("longitude"):
                st.write(f"**Location:** {geo.get('city')}, {geo.get('country')}")
                st.write(f"**ISP / ASN:** {geo.get('isp')} ({geo.get('asn')})")
                if geo.get("is_cloud_vps"):
                    st.error("⚠️ Sender infrastructure originates from a Cloud VPS/Hosting provider.")
                
                m = folium.Map(location=[geo["latitude"], geo["longitude"]], zoom_start=4)
                folium.Marker(
                    [geo["latitude"], geo["longitude"]],
                    popup=f"Origin: {geo.get('ip')}<br>ISP: {geo.get('isp')}",
                    icon=folium.Icon(color="red" if ml_pred == "Phishing" else "green", icon="info-sign")
                ).add_to(m)
                st_folium(m, height=280, width=500, returned_objects=[])
            else:
                st.info("No public origin IP detected in headers for mapping.")

        # --- EXPORT CERTIFIED DOSSIER ---
        st.divider()
        dossier_json = json.dumps(report, indent=2)
        st.download_button(
            label="📥 Export Certified Forensic Dossier (JSON)",
            data=dossier_json,
            file_name=f"forensic_dossier_{report['evidence_seal']['sha256_hash'][:8]}.json",
            mime="application/json"
        )

# ================= TAB 2: CAMPAIGN LOGS =================
elif tab_selection == "📊 Campaign Intelligence & Case Logs":
    st.subheader("Case Management & Threat Actor Campaign Correlation")
    
    if Path(DB_PATH).exists():
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, evidence_hash, sealed_timestamp, origin_ip, ml_prediction, forensic_data FROM chain_of_custody ORDER BY id DESC")
            records = cursor.fetchall()
            
        if records:
            st.write(f"**Total Logged Incidents:** {len(records)}")
            
            ip_counts = {}
            for r in records:
                ip = r[3]
                if ip and ip != "Unknown":
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    
            top_campaign_ips = {k: v for k, v in ip_counts.items() if v > 1}
            if top_campaign_ips:
                for ip, count in top_campaign_ips.items():
                    st.warning(f"🚨 **Coordinated Threat Campaign Detected:** Origin IP `{ip}` has sent {count} distinct attack payloads.")
            else:
                st.info("No multi-attack IP clusters detected yet.")
                
            st.markdown("### 📁 Evidence Vault")
            table_data = []
            for r in records:
                table_data.append({
                    "Case ID": r[0],
                    "Evidence SHA-256": r[1][:16] + "...",
                    "Sealed Timestamp": r[2],
                    "Origin IP": r[3],
                    "ML Classification": r[4]
                })
            st.dataframe(table_data, use_container_width=True)
        else:
            st.info("Evidence vault is currently empty. Analyze an email to populate logs.")
    else:
        st.info("Database file not yet initialized.")
