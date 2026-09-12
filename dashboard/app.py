from __future__ import annotations

import os
import sys
from typing import Any, Dict

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dashboard.api_client import APIClient


st.set_page_config(page_title="NETRA-Mail Investigation", page_icon="N", layout="wide")

client = APIClient()
st.markdown("""
<style>
:root { color-scheme: dark; }
.block-container { padding-top: 2rem; max-width: 1400px; }
[data-testid="stMetric"] { background: #172033; border: 1px solid #2a3a53; padding: 12px; }
</style>
""", unsafe_allow_html=True)


def safe_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs), None
    except Exception as exc:
        return None, str(exc)


def risk_color(score: int) -> str:
    return "#ef4444" if score >= 75 else "#f59e0b" if score >= 50 else "#22c55e"


def render_finding(finding: Dict[str, Any]):
    severity = str(finding.get("severity", "unknown")).upper()
    st.markdown(f"**{finding.get('title', 'Finding')}**  ·  `{severity}`  ·  confidence `{float(finding.get('confidence', 0)):.0%}`")
    st.write(finding.get("description", "No explanation available."))
    with st.expander("Evidence and limitations"):
        st.json({"evidence": finding.get("evidence", {}), "limitations": finding.get("limitations", [])})


def render_overview():
    st.title("NETRA-Mail Investigation Platform")
    st.caption("Detect, explain, trace, correlate, preserve, report")
    summary, error = safe_call(client.summary)
    if error:
        st.error(f"Backend unavailable: {error}")
        st.info("Start the FastAPI backend and confirm the configured API URL.")
        return
    cols = st.columns(5)
    for column, label, value in zip(cols, ("Analyzed emails", "Critical", "High risk", "Open cases", "Suspected campaigns"), (summary.get("total_emails", 0), summary.get("critical_emails", 0), summary.get("high_risk_emails", 0), summary.get("open_cases", 0), summary.get("suspected_campaigns", 0))):
        column.metric(label, value)
    st.subheader("Provider and integrity status")
    st.json({"provider_status": summary.get("provider_status", {}), "integrity_warnings": summary.get("integrity_warnings", 0), "limitations": summary.get("limitations", [])})
    st.subheader("Recent analyses")
    data, error = safe_call(client.emails, 10, 0)
    if error:
        st.warning(error)
    else:
        for item in data.get("items", []):
            score = int(item.get("risk_score", 0))
            st.markdown(f"`{item.get('email_id')}`  **{item.get('classification', 'Unknown')}**  · score **{score}/100**")


def render_email(email_id: str):
    result, error = safe_call(client.email, email_id)
    if error:
        st.error(error)
        return
    findings, findings_error = safe_call(client.findings, email_id)
    trace, trace_error = safe_call(client.trace, email_id)
    relationships, relation_error = safe_call(client.relationships, email_id)
    st.title("Email Investigation")
    st.caption(email_id)
    score = int(result.get("risk_score", 0))
    st.markdown(f"<h2 style='color:{risk_color(score)}'>{result.get('classification', 'Unknown')} · {score}/100</h2>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("Confidence", f"{float(result.get('confidence', 0)):.0%}")
    c2.metric("Evidence hash", str(result.get("evidence", {}).get("sha256", "Unavailable"))[:18] + "...")
    c3.metric("Analysis version", result.get("evidence", {}).get("analysis_version", "Unknown"))
    tabs = st.tabs(["Findings", "Origin trace", "Relationships", "Limitations"])
    with tabs[0]:
        if findings_error:
            st.error(findings_error)
        elif not findings.get("findings"):
            st.info("No structured findings were returned.")
        else:
            for finding in findings["findings"]:
                render_finding(finding)
    with tabs[1]:
        if trace_error:
            st.error(trace_error)
        else:
            for index, hop in enumerate(trace.get("hops", []), 1):
                st.markdown(f"**Hop {index}**  `{hop.get('source_hostname') or 'Unknown'}` -> `{hop.get('destination_hostname') or 'Unknown'}`")
                st.caption(f"IP: {hop.get('source_ip') or 'Unknown'} · classification: {', '.join(hop.get('ip_classifications', [])) or 'Unknown'} · timestamp: {hop.get('timestamp') or 'Unavailable'}")
            st.subheader("Origin candidates")
            for candidate in trace.get("origin_candidates", []):
                st.write(f"`{candidate.get('ip')}` · confidence `{float(candidate.get('confidence', 0)):.0%}` · {', '.join(candidate.get('basis', []))}")
            st.info("Geolocation is infrastructure intelligence and does not prove the sender's physical location.")
            st.json({"limitations": trace.get("limitations", [])})
    with tabs[2]:
        if relation_error:
            st.error(relation_error)
        elif not relationships.get("relationships"):
            st.info("No stored relationships for this email.")
        else:
            for relationship in relationships["relationships"]:
                st.markdown(f"**{relationship.get('relationship_type')}** · confidence `{float(relationship.get('confidence', 0)):.0%}`")
                st.json({"evidence": relationship.get("evidence", []), "limitations": relationship.get("limitations", [])})
    with tabs[3]:
        st.json(result.get("limitations", ["Not enough evidence."]))


def render_cases():
    st.title("Cases")
    with st.expander("Create case"):
        with st.form("create_case"):
            title = st.text_input("Title")
            description = st.text_area("Description")
            severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
            priority = st.selectbox("Priority", ["low", "normal", "high", "urgent"])
            if st.form_submit_button("Create case"):
                created, create_error = safe_call(client.create_case, {"title": title, "description": description, "severity": severity, "priority": priority})
                if create_error:
                    st.error(create_error)
                else:
                    st.success(f"Created {created.get('case_id')}")
    data, error = safe_call(client.cases)
    if error:
        st.error(error)
        return
    cases = data.get("cases", [])
    if not cases:
        st.info("No persisted cases.")
        return
    for case in cases:
        with st.expander(f"{case.get('case_id')} · {case.get('title')} · {case.get('status')} / {case.get('severity')}"):
            st.write(case.get("description", ""))
            st.json({"emails": case.get("email_ids", []), "campaigns": case.get("campaign_ids", []), "tags": case.get("tags", []), "notes": case.get("notes", [])})
            new_status = st.selectbox("Status", ["open", "investigating", "contained", "resolved", "closed", "false_positive"], index=["open", "investigating", "contained", "resolved", "closed", "false_positive"].index(case.get("status", "open")), key=f"status_{case['case_id']}")
            if st.button("Save status", key=f"save_{case['case_id']}"):
                updated, update_error = safe_call(client.update_case, case["case_id"], {"status": new_status})
                if update_error:
                    st.error(update_error)
                else:
                    st.success(f"Case updated to {updated.get('status')}")
            note = st.text_input("Add analyst note", key=f"note_{case['case_id']}")
            if st.button("Add note", key=f"add_note_{case['case_id']}") and note:
                _, note_error = safe_call(client.add_note, case["case_id"], note)
                st.error(note_error) if note_error else st.success("Note added")
            tag = st.text_input("Add tag", key=f"tag_{case['case_id']}")
            if st.button("Add tag", key=f"add_tag_{case['case_id']}") and tag:
                _, tag_error = safe_call(client.add_tag, case["case_id"], tag)
                st.error(tag_error) if tag_error else st.success("Tag added")
            evidence, evidence_error = safe_call(client.case_evidence, case["case_id"])
            if evidence_error:
                st.warning(evidence_error)
            else:
                st.subheader("Evidence")
                st.dataframe([{key: item.get(key) for key in ("evidence_id", "evidence_type", "filename", "sha256", "integrity_status")} for item in evidence.get("evidence", [])], use_container_width=True)
                for item in evidence.get("evidence", []):
                    if st.button(f"Verify {item.get('evidence_id')}", key=f"verify_{item.get('evidence_id')}"):
                        verification, verification_error = safe_call(client.evidence_verify, item["evidence_id"])
                        if verification_error:
                            st.error(verification_error)
                        else:
                            st.json(verification)
            timeline, timeline_error = safe_call(client.case_timeline, case["case_id"])
            if not timeline_error:
                st.subheader("Timeline")
                for event in timeline.get("timeline", []):
                    st.write(f"`{event.get('created_at')}` · {event.get('description')}")


def render_campaigns():
    st.title("Campaigns")
    data, error = safe_call(client.campaigns)
    if error:
        st.error(error)
        return
    campaigns = data.get("campaigns", [])
    for campaign in campaigns:
        with st.expander(f"{campaign.get('name')} · {campaign.get('status')} · {float(campaign.get('confidence', 0)):.0%}"):
            st.write(campaign.get("description", ""))
            st.write("Related email IDs:", ", ".join(campaign.get("email_ids", [])) or "Unavailable")
            st.caption("Campaign relationships show shared evidence and require analyst confirmation; they do not identify an attacker.")


def render_reports():
    st.title("Reports")
    case_id = st.text_input("Case ID")
    if not case_id:
        st.info("Enter a case ID to view and generate reports.")
        return
    reports, error = safe_call(client.reports, case_id)
    if error:
        st.error(error)
        return
    st.json(reports)
    format_choice = st.selectbox("Generate format", ["json", "html", "pdf"])
    if st.button("Generate report"):
        generated, generation_error = safe_call(client.create_report, case_id, format_choice)
        if generation_error:
            st.error(generation_error)
        else:
            st.success(f"Report created: {generated.get('report_id')}")
            st.json({key: generated.get(key) for key in ("report_id", "format", "evidence_count", "integrity_verified", "limitations")})
def render_attack_simulator():
    st.title("🧪 NETRA Attack Simulator")
    st.caption(
        "Run controlled phishing scenarios through the real NETRA analysis pipeline."
    )

    scenarios = {
        "Bank Credential Phishing": {
            "subject": "URGENT: Your SBI account will be suspended",
            "sender": "security@sbi-account-alert.example",
            "recipient": "user@example.com",
            "reply_to": "verify-account@secure-login.example",
            "body": """
URGENT ACTION REQUIRED!

Your SBI internet banking account has been temporarily
restricted due to a security verification issue.

To prevent permanent suspension, verify your account immediately:

https://sbi-secure-login.example/verify

Please enter your username, password and OTP.

Failure to complete verification within 24 hours
may result in account suspension.
""",
        },

        "Microsoft Credential Phishing": {
            "subject": "Microsoft Security Alert - Verify Your Account",
            "sender": "security@microsoft-security.example",
            "recipient": "user@example.com",
            "reply_to": "verify@microsoft-login.example",
            "body": """
Microsoft Security Alert

We detected unusual activity on your Microsoft account.

Verify your identity immediately:

https://microsoft-login.example/verify

You must provide your password and authentication code
to prevent your account from being locked.
""",
        },

        "CEO Financial Fraud": {
            "subject": "Urgent confidential payment request",
            "sender": "ceo@company.example",
            "recipient": "finance@example.com",
            "reply_to": "private-payment@example.net",
            "body": """
I need you to process an urgent payment immediately.

This is confidential. Do not discuss this request with
anyone else until the transaction is complete.

Please transfer the requested funds to the attached
beneficiary details today.

This is time sensitive.
""",
        },

        "Safe Email": {
            "subject": "Team meeting tomorrow",
            "sender": "manager@company.example",
            "recipient": "user@example.com",
            "reply_to": "manager@company.example",
            "body": """
Hi,

Just a reminder that our team meeting is scheduled
for tomorrow at 10:00 AM.

Please bring your project updates.

Regards,
Team Manager
""",
        },
    }

    selected = st.selectbox(
        "Choose an attack scenario",
        list(scenarios.keys()),
    )

    scenario = scenarios[selected]

    st.subheader("Scenario")

    st.write(f"**Subject:** {scenario['subject']}")
    st.write(f"**Sender:** `{scenario['sender']}`")
    st.write(f"**Reply-To:** `{scenario['reply_to']}`")

    with st.expander("View simulated email"):
        st.code(scenario["body"])

    if st.button(
        "🚀 RUN NETRA SIMULATION",
        type="primary",
        use_container_width=True,
    ):
        with st.spinner("NETRA is investigating the email..."):

            payload = {
                "subject": scenario["subject"],
                "sender": scenario["sender"],
                "recipient": scenario["recipient"],
                "reply_to": scenario["reply_to"],
                "body": scenario["body"],
                "html": "",
                "headers": "",
            }

            result, error = safe_call(
                client.analyze_email,
                payload,
            )

        if error:
            st.error(f"Simulation failed: {error}")
            return

        st.success("Analysis completed!")

        score = int(result.get("risk_score", 0))
        classification = result.get(
            "classification",
            "UNKNOWN",
        )

        st.divider()
        st.subheader("NETRA Decision")

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Risk Score",
            f"{score}/100",
        )

        c2.metric(
            "Classification",
            classification,
        )

        action_map = {
            "SAFE": "ALLOW",
            "LOW": "REVIEW",
            "HIGH": "QUARANTINE",
            "CRITICAL": "BLOCK",
        }

        c3.metric(
            "Recommended Action",
            action_map.get(
                classification,
                "REVIEW",
            ),
        )
        st.subheader("🔎 Evidence Found")

        findings = result.get(
            "findings",
            [],
        )

        if not findings:
            st.info(
                "No structured findings were generated."
            )
        else:
            for finding in findings:
                severity = str(
                    finding.get(
                        "severity",
                        "unknown",
                    )
                ).upper()

                st.markdown(
                    f"**{finding.get('title', 'Finding')}** "
                    f"· `{severity}` "
                    f"· confidence "
                    f"`{float(finding.get('confidence', 0)):.0%}`"
                )

                st.write(
                    finding.get(
                        "description",
                        "",
                    )
                )
        st.subheader("🎯 Investigation Summary")

        st.write(
            f"**Case:** {selected}"
        )

        st.write(
            f"**Final risk:** {score}/100"
        )

        st.write(
            f"**Decision:** "
            f"{action_map.get(classification, 'REVIEW')}"
        )

        st.caption(
            "This simulation uses the same NETRA backend "
            "analysis pipeline used for real email analysis."
        )


def main():page = st.sidebar.radio(
    "Navigate",
    [
        "Overview",
        "Email analysis",
        "🧪 Attack Simulator",
        "Campaigns",
        "Cases",
        "Reports",
    ],
    )
    st.sidebar.caption(f"API: {client.base_url}")
    if page == "Overview":
        render_overview()
    elif page == "Email analysis":
        data, error = safe_call(client.emails, 100, 0)
        if error:
            st.error(error)
            return
        email_ids = [item.get("email_id") for item in data.get("items", [])]
        selected = st.selectbox("Select analyzed email", email_ids or ["No analyses available"])
        if email_ids:
            render_email(selected)
    elif page == "Campaigns":
        render_campaigns()
    elif page == "Cases":
        render_cases()
    else:
        render_reports()


if __name__ == "__main__":
    main()
