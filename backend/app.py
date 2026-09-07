import streamlit as st
import sqlite3
import json
import os
import requests

try:
    import folium
    from streamlit_folium import st_folium
    FOLIUM_AVAILABLE = True
except Exception:
    FOLIUM_AVAILABLE = False


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NETRA-Mail SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CONFIG
# ============================================================

API_BASE_URL = "http://127.0.0.1:8000"

DATABASE_PATH = os.path.join(
    "data",
    "evidence",
    "threat_logs.db",
)


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_db_connection():
    if not os.path.exists(DATABASE_PATH):
        return None

    return sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False,
    )


def get_case_from_database(case_id: str):
    conn = get_db_connection()

    if conn is None:
        return None

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                case_id,
                timestamp,
                raw_sha256,
                threat_score,
                verdict,
                forensic_payload,
                previous_hash,
                block_hash
            FROM evidence_ledger
            WHERE case_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (case_id,),
        )

        row = cursor.fetchone()

        if not row:
            return None

        (
            stored_case_id,
            timestamp,
            raw_sha256,
            stored_threat_score,
            verdict,
            forensic_payload,
            previous_hash,
            block_hash,
        ) = row

        try:
            report = json.loads(
                forensic_payload
            )
        except Exception:
            report = {}

        return {
            "case_id": stored_case_id,
            "report": report,
            "ledger": {
                "timestamp": timestamp,
                "raw_sha256": raw_sha256,
                "threat_score": stored_threat_score,
                "verdict": verdict,
                "previous_hash": previous_hash,
                "block_hash": block_hash,
            },
        }

    finally:
        conn.close()


def get_latest_case():
    conn = get_db_connection()

    if conn is None:
        return None

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                case_id,
                timestamp,
                raw_sha256,
                threat_score,
                verdict,
                forensic_payload,
                previous_hash,
                block_hash
            FROM evidence_ledger
            ORDER BY id DESC
            LIMIT 1
            """
        )

        row = cursor.fetchone()

        if not row:
            return None

        (
            stored_case_id,
            timestamp,
            raw_sha256,
            stored_threat_score,
            verdict,
            forensic_payload,
            previous_hash,
            block_hash,
        ) = row

        try:
            report = json.loads(
                forensic_payload
            )
        except Exception:
            report = {}

        return {
            "case_id": stored_case_id,
            "report": report,
            "ledger": {
                "timestamp": timestamp,
                "raw_sha256": raw_sha256,
                "threat_score": stored_threat_score,
                "verdict": verdict,
                "previous_hash": previous_hash,
                "block_hash": block_hash,
            },
        }

    finally:
        conn.close()


# ============================================================
# API FALLBACK
# ============================================================

def get_case_from_api(case_id: str):

    try:

        response = requests.get(
            f"{API_BASE_URL}/api/v1/forensics/case/{case_id}",
            timeout=5,
        )

        if response.status_code == 200:
            return response.json()

    except Exception:
        pass

    return None


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def safe_dict(value):

    if isinstance(value, dict):
        return value

    return {}


def safe_list(value):

    if isinstance(value, list):
        return value

    return []


def get_score(report, ledger=None):

    threat_score = report.get(
        "threat_score",
        0,
    )

    # Current backend:
    # "threat_score": 12

    if isinstance(
        threat_score,
        (int, float),
    ):
        return max(
            0,
            min(
                100,
                int(
                    round(
                        threat_score
                    )
                ),
            ),
        )

    # Compatibility with older schema:
    # "threat_score": {"score": 12}

    if isinstance(
        threat_score,
        dict,
    ):

        value = threat_score.get(
            "threat_score",
            threat_score.get(
                "score",
                threat_score.get(
                    "total",
                    0,
                ),
            ),
        )

        try:
            return max(
                0,
                min(
                    100,
                    int(
                        round(
                            float(value)
                        )
                    ),
                ),
            )
        except Exception:
            pass

    # Ledger fallback

    if ledger:

        value = ledger.get(
            "threat_score",
            0,
        )

        try:
            return max(
                0,
                min(
                    100,
                    int(
                        round(
                            float(value)
                        )
                    ),
                ),
            )
        except Exception:
            pass

    return 0


def get_risk(report, score, ledger=None):

    decision = safe_dict(
        report.get(
            "decision"
        )
    )

    # Current backend decision

    risk = decision.get(
        "risk"
    )

    if risk:
        return str(
            risk
        ).upper()

    # Current forensic payload

    severity = report.get(
        "severity"
    )

    if severity:
        return str(
            severity
        ).upper()

    # Ledger

    if ledger:

        verdict = ledger.get(
            "verdict"
        )

        if verdict:
            return str(
                verdict
            ).upper()

    # Score fallback

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


def risk_icon(risk):

    if risk == "CRITICAL":
        return "🚨"

    if risk == "HIGH":
        return "🔴"

    if risk == "MEDIUM":
        return "🟠"

    return "🟢"


def risk_color(risk):

    if risk == "CRITICAL":
        return "#991b1b"

    if risk == "HIGH":
        return "#dc2626"

    if risk == "MEDIUM":
        return "#d97706"

    return "#16a34a"


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <style>

    .netra-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 0;
    }

    .netra-subtitle {
        color: #94a3b8;
        font-size: 17px;
        margin-top: 4px;
        margin-bottom: 30px;
    }

    .risk-card {
        padding: 24px;
        border-radius: 14px;
        color: white;
        margin-bottom: 20px;
    }

    .section-card {
        padding: 20px;
        border-radius: 12px;
        background: #111827;
        border: 1px solid #1f2937;
        margin-bottom: 15px;
    }

    .small-label {
        color: #94a3b8;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    '<div class="netra-title">🛡️ NETRA-Mail SOC</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="netra-subtitle">
    Digital Forensics • Threat Intelligence • Incident Investigation • Chain-of-Custody
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# GET CASE ID
# ============================================================

query_case_id = st.query_params.get(
    "case_id"
)

if isinstance(
    query_case_id,
    list,
):
    query_case_id = (
        query_case_id[0]
        if query_case_id
        else None
    )


# ============================================================
# LOAD CASE
# ============================================================

case_data = None

if query_case_id:

    # First try local database.

    case_data = get_case_from_database(
        query_case_id
    )

    # Then API fallback.

    if case_data is None:

        case_data = get_case_from_api(
            query_case_id
        )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🔎 Investigation")

    if query_case_id:

        st.success(
            "Case loaded from Gmail"
        )

        st.code(
            str(query_case_id)
        )

    else:

        st.info(
            "No case selected."
        )

    st.divider()

    if st.button(
        "🔄 Load Latest Case",
        use_container_width=True,
    ):

        latest = get_latest_case()

        if latest:

            st.query_params[
                "case_id"
            ] = latest["case_id"]

            st.rerun()

        else:

            st.warning(
                "No forensic cases found."
            )


# ============================================================
# NO CASE
# ============================================================

if case_data is None:

    st.warning(
        "Forensic report could not be loaded."
    )

    st.info(
        """
        Make sure:

        1. FastAPI is running on port 8000.
        2. The Gmail email was analyzed successfully.
        3. The case exists in the forensic ledger.
        4. The URL contains ?case_id=NETRA-XXXXXXXX.
        """
    )

    st.stop()


# ============================================================
# EXTRACT REPORT
# ============================================================

report = safe_dict(
    case_data.get(
        "report"
    )
)

ledger = safe_dict(
    case_data.get(
        "ledger"
    )
)


# ============================================================
# SCORE
# ============================================================

score = get_score(
    report,
    ledger,
)

risk = get_risk(
    report,
    score,
    ledger,
)

decision = safe_dict(
    report.get(
        "decision"
    )
)


action = str(
    decision.get(
        "action",
        "REVIEW",
    )
).upper()


confidence = decision.get(
    "confidence",
    report.get(
        "confidence",
        0,
    ),
)

try:
    confidence = float(
        confidence
    )
except Exception:
    confidence = 0


# ============================================================
# EMAIL INFORMATION
# ============================================================

email = safe_dict(
    report.get(
        "email"
    )
)

subject = email.get(
    "subject",
    "Unknown Subject",
)

sender = email.get(
    "sender",
    "Unknown Sender",
)

recipient = email.get(
    "recipient",
    "Unknown Recipient",
)


# ============================================================
# SUCCESS MESSAGE
# ============================================================

st.success(
    f"Case {case_data.get('case_id', query_case_id)} "
    f"loaded from NETRA forensic ledger."
)


# ============================================================
# RISK HEADER
# ============================================================

risk_bg = risk_color(
    risk
)

st.markdown(
    f"""
    <div class="risk-card"
         style="background:{risk_bg};">

        <div style="
            display:flex;
            justify-content:space-between;
            align-items:center;
        ">

            <div>

                <div style="
                    font-size:14px;
                    font-weight:600;
                    opacity:.85;
                ">
                    NETRA THREAT ASSESSMENT
                </div>

                <div style="
                    font-size:32px;
                    font-weight:800;
                    margin-top:4px;
                ">
                    {risk_icon(risk)}
                    {risk} RISK
                </div>

                <div style="
                    font-size:14px;
                    margin-top:5px;
                ">
                    Recommended Action:
                    <strong>{action}</strong>
                </div>

            </div>

            <div style="
                text-align:right;
            ">

                <div style="
                    font-size:42px;
                    font-weight:800;
                ">
                    {score}%
                </div>

                <div style="
                    font-size:13px;
                    opacity:.85;
                ">
                    THREAT SCORE
                </div>

            </div>

        </div>

    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# EMAIL DETAILS
# ============================================================

c1, c2, c3, c4 = st.columns(4)

with c1:

    st.metric(
        "Threat Score",
        f"{score}/100",
        risk,
    )

with c2:

    st.metric(
        "Confidence",
        f"{confidence:.1f}%",
    )

with c3:

    st.metric(
        "Action",
        action,
    )

with c4:

    st.metric(
        "Attachments",
        email.get(
            "attachment_count",
            0,
        ),
    )


st.divider()


# ============================================================
# EMAIL INFORMATION
# ============================================================

st.subheader(
    "📧 Email Information"
)

email_col1, email_col2 = st.columns(
    2
)

with email_col1:

    st.write(
        "**Subject:**"
    )

    st.code(
        subject
    )

    st.write(
        "**Sender:**"
    )

    st.code(
        sender
    )

with email_col2:

    st.write(
        "**Recipient:**"
    )

    st.code(
        recipient
    )

    st.write(
        "**Case ID:**"
    )

    st.code(
        case_data.get(
            "case_id",
            query_case_id,
        )
    )


# ============================================================
# ANALYSIS TABS
# ============================================================

tabs = st.tabs(
    [
        "📋 Executive Summary",
        "🛡️ Authentication",
        "🌍 GeoIP & Infrastructure",
        "🔗 URL & Domain Intelligence",
        "🧠 NLP & ML",
        "🔐 Evidence & Chain",
    ]
)


# ============================================================
# TAB 1
# ============================================================

with tabs[0]:

    st.subheader(
        "Executive Assessment"
    )

    reasons = safe_list(
        decision.get(
            "reasons",
            report.get(
                "evidence",
                [],
            ),
        )
    )

    if reasons:

        for reason in reasons:

            st.markdown(
                f"- {reason}"
            )

    else:

        st.info(
            "No detailed reasons were stored."
        )

    ai_explanation = report.get(
        "ai_explanation",
        "",
    )

    if ai_explanation:

        st.subheader(
            "🤖 AI Investigative Brief"
        )

        st.write(
            ai_explanation
        )


# ============================================================
# TAB 2
# ============================================================

with tabs[1]:

    st.subheader(
        "🛡️ Email Authentication & Header Forensics"
    )

    authentication = safe_dict(
        report.get(
            "authentication"
        )
    )

    if authentication:

        st.json(
            authentication
        )

    else:

        st.info(
            "No authentication data available."
        )


# ============================================================
# TAB 3
# ============================================================

with tabs[2]:

    st.subheader(
        "🌍 Origin Infrastructure & GeoIP"
    )

    infrastructure = safe_dict(
        report.get(
            "infrastructure"
        )
    )

    if not infrastructure:

        st.info(
            "No infrastructure intelligence was recorded."
        )

    else:

        geo_columns = st.columns(
            4
        )

        with geo_columns[0]:

            st.metric(
                "IP",
                str(
                    infrastructure.get(
                        "ip",
                        "Unknown",
                    )
                ),
            )

        with geo_columns[1]:

            st.metric(
                "Country",
                str(
                    infrastructure.get(
                        "country",
                        "Unknown",
                    )
                ),
            )

        with geo_columns[2]:

            st.metric(
                "City",
                str(
                    infrastructure.get(
                        "city",
                        "Unknown",
                    )
                ),
            )

        with geo_columns[3]:

            st.metric(
                "ASN",
                str(
                    infrastructure.get(
                        "asn",
                        "Unknown",
                    )
                ),
            )

        latitude = infrastructure.get(
            "latitude"
        )

        longitude = infrastructure.get(
            "longitude"
        )

        try:

            latitude = float(
                latitude
            )

            longitude = float(
                longitude
            )

            if (
                FOLIUM_AVAILABLE
                and latitude != 0
                and longitude != 0
            ):

                fmap = folium.Map(
                    location=[
                        latitude,
                        longitude,
                    ],
                    zoom_start=4,
                )

                folium.Marker(
                    [
                        latitude,
                        longitude,
                    ],
                    popup=(
                        f"IP: "
                        f"{infrastructure.get('ip', 'Unknown')}"
                    ),
                ).add_to(
                    fmap
                )

                st_folium(
                    fmap,
                    height=400,
                    width=None,
                )

            else:

                st.info(
                    "No usable public GeoIP coordinates available."
                )

        except Exception:

            st.info(
                "GeoIP coordinates unavailable."
            )

        st.subheader(
            "Infrastructure Details"
        )

        st.json(
            infrastructure
        )


# ============================================================
# TAB 4
# ============================================================

with tabs[3]:

    st.subheader(
        "🔗 URL Intelligence"
    )

    url_data = safe_dict(
        report.get(
            "url_intelligence"
        )
    )

    domain_data = safe_dict(
        report.get(
            "domain_intelligence"
        )
    )

    st.write(
        "### URL Analysis"
    )

    if url_data:

        st.json(
            url_data
        )

    else:

        st.info(
            "No URL intelligence available."
        )

    st.write(
        "### Domain Analysis"
    )

    if domain_data:

        st.json(
            domain_data
        )

    else:

        st.info(
            "No domain intelligence available."
        )


# ============================================================
# TAB 5
# ============================================================

with tabs[4]:

    st.subheader(
        "🧠 NLP & Machine Learning"
    )

    nlp = safe_dict(
        report.get(
            "nlp_analysis"
        )
    )

    ml = safe_dict(
        report.get(
            "ml_analysis"
        )
    )

    st.write(
        "### NLP Analysis"
    )

    if nlp:

        st.json(
            nlp
        )

    else:

        st.info(
            "No NLP analysis available."
        )

    st.write(
        "### ML Analysis"
    )

    if ml:

        st.json(
            ml
        )

    else:

        st.info(
            "No ML analysis available."
        )


# ============================================================
# TAB 6
# ============================================================

with tabs[5]:

    st.subheader(
        "🔐 Cryptographic Evidence & Chain-of-Custody"
    )

    evidence_seal = safe_dict(
        report.get(
            "evidence_seal"
        )
    )

    if evidence_seal:

        st.write(
            "### Evidence Seal"
        )

        st.json(
            evidence_seal
        )

    st.write(
        "### Ledger Record"
    )

    st.json(
        ledger
    )

    network_chain = safe_list(
        report.get(
            "network_chain"
        )
    )

    if network_chain:

        st.write(
            "### Network Chain"
        )

        st.json(
            network_chain
        )

    # Download report

    report_json = json.dumps(
        report,
        indent=2,
        default=str,
    )

    st.download_button(
        "📥 Download Forensic Dossier",
        data=report_json,
        file_name=(
            f"{case_data.get('case_id', 'NETRA')}"
            "_forensic_report.json"
        ),
        mime="application/json",
        use_container_width=True,
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "NETRA-Mail SOC • Local Forensic Investigation Platform"
)