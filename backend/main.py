"""
NETRA-Mail
----------
Local FastAPI backend for NETRA-Mail.

Features:
- Gmail live-extension analysis
- Local .EML analysis
- NLP phishing detection
- Local ML phishing detection
- URL intelligence
- Domain intelligence
- Header authentication analysis
- Optional GeoIP intelligence
- Explainable threat scoring
- Privacy sanitization
- Evidence sealing
- Tamper-evident forensic ledger
- SOC dashboard case retrieval

Run from project root:

    uvicorn backend.main:app --reload --port 8000

"""

import asyncio
import hashlib
import inspect
import os
import re
import uuid

from datetime import datetime, timezone
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import Any, Dict, List

import uvicorn

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    UploadFile,
)

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ================================================================
# IMPORTS
# ================================================================

try:

    from backend.compliance import IndiaPrivacyPreserver
    from backend.attachment_analyzer import AttachmentAnalyzer

    from backend.config import (
        APP_VERSION,
        DATABASE_PATH,
        GEOIP_ENABLED,
        MAX_EMAIL_SIZE_BYTES,
    )

    from backend.database import ForensicLedgerDB
    from backend.decision_engine import DecisionEngine
    from backend.domain_intel import DomainForensics
    from backend.geoip_mapper import GeoIPMapper
    from backend.header_analyzer import HeaderForensicAnalyzer
    from backend.llm_agent import ThreatExplainerAgent
    from backend.ml_classifier import LocalMLClassifier
    from backend.nlp_engine import NLPEngine
    from backend.parser import ForensicEmailParser
    from backend.threat_engine import ThreatScoringEngine

    try:
        from backend.url_analyzer import URLAnalyzer
    except Exception:
        URLAnalyzer = None

    try:
        from backend.evidence import create_evidence_seal
    except Exception:
        create_evidence_seal = None

except ImportError:

    from compliance import IndiaPrivacyPreserver
    from attachment_analyzer import AttachmentAnalyzer

    from config import (
        APP_VERSION,
        DATABASE_PATH,
        GEOIP_ENABLED,
        MAX_EMAIL_SIZE_BYTES,
    )

    from database import ForensicLedgerDB
    from decision_engine import DecisionEngine
    from domain_intel import DomainForensics
    from geoip_mapper import GeoIPMapper
    from header_analyzer import HeaderForensicAnalyzer
    from llm_agent import ThreatExplainerAgent
    from ml_classifier import LocalMLClassifier
    from nlp_engine import NLPEngine
    from parser import ForensicEmailParser
    from threat_engine import ThreatScoringEngine

    try:
        from url_analyzer import URLAnalyzer
    except Exception:
        URLAnalyzer = None

    try:
        from evidence import create_evidence_seal
    except Exception:
        create_evidence_seal = None


# ================================================================
# APPLICATION
# ================================================================

app = FastAPI(
    title="NETRA-Mail AI Threat Intelligence API",
    description=(
        "Explainable email phishing detection, "
        "forensic analysis, threat intelligence, "
        "privacy protection and tamper-evident evidence."
    ),
    version=str(APP_VERSION),
)


# ================================================================
# CORS
# ================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================================================================
# GLOBAL COMPONENTS
# ================================================================

parser = ForensicEmailParser()

try:
    db = ForensicLedgerDB(DATABASE_PATH)
except TypeError:
    db = ForensicLedgerDB()


# ================================================================
# REQUEST MODEL
# ================================================================

class EmailAnalysisRequest(BaseModel):

    subject: str = ""

    sender: str = ""

    recipient: str = ""

    reply_to: str = ""

    body: str = ""

    html: str = ""

    headers: str = ""

    received_headers: str = ""


# ================================================================
# GENERAL HELPERS
# ================================================================

def _now_iso() -> str:

    return datetime.now(
        timezone.utc
    ).isoformat()


def _normalize_score(
    value: Any,
) -> int:

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

        return 0


def _extract_domain(
    value: str,
) -> str:

    if not value:

        return ""

    match = re.search(
        r"@([A-Za-z0-9.-]+)",
        str(value),
    )

    if not match:

        return ""

    return (
        match.group(1)
        .lower()
        .strip(".")
    )


def _combine_email_text(
    subject: str = "",
    sender: str = "",
    body: str = "",
    html: str = "",
) -> str:

    return (
        f"{subject}\n"
        f"{sender}\n"
        f"{body}\n"
        f"{html}"
    ).strip()


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        if data and data.strip():
            self.parts.append(data.strip())


def _visible_html_text(html: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(html or "")
        parser.close()
        return " ".join(parser.parts)
    except Exception:
        return re.sub(r"<[^>]+>", " ", html or "")


def _safe_text_from_parsed(
    parsed: Dict[str, Any],
) -> str:

    body = parsed.get(
        "body",
        {},
    ) or {}

    metadata = parsed.get(
        "metadata",
        {},
    ) or {}

    return _combine_email_text(
        subject=str(
            metadata.get(
                "subject",
                "",
            )
        ),
        sender=str(
            metadata.get(
                "from",
                "",
            )
        ),
        body=str(
            body.get(
                "plain",
                "",
            )
        ),
        html=str(
            _visible_html_text(body.get("html", ""))
        ),
    )


# ================================================================
# DOMAIN EXTRACTION
# ================================================================

def _extract_domains(
    parsed: Dict[str, Any],
) -> List[Dict[str, str]]:

    domains = []

    seen = set()

    metadata = parsed.get(
        "metadata",
        {},
    ) or {}

    sources = [

        (
            metadata.get(
                "from",
                "",
            ),
            "from",
        ),

        (
            metadata.get(
                "reply_to",
                "",
            ),
            "reply_to",
        ),

        (
            metadata.get(
                "return_path",
                "",
            ),
            "return_path",
        ),

    ]

    for value, source in sources:

        domain = _extract_domain(
            value
        )

        if (
            domain
            and domain not in seen
        ):

            seen.add(domain)

            domains.append(
                {
                    "domain": domain,
                    "source": source,
                }
            )

    # ------------------------------------------------------------
    # URL HOSTNAMES
    # ------------------------------------------------------------

    try:

        from urllib.parse import urlparse

        for url in parsed.get(
            "urls",
            [],
        ) or []:

            try:

                hostname = (
                    urlparse(
                        str(url)
                    ).hostname
                    or ""
                ).lower()

                if (
                    hostname
                    and hostname not in seen
                ):

                    seen.add(hostname)

                    domains.append(
                        {
                            "domain": hostname,
                            "source": "url",
                        }
                    )

            except Exception:

                continue

    except Exception:

        pass

    # ------------------------------------------------------------
    # RECEIVED HOSTNAMES
    # ------------------------------------------------------------

    for hop in parsed.get(
        "network_chain",
        [],
    ) or []:

        raw_header = str(
            hop.get(
                "raw_header",
                "",
            )
        )

        matches = re.findall(
            r"\bfrom\s+([A-Za-z0-9._-]+)",
            raw_header,
            flags=re.IGNORECASE,
        )

        for hostname in matches:

            hostname = (
                hostname
                .lower()
                .strip(".")
            )

            if re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}",
                hostname,
            ):

                continue

            if (
                hostname
                and "." in hostname
                and hostname not in seen
            ):

                seen.add(hostname)

                domains.append(
                    {
                        "domain": hostname,
                        "source": "received",
                    }
                )

    return domains


# ================================================================
# NLP
# ================================================================

def _build_nlp_result(
    text: str,
) -> Dict[str, Any]:

    try:

        raw = NLPEngine.analyze_text(
            text or ""
        )

    except Exception as exc:

        return {

            "score": 0,

            "categories": {
                "urgency": [],
                "financial_fraud": [],
                "credential_harvesting": [],
                "social_engineering": [],
            },

            "matched_indicator_count": 0,

            "attack_classification": [],

            "risk_level": "LOW",

            "error": type(exc).__name__,

        }

    raw = raw or {}

    def get_category(
        primary: str,
        alternate: str,
    ) -> List[str]:

        value = raw.get(
            primary,
            raw.get(
                alternate,
                [],
            ),
        )

        if not isinstance(
            value,
            list,
        ):

            return []

        return sorted(
            set(
                str(x)
                for x in value
                if x
            )
        )

    raw_categories = raw.get("categories", raw)
    if not isinstance(raw_categories, dict):
        raw_categories = {}

    def get_raw_category(primary: str, alternate: str):
        value = raw_categories.get(primary, raw_categories.get(alternate, []))
        return value if isinstance(value, list) else []

    urgency = get_raw_category(
        "urgency",
        "urgency_cues",
    )

    financial = get_raw_category(
        "financial_fraud",
        "financial_fraud_cues",
    )

    credentials = get_raw_category(
        "credential_harvesting",
        "credential_harvesting_cues",
    )

    social = get_raw_category(
        "social_engineering",
        "social_engineering_cues",
    )

    categories = {

        "urgency":
            urgency,

        "financial_fraud":
            financial,

        "credential_harvesting":
            credentials,

        "social_engineering":
            social,

    }

    engine_score = raw.get(
        "score",
        None,
    )

    if engine_score is not None:

        score = _normalize_score(
            engine_score
        )

    else:

        score = 0

        score += min(
            25,
            len(urgency) * 5,
        )

        score += min(
            30,
            len(financial) * 7,
        )

        score += min(
            30,
            len(credentials) * 7,
        )

        score += min(
            20,
            len(social) * 5,
        )

        score = min(
            100,
            score,
        )

    normalized_text = text.lower()
    legitimate_reset_context = (
        "if you did not request" in normalized_text
        or "if you didn't request" in normalized_text
        or "if this was not you" in normalized_text
        or "if this wasn't you" in normalized_text
        or "if not, ignore" in normalized_text
        or "please ignore this email" in normalized_text
    )
    if legitimate_reset_context and not financial:
        score = min(score, 24)

    attack_classification = []

    if financial:

        attack_classification.append(
            "Financial Fraud / BEC"
        )

    if credentials:

        attack_classification.append(
            "Credential Phishing"
        )

    if social:

        attack_classification.append(
            "Social Engineering"
        )

    if (
        urgency
        and not attack_classification
    ):

        attack_classification.append(
            "Social Engineering"
        )

    matched_count = sum(
        len(values)
        for values in categories.values()
    )

    engine_risk = raw.get(
        "risk_level"
    )

    if engine_risk:

        risk_level = str(
            engine_risk
        ).upper()

    else:

        if score >= 60:

            risk_level = "HIGH"

        elif score >= 30:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

    return {

        "score":
            score,

        "categories":
            categories,

        "matched_indicator_count":
            matched_count,

        "attack_classification":
            list(
                dict.fromkeys(
                    attack_classification
                )
            ),

        "risk_level":
            risk_level,

        "raw_findings":
            raw,

    }


# ================================================================
# ML
# ================================================================

def _build_ml_result(
    text: str,
) -> Dict[str, Any]:

    try:

        raw = LocalMLClassifier.predict(
            text or ""
        )

    except Exception as exc:

        return {

            "classification":
                "UNKNOWN",

            "phishing_probability":
                0.0,

            "confidence":
                0.0,

            "model":
                "unavailable",

            "training_source":
                "error",

            "error":
                type(exc).__name__,

        }

    raw = raw or {}

    classification = str(
        raw.get(
            "ml_classification",
            raw.get(
                "classification",
                "UNKNOWN",
            ),
        )
    ).upper()

    confidence = raw.get(
        "confidence_score",
        raw.get(
            "confidence",
            0,
        ),
    )

    try:

        confidence = float(
            confidence
        )

    except Exception:

        confidence = 0.0

    confidence = max(
        0.0,
        min(
            100.0,
            confidence,
        ),
    )

    probability = raw.get(
        "phishing_probability",
        None,
    )

    if probability is not None:

        try:

            probability = float(
                probability
            )

        except Exception:

            probability = None

    if probability is None:

        if classification == "PHISHING":

            probability = (
                confidence / 100.0
            )

        else:

            probability = (
                1.0
                - confidence / 100.0
            )

    probability = max(
        0.0,
        min(
            1.0,
            probability,
        ),
    )

    return {

        "classification":
            classification,

        "phishing_probability":
            round(
                probability,
                4,
            ),

        "confidence":
            round(
                confidence,
                2,
            ),

        "model":
            raw.get(
                "model",
                "Local TF-IDF classifier",
            ),

        "training_source":
            raw.get(
                "training_source",
                "local trained model",
            ),

    }


# ================================================================
# DOMAIN INTELLIGENCE
# ================================================================

def _build_domain_result(
    parsed: Dict[str, Any],
) -> Dict[str, Any]:

    domains = _extract_domains(
        parsed
    )

    # ------------------------------------------------------------
    # Dedicated domain engine
    # ------------------------------------------------------------

    if hasattr(
        DomainForensics,
        "inspect_domains",
    ):

        try:

            result = (
                DomainForensics.inspect_domains(
                    domains
                )
            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except Exception:

            pass

    inspected = []

    for item in domains:

        domain = item.get(
            "domain",
            "",
        )

        if not domain:

            continue

        try:

            results = (
                DomainForensics.inspect_urls(
                    [
                        f"https://{domain}"
                    ]
                )
            )

            if results:

                result = results[0]

                analysis = result.get(
                    "analysis",
                    {},
                ) or {}

                risk_score = _normalize_score(
                    analysis.get(
                        "risk_score",
                        0,
                    )
                )

                if risk_score >= 70:

                    risk_level = "CRITICAL"

                elif risk_score >= 50:

                    risk_level = "HIGH"

                elif risk_score >= 30:

                    risk_level = "MEDIUM"

                else:

                    risk_level = "LOW"

                impersonated_brand = (
                    analysis.get(
                        "impersonated_brand"
                    )
                )

                inspected.append(
                    {

                        "domain":
                            domain,

                        "source":
                            item.get(
                                "source",
                                "unknown",
                            ),

                        "valid":
                            True,

                        "registered_domain":
                            domain,

                        "is_punycode":
                            analysis.get(
                                "is_punycode",
                                False,
                            ),

                        "has_suspicious_tld":
                            analysis.get(
                                "has_suspicious_tld",
                                False,
                            ),

                        "impersonated_brand":
                            impersonated_brand,

                        "impersonated_brands":
                            (
                                [impersonated_brand]
                                if impersonated_brand
                                else []
                            ),

                        "typosquatting":
                            analysis.get(
                                "typosquatting",
                                [],
                            ),

                        "resolves":
                            analysis.get(
                                "resolves",
                                False,
                            ),

                        "resolved_ip":
                            analysis.get(
                                "resolved_ip"
                            ),

                        "risk_score":
                            risk_score,

                        "risk_level":
                            risk_level,

                        "reasons":
                            analysis.get(
                                "reasons",
                                [],
                            ),

                    }
                )

        except Exception as exc:

            inspected.append(
                {

                    "domain":
                        domain,

                    "source":
                        item.get(
                            "source",
                            "unknown",
                        ),

                    "valid":
                        True,

                    "risk_score":
                        0,

                    "risk_level":
                        "LOW",

                    "reasons":
                        [
                            (
                                "Domain analysis "
                                f"unavailable: "
                                f"{type(exc).__name__}"
                            )
                        ],

                }
            )

    highest = max(
        (
            item.get(
                "risk_score",
                0,
            )
            for item in inspected
        ),
        default=0,
    )

    brands = []

    typosquatting = []

    reasons = []

    for item in inspected:

        brand = item.get(
            "impersonated_brand"
        )

        if (
            brand
            and brand not in brands
        ):

            brands.append(
                brand
            )

        for brand_item in item.get(
            "impersonated_brands",
            [],
        ) or []:

            if (
                brand_item
                and brand_item not in brands
            ):

                brands.append(
                    brand_item
                )

        for typo in item.get(
            "typosquatting",
            [],
        ) or []:

            if typo not in typosquatting:

                typosquatting.append(
                    typo
                )

        for reason in item.get(
            "reasons",
            [],
        ) or []:

            if reason not in reasons:

                reasons.append(
                    reason
                )

    if highest >= 70:

        overall_risk = "CRITICAL"

    elif highest >= 50:

        overall_risk = "HIGH"

    elif highest >= 30:

        overall_risk = "MEDIUM"

    else:

        overall_risk = "LOW"

    return {

        "total_domains":
            len(domains),

        "highest_risk_score":
            highest,

        "overall_risk":
            overall_risk,

        "impersonated_brands":
            brands,

        "typosquatting_detected":
            typosquatting,

        "reasons":
            reasons,

        "domains":
            inspected,

    }


# ================================================================
# URL INTELLIGENCE
# ================================================================

def _build_url_result(
    parsed: Dict[str, Any],
) -> Dict[str, Any]:

    urls = parsed.get(
        "urls",
        [],
    ) or []

    body = parsed.get(
        "body",
        {},
    ) or {}

    combined_text = (

        str(
            body.get(
                "plain",
                "",
            )
        )

        + "\n"

        + str(
            body.get(
                "html",
                "",
            )
        )

    )

    if URLAnalyzer is not None:

        try:

            result = (
                URLAnalyzer.analyze_text(
                    combined_text
                )
            )

            if isinstance(
                result,
                dict,
            ):

                if (
                    result.get(
                        "total_urls",
                        0,
                    ) > 0
                    or not urls
                ):

                    if os.getenv("NETRA_EXPAND_SHORT_URLS", "0") == "1":
                        from backend.url_expander import URLExpander

                        expansions = []
                        for item in result.get("urls", []):
                            if not item.get("is_shortener"):
                                continue
                            expansion = URLExpander.expand(item.get("url", ""))
                            expansions.append(expansion)
                            final_url = expansion.get("final_url", "")
                            if expansion.get("expanded") and final_url:
                                final_analysis = URLAnalyzer.analyze_url(final_url)
                                item["expanded_url"] = final_url
                                item["redirect_chain"] = expansion.get("redirect_chain", [])
                                item["expanded_analysis"] = final_analysis
                                item["risk_score"] = max(
                                    item.get("risk_score", 0),
                                    final_analysis.get("risk_score", 0),
                                )
                            else:
                                item["expansion_error"] = expansion.get("error", "not_expanded")
                        result["url_expansions"] = expansions
                        if expansions:
                            result["summary"]["reasons"].append(
                                "Shortened URL expansion was attempted with bounded HEAD requests"
                            )

                    return result

        except Exception:

            pass

    try:

        inspected = (
            DomainForensics.inspect_urls(
                urls
            )
        )

    except Exception:

        inspected = []

    highest = max(
        (
            item.get(
                "analysis",
                {},
            ).get(
                "risk_score",
                0,
            )
            for item in inspected
            if isinstance(
                item,
                dict,
            )
        ),
        default=0,
    )

    brands = []

    typosquatting = []

    for item in inspected:

        analysis = item.get(
            "analysis",
            {},
        ) or {}

        brand = analysis.get(
            "impersonated_brand"
        )

        if brand:

            brands.append(
                str(brand)
            )

        typo = analysis.get(
            "typosquatting",
            [],
        )

        if isinstance(
            typo,
            list,
        ):

            typosquatting.extend(
                typo
            )

    if highest >= 70:

        overall_risk = "CRITICAL"

    elif highest >= 50:

        overall_risk = "HIGH"

    elif highest >= 30:

        overall_risk = "MEDIUM"

    else:

        overall_risk = "LOW"

    return {

        "total_urls":
            len(inspected),

        "urls":
            inspected,

        "summary": {

            "suspicious_urls":
                sum(
                    1
                    for item in inspected
                    if item.get(
                        "analysis",
                        {},
                    ).get(
                        "risk_score",
                        0,
                    ) >= 30
                ),

            "highest_url_score":
                highest,

            "impersonated_brands":
                list(
                    dict.fromkeys(
                        brands
                    )
                ),

            "typosquatting_detected":
                list(
                    dict.fromkeys(
                        typosquatting
                    )
                ),

            "overall_risk":
                overall_risk,

        },

    }


# ================================================================
# GEOIP / INFRASTRUCTURE
# ================================================================

def _get_infrastructure(
    parsed: Dict[str, Any],
    authentication: Dict[str, Any],
    enabled: bool = True,
) -> Dict[str, Any]:

    origin_ip = authentication.get(
        "originating_ip"
    )

    if not origin_ip:

        chain = parsed.get(
            "network_chain",
            [],
        ) or []

        if chain:

            origin_ip = chain[0].get(
                "originating_ip"
            )

    base = {

        "ip":
            origin_ip,

        "available":
            False,

        "country":
            "Unknown",

        "city":
            "Unknown",

        "latitude":
            0.0,

        "longitude":
            0.0,

        "isp":
            "Unknown",

        "organization":
            "Unknown",

        "asn":
            "Unknown",

        "timezone":
            "Unknown",

        "is_cloud_vps":
            False,

    }

    if not origin_ip:

        return base

    if (
        not enabled
        or not GEOIP_ENABLED
    ):

        return base

    try:

        intel = GeoIPMapper.get_ip_intel(
            origin_ip
        )

        if intel:

            return intel

    except Exception:

        pass

    return base


# ================================================================
# EVIDENCE
# ================================================================

def _build_evidence(
    header: Dict[str, Any],
    nlp: Dict[str, Any],
    ml: Dict[str, Any],
    domain: Dict[str, Any],
    url: Dict[str, Any],
    infrastructure: Dict[str, Any],
    decision: Dict[str, Any],
) -> List[str]:

    evidence = []

    # ------------------------------------------------------------
    # DOMAIN
    # ------------------------------------------------------------

    for brand in domain.get(
        "impersonated_brands",
        [],
    ) or []:

        evidence.append(
            f"Brand impersonation: {brand}"
        )

    for reason in domain.get(
        "reasons",
        [],
    ) or []:

        evidence.append(
            str(reason)
        )

    # ------------------------------------------------------------
    # URL
    # ------------------------------------------------------------

    url_summary = (
        url.get(
            "summary",
            {},
        )
        or {}
    )

    if url_summary.get(
        "suspicious_urls",
        0,
    ):

        evidence.append(
            "Suspicious URLs detected: "
            + str(
                url_summary.get(
                    "suspicious_urls",
                    0,
                )
            )
        )

    for brand in url_summary.get(
        "impersonated_brands",
        [],
    ) or []:

        evidence.append(
            f"URL brand impersonation: {brand}"
        )

    # ------------------------------------------------------------
    # NLP
    # ------------------------------------------------------------

    categories = (
        nlp.get(
            "categories",
            {},
        )
        or {}
    )

    for category_name, values in categories.items():

        if not isinstance(
            values,
            list,
        ):

            continue

        for value in values:

            evidence.append(
                (
                    f"{category_name.replace('_', ' ').title()}: "
                    f"{value}"
                )
            )

    # ------------------------------------------------------------
    # ML
    # ------------------------------------------------------------

    classification = str(
        ml.get(
            "classification",
            "",
        )
    ).upper()

    probability = ml.get(
        "phishing_probability"
    )

    if classification == "PHISHING":

        evidence.append(
            "ML classifier identified phishing."
        )

        if probability is not None:

            try:

                evidence.append(
                    "ML phishing probability is "
                    f"{float(probability) * 100:.1f}%."
                )

            except Exception:

                pass

    # ------------------------------------------------------------
    # AUTHENTICATION
    # ------------------------------------------------------------

    authentication = (
        header.get(
            "authentication",
            {},
        )
        or {}
    )

    for auth_name in [
        "spf",
        "dkim",
        "dmarc",
    ]:

        status = str(
            authentication.get(
                auth_name,
                "none",
            )
        ).upper()

        if status in {
            "NONE",
            "FAIL",
            "SOFTFAIL",
        }:

            evidence.append(
                f"{auth_name.upper()} "
                f"authentication result: {status}"
            )

    # ------------------------------------------------------------
    # HEADER INDICATORS
    # ------------------------------------------------------------

    for indicator in header.get(
        "indicators",
        [],
    ) or []:

        evidence.append(
            str(indicator)
        )

    # ------------------------------------------------------------
    # INFRASTRUCTURE
    # ------------------------------------------------------------

    if infrastructure.get(
        "ip"
    ):

        evidence.append(
            "Originating IP: "
            + str(
                infrastructure.get(
                    "ip"
                )
            )
        )

    if infrastructure.get(
        "is_cloud_vps",
        False,
    ):

        evidence.append(
            "Origin infrastructure appears "
            "to use cloud/VPS hosting."
        )

    # ------------------------------------------------------------
    # DECISION
    # ------------------------------------------------------------

    for reason in decision.get(
        "reasons",
        [],
    ) or []:

        evidence.append(
            str(reason)
        )

    return list(
        dict.fromkeys(
            evidence
        )
    )


# ================================================================
# EVIDENCE SEAL
# ================================================================

def _create_seal(
    raw: bytes,
    evidence: List[str],
) -> Dict[str, Any]:

    if create_evidence_seal is not None:

        try:

            result = create_evidence_seal(
                raw
            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except Exception:

            pass

    evidence_bytes = (
        "\n".join(
            evidence
        ).encode(
            "utf-8",
            errors="ignore",
        )
    )

    return {

        "sha256_hash":
            hashlib.sha256(
                evidence_bytes
            ).hexdigest(),

        "byte_size":
            len(
                evidence_bytes
            ),

        "sealed_at":
            _now_iso(),

        "encoding":
            "utf-8",

    }


# ================================================================
# THREAT SCORING
# ================================================================

def _run_threat_scoring(
    authentication: Dict[str, Any],
    url: Dict[str, Any],
    nlp: Dict[str, Any],
    ml: Dict[str, Any],
    domain: Dict[str, Any],
    infrastructure: Dict[str, Any],
    attachments: Dict[str, Any] = None,
) -> Dict[str, Any]:

    evaluate = getattr(
        ThreatScoringEngine,
        "evaluate",
        None,
    )

    if evaluate is None:

        return {

            "threat_score":
                0,

            "score":
                0,

            "severity":
                "SAFE",

            "confidence":
                0,

        }

    # ------------------------------------------------------------
    # Current engine
    # ------------------------------------------------------------

    try:

        signature = inspect.signature(
            evaluate
        )

        parameters = signature.parameters

        if "header_res" in parameters:

            result = evaluate(

                header_res=
                    authentication,

                url_res=
                    url,

                nlp_res=
                    nlp,

                ml_res=
                    ml,

                domain_res=
                    domain,

                infrastructure=
                    infrastructure,

                attachment_res=
                    attachments or {},

            )

            if isinstance(
                result,
                dict,
            ):

                return result

    except Exception:

        pass

    # ------------------------------------------------------------
    # Legacy positional engine
    # ------------------------------------------------------------

    try:

        nlp_score = (
            _normalize_score(
                nlp.get(
                    "score",
                    0,
                )
            )
            / 100.0
        )

        ml_score = ml.get(
            "phishing_probability",
            0,
        )

        try:

            ml_score = float(
                ml_score
            )

        except Exception:

            ml_score = 0.0

        result = evaluate(

            authentication,

            url.get(
                "urls",
                [],
            ),

            nlp_score,

            ml_score,

        )

        if isinstance(
            result,
            dict,
        ):

            return result

    except Exception:

        pass

    # ------------------------------------------------------------
    # Modern keyword engine
    # ------------------------------------------------------------

    try:

        result = evaluate(

            ml=
                ml,

            nlp=
                nlp,

            url=
                url,

            domain=
                domain,

            authentication=
                authentication,

            infrastructure=
                infrastructure,

        )

        if isinstance(
            result,
            dict,
        ):

            return result

    except Exception as exc:

        return {

            "threat_score":
                0,

            "score":
                0,

            "severity":
                "SAFE",

            "confidence":
                0,

            "error":
                type(exc).__name__,

        }

    return {

        "threat_score":
            0,

        "score":
            0,

        "severity":
            "SAFE",

        "confidence":
            0,

    }


# ================================================================
# DECISION ENGINE
# ================================================================

def _run_decision_engine(
    scoring: Dict[str, Any],
    nlp: Dict[str, Any],
    ml: Dict[str, Any],
    domain: Dict[str, Any],
    url: Dict[str, Any],
    authentication: Dict[str, Any],
    infrastructure: Dict[str, Any],
) -> Dict[str, Any]:

    decide = getattr(
        DecisionEngine,
        "decide",
        None,
    )

    if decide is not None:

        try:

            result = decide(

                scoring=
                    scoring,

                nlp_analysis=
                    nlp,

                ml_analysis=
                    ml,

                domain_analysis=
                    domain,

                url_analysis=
                    url,

                header_analysis=
                    authentication,

                infrastructure=
                    infrastructure,

            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except TypeError:

            pass

        except Exception:

            pass

    evaluate = getattr(
        DecisionEngine,
        "evaluate",
        None,
    )

    if evaluate is not None:

        try:

            result = evaluate(

                scoring,

                nlp_analysis=
                    nlp,

                ml_analysis=
                    ml,

                domain_analysis=
                    domain,

                url_analysis=
                    url,

                header_analysis=
                    authentication,

                infrastructure=
                    infrastructure,

            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except TypeError:

            pass

        except Exception:

            pass

        try:

            result = evaluate(

                score_result=
                    scoring,

                ml=
                    ml,

                nlp=
                    nlp,

                url=
                    url,

                domain=
                    domain,

                auth=
                    authentication,

                infrastructure=
                    infrastructure,

            )

            if isinstance(
                result,
                dict,
            ):

                return result

        except Exception:

            pass

    # ------------------------------------------------------------
    # Local fallback
    # ------------------------------------------------------------

    score = _normalize_score(

        scoring.get(
            "threat_score",
            scoring.get(
                "score",
                scoring.get(
                    "total",
                    0,
                ),
            ),
        )

    )

    confidence = _normalize_score(

        scoring.get(
            "confidence",
            ml.get(
                "confidence",
                0,
            ),
        )

    )

    if score >= 75:

        risk = "CRITICAL"

        action = "BLOCK"

    elif score >= 50:

        risk = "HIGH"

        action = "QUARANTINE"

    elif score >= 25:

        risk = "LOW"

        action = "REVIEW"

    else:

        risk = "SAFE"

        action = "ALLOW"

    reasons = []

    if nlp.get(
        "matched_indicator_count",
        0,
    ):

        reasons.append(
            "Suspicious linguistic indicators detected."
        )

    if ml.get(
        "classification",
        "",
    ).upper() == "PHISHING":

        reasons.append(
            "Machine-learning classifier identified phishing."
        )

    if domain.get(
        "impersonated_brands",
        [],
    ):

        reasons.append(
            "Brand impersonation detected."
        )

    if not reasons:

        reasons.append(
            "No significant phishing indicators were identified."
        )

    return {

        "risk":
            risk,

        "score":
            score,

        "action":
            action,

        "confidence":
            confidence,

        "reasons":
            list(
                dict.fromkeys(
                    reasons
                )
            ),

        "attack_classification":
            [],

    }


# ================================================================
# CORE ANALYSIS
# ================================================================

async def _analyze_parsed_email(
    parsed: Dict[str, Any],
    raw: bytes,
    filename: str,
    live_mode: bool = False,
) -> Dict[str, Any]:

    case_id = (
        "NETRA-"
        + uuid.uuid4().hex[:8].upper()
    )

    # ------------------------------------------------------------
    # PRIVACY
    # ------------------------------------------------------------

    try:

        sanitized = (
            IndiaPrivacyPreserver.sanitize_payload(
                parsed
            )
        )

    except Exception:

        sanitized = parsed

    # ------------------------------------------------------------
    # TEXT
    # ------------------------------------------------------------

    text = _safe_text_from_parsed(
        sanitized
    )

    # ------------------------------------------------------------
    # HEADER ANALYSIS
    # ------------------------------------------------------------

    try:

        authentication = (
            HeaderForensicAnalyzer.analyze(
                parsed
            )
        )

    except Exception as exc:

        authentication = {

            "authentication": {

                "spf":
                    "none",

                "dkim":
                    "none",

                "dmarc":
                    "none",

            },

            "alignment": {

                "from_domain":
                    "",

                "reply_to_domain":
                    "",

                "return_path_domain":
                    "",

                "has_mismatch":
                    False,

            },

            "originating_ip":
                None,

            "hop_count":
                0,

            "header_risk_score":
                0,

            "indicators":
                [
                    (
                        "Header analysis unavailable: "
                        f"{type(exc).__name__}"
                    )
                ],

        }

    # ------------------------------------------------------------
    # PARALLEL ANALYSIS
    #
    # Important:
    # These operations are independent, so they execute together.
    # This keeps Gmail response latency low.
    # ------------------------------------------------------------

    nlp_task = asyncio.to_thread(
        _build_nlp_result,
        text,
    )

    ml_task = asyncio.to_thread(
        _build_ml_result,
        text,
    )

    url_task = asyncio.to_thread(
        _build_url_result,
        parsed,
    )

    domain_task = asyncio.to_thread(
        _build_domain_result,
        parsed,
    )

    # For Gmail live analysis, GeoIP can be expensive.
    # We still keep the infrastructure field in the result,
    # but allow it to be skipped when necessary.
    infrastructure_task = asyncio.to_thread(
        _get_infrastructure,
        parsed,
        authentication,
        True,
    )

    attachment_analysis = AttachmentAnalyzer.analyze(
        parsed.get("attachments", []) or []
    )

    (
        nlp,
        ml,
        url,
        domain,
        infrastructure,
    ) = await asyncio.gather(

        nlp_task,

        ml_task,

        url_task,

        domain_task,

        infrastructure_task,

    )

    # ------------------------------------------------------------
    # THREAT SCORING
    # ------------------------------------------------------------

    scoring = _run_threat_scoring(

        authentication=
            authentication,

        url=
            url,

        nlp=
            nlp,

        ml=
            ml,

        domain=
            domain,

        infrastructure=
            infrastructure,

        attachments=
            attachment_analysis,

    )

    scoring = scoring or {}

    # ------------------------------------------------------------
    # DECISION
    # ------------------------------------------------------------

    decision = _run_decision_engine(

        scoring=
            scoring,

        nlp=
            nlp,

        ml=
            ml,

        domain=
            domain,

        url=
            url,

        authentication=
            authentication,

        infrastructure=
            infrastructure,

    )

    decision = decision or {}

    attachment_reasons = []
    for finding in attachment_analysis.get("attachments", []):
        attachment_reasons.extend(finding.get("reasons", []))
    if attachment_reasons:
        decision["reasons"] = list(dict.fromkeys(
            list(decision.get("reasons", []))
            + attachment_reasons
        ))

    # ------------------------------------------------------------
    # REDACTIONS
    # ------------------------------------------------------------

    try:

        redactions = (
            IndiaPrivacyPreserver.extract_redaction_findings(
                text
            )
        )

    except Exception:

        redactions = []

    # ------------------------------------------------------------
    # EVIDENCE
    # ------------------------------------------------------------

    evidence = _build_evidence(

        header=
            authentication,

        nlp=
            nlp,

        ml=
            ml,

        domain=
            domain,

        url=
            url,

        infrastructure=
            infrastructure,

        decision=
            decision,

    )

    # ------------------------------------------------------------
    # EVIDENCE SEAL
    # ------------------------------------------------------------

    evidence_seal = _create_seal(

        raw,

        evidence,

    )

    # ------------------------------------------------------------
    # FINAL SCORE
    # ------------------------------------------------------------

    threat_score = _normalize_score(

        scoring.get(
            "threat_score",
            scoring.get(
                "score",
                scoring.get(
                    "total",
                    decision.get(
                        "score",
                        0,
                    ),
                ),
            ),
        )

    )

    # ------------------------------------------------------------
    # FINAL SEVERITY
    # ------------------------------------------------------------

    severity = str(

        decision.get(

            "risk",

            scoring.get(

                "severity",

                "UNKNOWN",

            ),

        )

    ).upper()

    if severity in {
        "SAFE",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:

        pass

    else:

        if threat_score >= 75:

            severity = "CRITICAL"

        elif threat_score >= 50:

            severity = "HIGH"

        elif threat_score >= 25:

            severity = "LOW"

        else:

            severity = "SAFE"

    # ------------------------------------------------------------
    # AI EXPLANATION
    #
    # IMPORTANT:
    # For Gmail we use the local rule-based explanation.
    # We do not call an external/slow LLM.
    #
    # ------------------------------------------------------------

    ai_explanation = (

        f"Assessment: {severity} "
        f"({threat_score}/100).\n"

        f"Recommended action: "
        f"{decision.get('action', 'REVIEW')}.\n"

        "Assessment based on multiple "
        "independent threat signals."

    )

    # ------------------------------------------------------------
    # Full forensic explanation
    # ------------------------------------------------------------

    explanation_payload = {

        "case_id":
            case_id,

        "threat_score":
            threat_score,

        "severity":
            severity,

        "decision":
            decision,

        "header_analysis":
            authentication,

        "nlp_analysis":
            nlp,

        "ml_analysis":
            ml,

        "domain_analysis":
            domain,

        "url_analysis":
            url,

        "infrastructure":
            infrastructure,

        "attachments":
            attachment_analysis,

        "evidence":
            evidence,

        "redacted_metadata":
            sanitized.get(
                "metadata",
                {},
            ),

    }

    # Only use the local explainer when available.
    # The current llm_agent.py is local/rule based, so this
    # should be fast, but keep a safe fallback.

    try:

        ai_explanation = (
            ThreatExplainerAgent.explain(
                explanation_payload
            )
        )

    except Exception:

        pass

    # ------------------------------------------------------------
    # FORENSIC PAYLOAD
    # ------------------------------------------------------------

    forensic_payload = {

        "case_id":
            case_id,

        "decision":
            decision,

        "threat_score":
            threat_score,

        "severity":
            severity,

        "confidence":
            decision.get(
                "confidence",
                scoring.get(
                    "confidence",
                    0,
                ),
            ),

        "authentication":
            authentication,

        "nlp_analysis":
            nlp,

        "ml_analysis":
            ml,

        "url_intelligence":
            url,

        "domain_intelligence":
            domain,

        "infrastructure":
            infrastructure,

        "evidence":
            evidence,

        "evidence_seal":
            evidence_seal,

        "ai_explanation":
            ai_explanation,

        "redacted_metadata":
            sanitized.get(
                "metadata",
                {},
            ),

        "live_gmail":
            live_mode,

        "analyzed_at":
            _now_iso(),

    }

    # ------------------------------------------------------------
    # CRITICAL FIX
    #
    # OLD VERSION:
    #
    #     if not live_mode:
    #         db.record_evidence(...)
    #
    # That caused:
    #
    # Gmail -> generated case ID
    # SOC -> requested case ID
    # DB -> case did not exist -> 404
    #
    # NEW VERSION:
    #
    # EVERY analysis gets recorded.
    #
    # This makes Gmail -> SOC case linking work.
    # ------------------------------------------------------------

    block_hash = None

    ledger_error = None

    try:

        block_hash = db.record_evidence(

            case_id=
                case_id,

            raw_sha256=
                parsed.get(
                    "raw_sha256",
                    hashlib.sha256(
                        raw
                    ).hexdigest(),
                ),

            threat_score=
                threat_score,

            verdict=
                decision.get(
                    "risk",
                    severity,
                ),

            forensic_data=
                forensic_payload,

        )

    except Exception as exc:

        ledger_error = (
            f"{type(exc).__name__}: {exc}"
        )

        forensic_payload[
            "ledger_error"
        ] = ledger_error

    # ------------------------------------------------------------
    # METADATA
    # ------------------------------------------------------------

    metadata = parsed.get(
        "metadata",
        {},
    ) or {}

    clean_metadata = (
        sanitized.get(
            "metadata",
            {},
        )
        or {}
    )

    # ------------------------------------------------------------
    # RESPONSE
    # ------------------------------------------------------------

    return {

        "status":
            "SUCCESS",

        "case_id":
            case_id,

        "decision":
            decision,

        "email": {

            "filename":
                filename,

            "subject":
                clean_metadata.get(
                    "subject",
                    metadata.get(
                        "subject",
                        "",
                    ),
                ),

            "sender":
                clean_metadata.get(
                    "from",
                    "",
                ),

            "recipient":
                clean_metadata.get(
                    "to",
                    "",
                ),

            "reply_to":
                clean_metadata.get(
                    "reply_to",
                    "",
                ),

            "attachment_count":
                len(
                    parsed.get(
                        "attachments",
                        [],
                    )
                ),

        },

        "authentication":
            authentication,

        "nlp_analysis":
            nlp,

        "ml_analysis":
            ml,

        "url_intelligence":
            url,

        "domain_intelligence":
            domain,

        "infrastructure":
            infrastructure,

        "threat_score":
            scoring,

        "evidence":
            evidence,

        "ai_explanation":
            ai_explanation,

        "evidence_seal":
            evidence_seal,

        "privacy": {

            "redactions":
                redactions,

            "sanitized":
                True,

        },

        "attachments":
            parsed.get(
                "attachments",
                [],
            ),

        "attachment_analysis":
            attachment_analysis,

        "network_chain":
            parsed.get(
                "network_chain",
                [],
            ),

        "block_hash":
            block_hash,

        "ledger_error":
            ledger_error,

        "analyzed_at":
            _now_iso(),

        # --------------------------------------------------------
        # Extension-friendly result
        # --------------------------------------------------------

        "netra_result": {

            "score":
                threat_score,

            "risk":
                decision.get(
                    "risk",
                    severity,
                ),

            "action":
                decision.get(
                    "action",
                    "REVIEW",
                ),

            "confidence":
                decision.get(
                    "confidence",
                    scoring.get(
                        "confidence",
                        0,
                    ),
                ),

            "case_id":
                case_id,

        },

    }


# ================================================================
# ROOT
# ================================================================

@app.get("/")
async def root():

    return {

        "name":
            "NETRA-Mail",

        "version":
            str(APP_VERSION),

        "status":
            "ONLINE",

        "mode":
            "LOCAL",

        "extension":
            "ENABLED",

        "soc":
            "ENABLED",

        "endpoints": {

            "health":
                "/health",

            "eml_analysis":
                "POST /api/v1/analyze/eml",

            "gmail_analysis":
                "POST /api/v1/analyze/email",

            "gmail_text_analysis":
                "POST /api/v1/analyze/text",

            "forensic_case":
                "GET /api/v1/forensics/case/{case_id}",

            "audit":
                "GET /api/v1/forensics/audit",

        },

    }


# ================================================================
# HEALTH
# ================================================================

@app.get("/health")
async def health():

    # ------------------------------------------------------------
    # ML MODEL
    # ------------------------------------------------------------

    try:

        model_path = getattr(
            LocalMLClassifier,
            "MODEL_PATH",
            None,
        )

        if hasattr(
            model_path,
            "exists",
        ):

            model_available = (
                model_path.exists()
            )

        else:

            model_available = bool(
                model_path
                and os.path.exists(
                    str(model_path)
                )
            )

    except Exception:

        model_available = False

    # ------------------------------------------------------------
    # LEDGER
    # ------------------------------------------------------------

    try:

        ledger = (
            db.verify_chain_integrity()
        )

    except Exception as exc:

        ledger = {

            "status":
                "ERROR",

            "valid":
                False,

            "error":
                type(exc).__name__,

        }

    return {

        "status":
            "healthy",

        "version":
            str(APP_VERSION),

        "mode":
            "LOCAL",

        "extension_api":
            True,

        "soc_api":
            True,

        "model_available":
            model_available,

        "ledger":
            ledger,

    }


# ================================================================
# EML ANALYSIS
# ================================================================

@app.post(
    "/api/v1/analyze/eml"
)
async def analyze_eml_file(
    file: UploadFile = File(...),
):

    if not file.filename:

        raise HTTPException(

            status_code=400,

            detail=
                "A filename is required.",

        )

    filename = file.filename

    if not filename.lower().endswith(
        ".eml"
    ):

        raise HTTPException(

            status_code=400,

            detail=
                "Only .eml files are supported.",

        )

    raw = await file.read()

    if not raw:

        raise HTTPException(

            status_code=400,

            detail=
                "Uploaded email is empty.",

        )

    if len(raw) > MAX_EMAIL_SIZE_BYTES:

        raise HTTPException(

            status_code=413,

            detail=(
                "Email exceeds configured maximum "
                f"size of {MAX_EMAIL_SIZE_BYTES} bytes."
            ),

        )

    try:

        parsed = await asyncio.to_thread(
            parser.parse_eml_bytes,
            raw,
        )

        return await _analyze_parsed_email(

            parsed=
                parsed,

            raw=
                raw,

            filename=
                filename,

            live_mode=
                False,

        )

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# DIRECT GMAIL ANALYSIS
# ================================================================
#
# This is the endpoint used by content.js.
#
# Gmail sends:
#
# {
#     subject,
#     sender,
#     recipient,
#     reply_to,
#     body,
#     html,
#     headers,
#     received_headers
# }
#
# No .EML upload is required.
#
# ================================================================

@app.post(
    "/api/v1/analyze/email"
)
async def analyze_direct_email(
    request: EmailAnalysisRequest,
):

    if not any(

        [
            request.subject,
            request.sender,
            request.body,
            request.html,
        ]

    ):

        raise HTTPException(

            status_code=400,

            detail=
                "Email content is empty.",

        )

    try:

        message = EmailMessage()

        # --------------------------------------------------------
        # Basic headers
        # --------------------------------------------------------

        if request.subject:

            message["Subject"] = (
                request.subject
            )

        if request.sender:

            message["From"] = (
                request.sender
            )

        if request.recipient:

            message["To"] = (
                request.recipient
            )

        if request.reply_to:

            message["Reply-To"] = (
                request.reply_to
            )

        # --------------------------------------------------------
        # Extra headers
        # --------------------------------------------------------

        combined_headers = []

        if request.headers:

            combined_headers.append(
                request.headers
            )

        if request.received_headers:

            combined_headers.append(
                request.received_headers
            )

        for line in "\n".join(
            combined_headers
        ).splitlines():

            if ":" not in line:

                continue

            key, value = line.split(
                ":",
                1,
            )

            key = key.strip()

            value = value.strip()

            if not key:

                continue

            if key.lower() in {

                "subject",
                "from",
                "to",
                "reply-to",

            }:

                continue

            try:

                message[key] = value

            except Exception:

                pass

        # --------------------------------------------------------
        # Body
        # --------------------------------------------------------

        message.set_content(
            request.body or ""
        )

        if request.html:

            try:

                message.add_alternative(

                    request.html,

                    subtype="html",

                )

            except Exception:

                pass

        # --------------------------------------------------------
        # MIME BYTES
        # --------------------------------------------------------

        raw = message.as_bytes()

        parsed = await asyncio.to_thread(

            parser.parse_eml_bytes,

            raw,

        )

        # --------------------------------------------------------
        # COMPLETE LIVE ANALYSIS
        #
        # IMPORTANT:
        # live_mode no longer prevents ledger storage.
        # --------------------------------------------------------

        return await _analyze_parsed_email(

            parsed=
                parsed,

            raw=
                raw,

            filename=
                "gmail-live-analysis.eml",

            live_mode=
                True,

        )

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# TEXT COMPATIBILITY ENDPOINT
# ================================================================

@app.post(
    "/api/v1/analyze/text"
)
async def analyze_text_email(
    request: EmailAnalysisRequest,
):

    return await analyze_direct_email(
        request
    )


# ================================================================
# FORENSIC CASE REPORT
# ================================================================
#
# THIS IS THE ENDPOINT USED BY THE SOC DASHBOARD.
#
# It uses db.get_case() first because that guarantees we use the
# exact same database object/configuration that recorded the case.
#
# A SQLite fallback is also provided for compatibility with older
# database.py implementations.
#
# ================================================================

@app.get(
    "/api/v1/forensics/case/{case_id}"
)
async def get_forensic_case(
    case_id: str,
):

    case_id = case_id.strip()

    if not case_id:

        raise HTTPException(

            status_code=400,

            detail=
                "Case ID is required.",

        )

    # ------------------------------------------------------------
    # PRIMARY METHOD: DATABASE CLASS
    # ------------------------------------------------------------

    try:

        get_case = getattr(
            db,
            "get_case",
            None,
        )

        if callable(
            get_case
        ):

            record = get_case(
                case_id
            )

            if record:

                payload = (
                    record.get(
                        "forensic_payload",
                        {},
                    )
                    or {}
                )

                return {

                    "status":
                        "SUCCESS",

                    "case_id":
                        case_id,

                    "report":
                        payload,

                    "ledger": {

                        "id":
                            record.get(
                                "id"
                            ),

                        "timestamp":
                            record.get(
                                "timestamp"
                            ),

                        "raw_sha256":
                            record.get(
                                "raw_sha256"
                            ),

                        "threat_score":
                            record.get(
                                "threat_score"
                            ),

                        "verdict":
                            record.get(
                                "verdict"
                            ),

                        "previous_hash":
                            record.get(
                                "previous_hash"
                            ),

                        "block_hash":
                            record.get(
                                "block_hash"
                            ),

                    },

                }

    except Exception:

        pass

    # ------------------------------------------------------------
    # SQLITE FALLBACK
    # ------------------------------------------------------------

    try:

        import sqlite3
        import json

        db_path = getattr(
            db,
            "db_path",
            DATABASE_PATH,
        )

        if not db_path:

            db_path = DATABASE_PATH

        if not os.path.isabs(
            str(db_path)
        ):

            db_path = os.path.abspath(
                str(db_path)
            )

        with sqlite3.connect(
            db_path
        ) as conn:

            conn.row_factory = (
                sqlite3.Row
            )

            cursor = conn.cursor()

            # ----------------------------------------------------
            # Check actual table first.
            # ----------------------------------------------------

            cursor.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                """
            )

            tables = {
                row[0]
                for row in cursor.fetchall()
            }

            if "evidence_ledger" not in tables:

                raise HTTPException(

                    status_code=404,

                    detail={

                        "error":
                            "CASE_NOT_FOUND",

                        "message":
                            (
                                f"Case {case_id} "
                                "was not found."
                            ),

                        "case_id":
                            case_id,

                        "database":
                            str(db_path),

                    },

                )

            cursor.execute(
                """
                SELECT
                    *
                FROM evidence_ledger
                WHERE case_id = ?
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (
                    case_id,
                ),
            )

            row = cursor.fetchone()

        if row is None:

            raise HTTPException(

                status_code=404,

                detail={

                    "error":
                        "CASE_NOT_FOUND",

                    "message":
                        (
                            f"Case {case_id} "
                            "was not found in "
                            "the forensic ledger."
                        ),

                    "case_id":
                        case_id,

                },

            )

        row = dict(row)

        forensic_payload = (
            row.get(
                "forensic_payload"
            )
        )

        if isinstance(
            forensic_payload,
            str,
        ):

            try:

                report = json.loads(
                    forensic_payload
                )

            except Exception:

                report = {

                    "case_id":
                        case_id,

                    "forensic_payload":
                        forensic_payload,

                }

        elif isinstance(
            forensic_payload,
            dict,
        ):

            report = forensic_payload

        else:

            report = {

                "case_id":
                    case_id,

            }

        report["case_id"] = (
            row.get(
                "case_id",
                case_id,
            )
        )

        return {

            "status":
                "SUCCESS",

            "case_id":
                row.get(
                    "case_id",
                    case_id,
                ),

            "report":
                report,

            "ledger": {

                "id":
                    row.get(
                        "id"
                    ),

                "timestamp":
                    row.get(
                        "timestamp"
                    ),

                "raw_sha256":
                    row.get(
                        "raw_sha256"
                    ),

                "threat_score":
                    row.get(
                        "threat_score"
                    ),

                "verdict":
                    row.get(
                        "verdict"
                    ),

                "previous_hash":
                    row.get(
                        "previous_hash"
                    ),

                "block_hash":
                    row.get(
                        "block_hash"
                    ),

            },

        }

    except HTTPException:

        raise

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# FORENSIC AUDIT
# ================================================================

@app.get(
    "/api/v1/forensics/audit"
)
async def audit_chain_integrity():

    try:

        return db.verify_chain_integrity()

    except Exception as exc:

        raise HTTPException(

            status_code=500,

            detail={

                "error":
                    type(exc).__name__,

                "message":
                    str(exc),

            },

        )


# ================================================================
# RUN DIRECTLY
# ================================================================

if __name__ == "__main__":

    uvicorn.run(

        "backend.main:app",

        host="0.0.0.0",

        port=8000,

        reload=True,

    )