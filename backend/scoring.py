"""
Agentic MX - Explainable Threat Scoring Engine
Calculates deterministic 0-100 threat score from independent signals.
Prevents signal double-counting and enforces transparent risk classification.
"""

from typing import Dict, Any, Tuple, List
from models import ScoreBreakdown, ThreatScore

class ThreatScoringEngine:
    """
    Max points per group:
      A. ML Classifier: 30
      B. NLP / Social Engineering: 20
      C. URL Intelligence: 20
      D. Domain Intelligence: 15
      E. Header / Email Auth: 10
      F. Infrastructure / GeoIP: 5
    Total Max: 100
    """

    def calculate_score(
        self,
        ml_res: Dict[str, Any],
        nlp_res: Dict[str, Any],
        url_res: Dict[str, Any],
        domain_res: Dict[str, Any],
        auth_res: Dict[str, Any],
        routing_res: Dict[str, Any]
    ) -> ThreatScore:
        evidence_factors: List[str] = []

        # A. ML Signal (Max 30)
        ml_prob = ml_res.get("phishing_probability", 0.0)
        ml_score = min(30.0, ml_prob * 30.0)
        if ml_prob > 0.7:
            evidence_factors.append(f"ML Classifier detected strong phishing pattern ({ml_prob*100:.1f}%)")

        # B. NLP Signal (Max 20)
        nlp_score_raw = nlp_res.get("score", 0.0)
        nlp_score = min(20.0, nlp_score_raw)
        for ind in nlp_res.get("indicators", []):
            cat = ind.get("category", "")
            if cat:
                evidence_factors.append(f"NLP trigger: {cat}")

        # C. URL Signal (Max 20)
        url_score = 0.0
        suspicious_urls = url_res.get("suspicious_urls_count", 0)
        brand_impersonations = url_res.get("brand_impersonations", [])
        
        if brand_impersonations:
            url_score += 12.0
            evidence_factors.append(f"URL brand impersonation: {', '.join(brand_impersonations)}")
        if suspicious_urls > 0:
            url_score += min(8.0, suspicious_urls * 4.0)
            evidence_factors.append(f"Extracted {suspicious_urls} suspicious URL(s)")
        url_score = min(20.0, url_score)

        # D. Domain Intelligence Signal (Max 15)
        domain_score = 0.0
        if domain_res.get("mx_valid") is False:
            domain_score += 6.0
            evidence_factors.append("Sender domain missing valid MX records")
        if domain_res.get("status") == "available":
            age = domain_res.get("domain_age_days")
            if age is not None and age < 30:
                domain_score += 5.0
                evidence_factors.append(f"Newly registered domain ({age} days old)")
        for flag in domain_res.get("risk_flags", []):
            domain_score += 2.0
            evidence_factors.append(f"Domain risk flag: {flag}")
        domain_score = min(15.0, domain_score)

        # E. Authentication / Header Signal (Max 10)
        auth_score = 0.0
        if auth_res.get("spf_result") == "FAIL":
            auth_score += 3.0
            evidence_factors.append("SPF authentication failed")
        if auth_res.get("dmarc_result") == "FAIL":
            auth_score += 3.0
            evidence_factors.append("DMARC authentication failed")
        if auth_res.get("from_reply_to_mismatch"):
            auth_score += 4.0
            evidence_factors.append("Sender address mismatched with Reply-To")
        auth_score = min(10.0, auth_score)

        # F. Infrastructure / GeoIP Signal (Max 5)
        infra_score = 0.0
        if routing_res.get("unusual_routing"):
            infra_score += 3.0
            evidence_factors.append("Unusual or suspicious mail routing hops detected")
        if len(routing_res.get("routing_anomalies", [])) > 0:
            infra_score += 2.0
        infra_score = min(5.0, infra_score)

        # Aggregate total deterministic score
        total_score = int(round(ml_score + nlp_score + url_score + domain_score + auth_score + infra_score))
        total_score = max(0, min(100, total_score))

        # Risk Classification mapping
        if total_score <= 24:
            risk_level = "LOW"
        elif total_score <= 49:
            risk_level = "MEDIUM"
        elif total_score <= 74:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        breakdown = ScoreBreakdown(
            ml_score=round(ml_score, 1),
            nlp_score=round(nlp_score, 1),
            url_score=round(url_score, 1),
            domain_score=round(domain_score, 1),
            auth_score=round(auth_score, 1),
            infra_score=round(infra_score, 1)
        )

        return ThreatScore(
            score=total_score,
            risk_level=risk_level,
            breakdown=breakdown,
            evidence_factors=evidence_factors
        )
