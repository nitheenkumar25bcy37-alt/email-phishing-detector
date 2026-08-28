# FILE: backend/llm_agent.py
"""
Agentic MX — AI Forensic Agent
Generates a human-readable investigative briefing from deterministic
telemetry already computed by the other analysis modules. The LLM is
an EXPLANATION layer only — it never determines the threat score, and
its prompt explicitly instructs it not to override the deterministic
score. If the LLM provider is unavailable, a deterministic fallback
briefing is returned instead; this must never fail because of the LLM.
"""

import json
import os
from typing import Dict, Any, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
REQUEST_TIMEOUT_SECONDS = 12.0

SYSTEM_PROMPT = (
    "You are a cybersecurity forensic analyst assistant embedded in an "
    "email phishing detection platform. You are given deterministic "
    "telemetry that has ALREADY been computed by rule-based and machine "
    "learning detectors. Your job is ONLY to explain this evidence in "
    "clear analyst-facing language. "
    "Do not override the deterministic threat score. "
    "Do not invent evidence that is not present in the telemetry. "
    "Respond ONLY with a JSON object with these exact keys: "
    "executive_threat_assessment, attack_vector_identified, key_evidence "
    "(a list of short strings), recommended_analyst_action, "
    "confidence_note, infrastructure_verdict. No prose outside the JSON."
)


class LLMAgent:
    """AI forensic explanation layer with a safe deterministic fallback."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")

    def investigate(
        self,
        subject: str,
        body: str,
        ml_result: Dict[str, Any],
        nlp_result: Dict[str, Any],
        urls: List[str],
        domain_flags: List[str],
        threat_score: int,
    ) -> Dict[str, Any]:

        if not self.api_key or not REQUESTS_AVAILABLE:
            return self._fallback_briefing(
                ml_result, nlp_result, urls, domain_flags, threat_score,
                reason="LLM provider not configured",
            )

        try:
            payload = self._build_payload(
                subject, body, ml_result, nlp_result, urls, domain_flags, threat_score
            )
            response = requests.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )

            if response.status_code != 200:
                return self._fallback_briefing(
                    ml_result, nlp_result, urls, domain_flags, threat_score,
                    reason=f"LLM provider returned HTTP {response.status_code}",
                )

            data = response.json()
            content = data["choices"][0]["message"]["content"]
            parsed = self._parse_llm_json(content)

            if parsed is None:
                return self._fallback_briefing(
                    ml_result, nlp_result, urls, domain_flags, threat_score,
                    reason="LLM response could not be parsed",
                )

            return {
                "source": "llm",
                "executive_threat_assessment": parsed.get("executive_threat_assessment", ""),
                "attack_vector_identified": parsed.get("attack_vector_identified", ""),
                "key_evidence": parsed.get("key_evidence", []),
                "recommended_analyst_action": parsed.get("recommended_analyst_action", ""),
                "confidence_note": parsed.get("confidence_note", ""),
                "infrastructure_verdict": parsed.get("infrastructure_verdict", ""),
            }

        except Exception as exc:
            return self._fallback_briefing(
                ml_result, nlp_result, urls, domain_flags, threat_score,
                reason=f"LLM request failed: {exc.__class__.__name__}",
            )

    # ------------------------------------------------------------------
    def _build_payload(self, subject, body, ml_result, nlp_result, urls, domain_flags, threat_score) -> Dict[str, Any]:
        telemetry = {
            "subject": subject,
            "body_excerpt": (body or "")[:800],
            "ml_assessment": ml_result,
            "nlp_indicators": nlp_result,
            "urls": urls[:10],
            "domain_risk_flags": domain_flags,
            "deterministic_threat_score": threat_score,
        }
        return {
            "model": GROQ_MODEL,
            "temperature": 0.2,
            "max_tokens": 600,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(telemetry)},
            ],
        }

    def _parse_llm_json(self, content: str) -> Optional[Dict[str, Any]]:
        try:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.strip("`")
                if cleaned.lower().startswith("json"):
                    cleaned = cleaned[4:]
            return json.loads(cleaned)
        except Exception:
            return None

    def _fallback_briefing(
        self,
        ml_result: Dict[str, Any],
        nlp_result: Dict[str, Any],
        urls: List[str],
        domain_flags: List[str],
        threat_score: int,
        reason: str,
    ) -> Dict[str, Any]:
        """Deterministic, template-based briefing used whenever the LLM
        is unavailable, mis-configured, or errors out."""

        categories = [ind.get("category") for ind in nlp_result.get("indicators", [])]
        evidence: List[str] = []

        classification = ml_result.get("classification", "unavailable")
        if classification == "phishing":
            evidence.append(
                f"ML classifier flagged this message as phishing "
                f"({ml_result.get('phishing_probability', 0)}% probability)"
            )
        if "credential_harvesting" in categories:
            evidence.append("Credential harvesting language detected in message body")
        if "urgency" in categories:
            evidence.append("Urgency / pressure language detected")
        if "financial_fraud" in categories:
            evidence.append("Financial fraud indicators detected")
        if urls:
            evidence.append(f"{len(urls)} embedded URL(s) require verification")
        if domain_flags:
            evidence.append(f"Sender domain risk flags: {', '.join(domain_flags[:3])}")

        if not evidence:
            evidence.append("No high-confidence indicators were present in the available telemetry")

        if threat_score >= 75:
            assessment = "This message exhibits strong, multi-signal indicators consistent with phishing."
            action = "Do not click any links or reply. Escalate to the security team and quarantine the message."
        elif threat_score >= 50:
            assessment = "This message shows several indicators consistent with a social engineering attempt."
            action = "Treat with caution. Verify sender and any links through an independent, trusted channel."
        elif threat_score >= 25:
            assessment = "This message shows some indicators worth reviewing but no strong consensus of malicious intent."
            action = "Review manually. No immediate action required unless additional context raises concern."
        else:
            assessment = "Available signals do not show strong indicators of phishing."
            action = "No action required. Continue standard email hygiene practices."

        return {
            "source": "deterministic_fallback",
            "fallback_reason": reason,
            "executive_threat_assessment": assessment,
            "attack_vector_identified": (
                "Credential harvesting via impersonation link"
                if "credential_harvesting" in categories and urls
                else "Undetermined from available telemetry"
            ),
            "key_evidence": evidence[:6],
            "recommended_analyst_action": action,
            "confidence_note": (
                "This briefing was generated deterministically from rule-based "
                "and ML telemetry because the AI explanation service was unavailable."
            ),
            "infrastructure_verdict": (
                "Sender domain shows risk flags" if domain_flags else "No infrastructure risk flags recorded"
            ),
        }
