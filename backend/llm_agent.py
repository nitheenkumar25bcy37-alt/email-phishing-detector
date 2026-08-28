"""
Agentic MX - AI Forensic Agent
Generates structured security briefings from deterministic telemetry.
Explicitly constrained from overriding primary deterministic threat scores.
"""

import os
from typing import Dict, Any
from models import AIBriefing

class LLMAgent:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")

    def generate_briefing(self, telemetry: Dict[str, Any], redacted_body: str) -> AIBriefing:
        score_info = telemetry.get("threat_score", {})
        score = score_info.get("score", 0)
        risk_level = score_info.get("risk_level", "LOW")
        evidence = score_info.get("evidence_factors", [])

        # Fallback explanation generator
        exec_summary = f"The email was evaluated with a threat score of {score}/100, placing it in the {risk_level} risk category."
        
        attack_vector = "Social Engineering / Brand Impersonation" if score >= 50 else "Standard Communication / Unverified Domain"
        
        recommended_action = (
            "Isolate message, block sender domain, and do not click embedded links."
            if score >= 50 else
            "No immediate threat detected. Exercise standard security awareness."
        )

        return AIBriefing(
            executive_threat_assessment=exec_summary,
            attack_vector_identified=attack_vector,
            key_evidence=evidence if evidence else ["No major threat indicators identified."],
            recommended_analyst_action=recommended_action,
            confidence_note="Briefing compiled from deterministic multi-signal telemetry.",
            infrastructure_verdict=f"Domain status: {telemetry.get('domain', {}).get('status', 'unknown')}"
        )
