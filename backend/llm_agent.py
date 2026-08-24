import os
import json
from dotenv import load_dotenv

load_dotenv()

class LLMForensicAgent:
    """Synthesizes technical forensic telemetry into an executive SOC briefing."""

    @staticmethod
    def generate_assessment(metadata: dict, ml_assessment: dict, nlp_cues: dict, routing: dict, infra: dict) -> dict:
        api_key = os.getenv("GROQ_API_KEY")
        
        # Rule-based fallback if no API key is configured
        if not api_key or api_key == "your_groq_api_key_here":
            return LLMForensicAgent._fallback_assessment(ml_assessment, nlp_cues, infra)

        try:
            from groq import Groq
            client = Groq(api_key=api_key)
            
            prompt = f"""You are a Lead Digital Forensics & Incident Response (DFIR) Analyst.
Analyze the following email telemetry and generate a structured JSON forensic assessment for legal and SOC review.

Metadata:
- Sender: {metadata.get('from')}
- Subject: {metadata.get('subject')}

Technical Indicators:
- ML Prediction: {ml_assessment.get('ml_classification')} ({ml_assessment.get('confidence_score')}%)
- NLP Social Engineering Cues: {nlp_cues}
- Origin IP: {routing.get('origin_ip')}
- GeoIP / ASN: {infra.get('geolocation')}
- Domain Intelligence: {infra.get('domain_intelligence')}

Respond ONLY with a valid JSON object matching this schema (no markdown, no preamble):
{{
  "threat_actor_tactics": ["tactic 1", "tactic 2"],
  "infrastructure_verdict": "<assessment of hosting/domain legitimacy>",
  "executive_summary": "<2-sentence plain English briefing for investigators>",
  "recommended_soc_actions": ["action 1", "action 2"]
}}"""

            chat_completion = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.3-70b-versatile",
                temperature=0.2,
                response_format={"type": "json_object"}
            )
            
            return json.loads(chat_completion.choices[0].message.content)
            
        except Exception:
            return LLMForensicAgent._fallback_assessment(ml_assessment, nlp_cues, infra)

    @staticmethod
    def _fallback_assessment(ml_assessment: dict, nlp_cues: dict, infra: dict) -> dict:
        geo = infra.get("geolocation") or {}
        domain = infra.get("domain_intelligence") or {}
        
        is_phish = ml_assessment.get("ml_classification") == "Phishing"
        return {
            "threat_actor_tactics": [k.replace('_', ' ').title() for k, v in nlp_cues.items() if v],
            "infrastructure_verdict": f"Originates from {geo.get('country', 'Unknown')} ({geo.get('isp', 'Unknown')}). Domain has {len(domain.get('risk_flags', []))} security risk flags.",
            "executive_summary": f"Automated analysis classified email as {ml_assessment.get('ml_classification')} with {ml_assessment.get('confidence_score')}% confidence. Suspicious technical infrastructure and social engineering cues detected.",
            "recommended_soc_actions": [
                f"Block origin IP {geo.get('ip', 'Unknown')} at boundary firewall",
                f"Sinkhole sender domain {domain.get('domain', 'Unknown')}",
                "Preserve SHA-256 evidence record for incident response"
            ]
        }
