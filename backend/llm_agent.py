class ThreatExplainerAgent:
    @classmethod
    def explain(cls, report):
        decision = report.get("decision", {})
        score = decision.get("score", 0)
        risk = decision.get("risk", "UNKNOWN")
        action = decision.get("action", "UNKNOWN")
        reasons = decision.get("reasons", [])
        attacks = decision.get("attack_classification", [])

        lines = [
            f"Assessment: {risk} ({score}/100).",
            f"Recommended action: {action}.",
        ]

        if attacks:
            lines.append("Likely attack types: " + ", ".join(attacks) + ".")

        if reasons:
            lines.append("Key evidence: " + "; ".join(reasons[:5]) + ".")

        auth = report.get("authentication", {}).get("authentication", {})
        if auth:
            lines.append(
                f"Authentication results: SPF={auth.get('spf','none').upper()}, "
                f"DKIM={auth.get('dkim','none').upper()}, "
                f"DMARC={auth.get('dmarc','none').upper()}."
            )

        lines.append(
            "The conclusion is based on multiple independent signals rather than a single indicator."
        )
        return "\n".join(lines)
