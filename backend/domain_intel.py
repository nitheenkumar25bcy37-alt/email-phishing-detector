import whois
import dns.resolver
from datetime import datetime
from typing import Dict

class DomainIntelEngine:
    """Performs DNS verification and WHOIS age analysis on sender domains."""

    @staticmethod
    def inspect_domain(domain: str) -> Dict:
        findings = {
            "domain": domain,
            "domain_age_days": None,
            "is_newly_registered": False,
            "has_valid_mx": False,
            "registrar": "Unknown",
            "spf_record": None,
            "dmarc_record": None,
            "risk_flags": []
        }

        # 1. DNS MX Records Check
        try:
            mx_records = dns.resolver.resolve(domain, 'MX', lifetime=4)
            findings["has_valid_mx"] = len(mx_records) > 0
        except Exception:
            findings["has_valid_mx"] = False
            findings["risk_flags"].append("NO_VALID_MX_RECORDS")

        # 2. DNS TXT (SPF) & DMARC Check
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT', lifetime=4)
            for record in txt_records:
                txt_str = record.to_text().strip('"')
                if txt_str.startswith('v=spf1'):
                    findings["spf_record"] = txt_str
        except Exception:
            pass

        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=4)
            for record in dmarc_records:
                txt_str = record.to_text().strip('"')
                if txt_str.startswith('v=DMARC1'):
                    findings["dmarc_record"] = txt_str
        except Exception:
            pass

        if not findings["spf_record"]:
            findings["risk_flags"].append("MISSING_SPF_RECORD")
        if not findings["dmarc_record"]:
            findings["risk_flags"].append("MISSING_DMARC_RECORD")

        # 3. WHOIS Domain Age Analysis
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                findings["domain_age_days"] = age_days
                findings["registrar"] = str(w.registrar or "Unknown")
                
                # Flag domains younger than 30 days
                if age_days < 30:
                    findings["is_newly_registered"] = True
                    findings["risk_flags"].append(f"NEWLY_REGISTERED_DOMAIN_{age_days}_DAYS_OLD")
        except Exception:
            findings["risk_flags"].append("WHOIS_LOOKUP_FAILED")

        return findings
