import email
from email import policy
import hashlib
from datetime import datetime

class EmailIngestionEngine:
    """Parses raw email bytes into structured data and seals evidence."""
    
    @staticmethod
    def parse_raw_email(raw_bytes: bytes) -> dict:
        # 1. Generate a cryptographic hash for Chain-of-Custody
        evidence_hash = hashlib.sha256(raw_bytes).hexdigest()
        
        # 2. Parse the email using standard RFC policies
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        # 3. Extract the body (preferring plain text for NLP processing)
        body = ""
        body_part = msg.get_body(preferencelist=('plain', 'html'))
        if body_part:
            body = body_part.get_content()
            
        # 4. Extract raw headers for SMTP path tracing
        headers_dict = {k: v for k, v in msg.items()}
        raw_headers_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
        
        return {
            "metadata": {
                "subject": msg.get("Subject", "(No Subject)"),
                "from": msg.get("From", "Unknown"),
                "to": msg.get("To", "Unknown"),
                "date": msg.get("Date", "Unknown"),
            },
            "headers": headers_dict,
            "raw_header_text": raw_headers_text,
            "body": body,
            "evidence": {
                "sha256_hash": evidence_hash,
                "sealed_at": datetime.utcnow().isoformat() + "Z"
            }
        }
