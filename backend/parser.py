"""
Agentic MX - Email Parser & Evidence Sealer
Robust parser for raw .eml RFC822 messages and plain text submissions.
Generates deterministic SHA-256 evidence seals.
"""

import email
from email import policy
from email.parser import BytesParser, Parser
import hashlib
from datetime import datetime
from typing import Dict, Any, Tuple, List


class EmailParser:
    def __init__(self):
        pass

    def hash_email(self, content_str: str) -> Tuple[str, int]:
        """Generate canonical SHA-256 hash and byte size for raw content."""
        canonical_bytes = content_str.encode('utf-8')
        sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()
        return sha256_hash, len(canonical_bytes)

    def parse_email(self, raw_content: str) -> Dict[str, Any]:
        """
        Parses raw text or RFC822 email file into a structured dictionary.
        """
        if not raw_content or not raw_content.strip():
            return {
                "success": False,
                "error": "Empty content provided"
            }

        try:
            # Check if this resembles an RFC822 structured email header block
            if "From:" in raw_content or "Subject:" in raw_content or "Received:" in raw_content:
                msg = email.message_from_string(raw_content, policy=policy.default)
                return self._extract_from_msg(msg)
            else:
                # Treat as plain text content
                return {
                    "success": True,
                    "from_address": "",
                    "to_address": "",
                    "subject": "Plain Text Submission",
                    "date": datetime.utcnow().isoformat(),
                    "message_id": "",
                    "received_count": 0,
                    "body": raw_content,
                    "headers": {},
                    "attachments": [],
                    "is_multipart": False
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Parsing exception: {str(e)}"
            }

    def _extract_from_msg(self, msg: email.message.EmailMessage) -> Dict[str, Any]:
        """Helper to unpack EmailMessage object safely."""
        from_header = str(msg.get("From", ""))
        to_header = str(msg.get("To", ""))
        subject = str(msg.get("Subject", ""))
        date = str(msg.get("Date", ""))
        message_id = str(msg.get("Message-ID", ""))

        headers_dict = {}
        for key, value in msg.items():
            if key in headers_dict:
                if isinstance(headers_dict[key], list):
                    headers_dict[key].append(str(value))
                else:
                    headers_dict[key] = [headers_dict[key], str(value)]
            else:
                headers_dict[key] = str(value)

        received_headers = msg.get_all("Received", [])
        received_count = len(received_headers) if received_headers else 0

        body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    filename = part.get_filename() or "unnamed_attachment"
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(part.get_payload(decode=True) or b"")
                    })
                elif content_type == "text/plain" and not body:
                    try:
                        body = part.get_content()
                    except Exception:
                        body = str(part.get_payload(decode=True).decode('utf-8', errors='replace'))
                elif content_type == "text/html" and not body:
                    try:
                        # Fallback html extraction if plain text is missing
                        body = part.get_content()
                    except Exception:
                        body = str(part.get_payload(decode=True).decode('utf-8', errors='replace'))
        else:
            try:
                body = msg.get_content()
            except Exception:
                body = str(msg.get_payload(decode=True or b"").decode('utf-8', errors='replace'))

        # Extract email address string from 'From' header
        from_address = from_header
        if "<" in from_header and ">" in from_header:
            from_address = from_header.split("<")[1].split(">")[0].strip()

        return {
            "success": True,
            "from_address": from_address,
            "to_address": to_header,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "received_count": received_count,
            "body": body or "",
            "headers": headers_dict,
            "attachments": attachments,
            "is_multipart": msg.is_multipart()
        }
