import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from typing import Any, Dict, List
from urllib.parse import urlparse


class ForensicEmailParser:
    URL_REGEX = re.compile(r"""https?://[^\s<>"']+|www\.[^\s<>"']+""", re.I)
    IP_REGEX = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")

    def parse_eml_bytes(self, raw_bytes: bytes) -> Dict[str, Any]:
        if not raw_bytes:
            raise ValueError("Empty email file")

        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        received = msg.get_all("Received", [])
        plain, html = self._extract_bodies(msg)
        header_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
        combined = f"{plain}\n{html}\n{header_text}"

        urls = []
        for value in self.URL_REGEX.findall(combined):
            value = value.rstrip(".,;:!?)]}>\"'")
            if value.lower().startswith("www."):
                value = "http://" + value
            if value not in urls:
                urls.append(value)

        return {
            "metadata": {
                "message_id": str(msg.get("Message-ID", "")).strip(),
                "date": str(msg.get("Date", "")).strip(),
                "subject": str(msg.get("Subject", "")).strip(),
                "from": str(msg.get("From", "")).strip(),
                "to": str(msg.get("To", "")).strip(),
                "reply_to": str(msg.get("Reply-To", "")).strip(),
                "return_path": str(msg.get("Return-Path", "")).strip(),
            },
            "authentication_headers": {
                "authentication_results": str(msg.get("Authentication-Results", "")),
                "dkim_signature": str(msg.get("DKIM-Signature", "")),
                "arc_authentication_results": str(msg.get("ARC-Authentication-Results", "")),
                "spf_received": str(msg.get("Received-SPF", "")),
            },
            "network_chain": self._parse_received_chain(received),
            "body": {"plain": plain, "html": html},
            "urls": urls,
            "attachments": self._extract_attachments(msg),
            "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "byte_size": len(raw_bytes),
        }

    def _parse_received_chain(self, received_list: List[str]) -> List[Dict[str, Any]]:
        hops = []
        for idx, header in enumerate(reversed(received_list), start=1):
            ips = []
            for ip in self.IP_REGEX.findall(header):
                try:
                    obj = ipaddress.ip_address(ip)
                    if obj.is_global and ip not in ips:
                        ips.append(ip)
                except ValueError:
                    continue
            hops.append({
                "hop_index": idx,
                "raw_header": header.strip(),
                "extracted_ips": ips,
                "originating_ip": ips[0] if ips else None,
            })
        return hops

    def _extract_bodies(self, msg):
        plain_parts, html_parts = [], []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if "attachment" in str(part.get("Content-Disposition", "")).lower():
                    continue
                try:
                    content = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    content = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                if part.get_content_type() == "text/plain":
                    plain_parts.append(str(content))
                elif part.get_content_type() == "text/html":
                    html_parts.append(str(content))
        else:
            try:
                content = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True) or b""
                content = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
            if msg.get_content_type() == "text/html":
                html_parts.append(str(content))
            else:
                plain_parts.append(str(content))
        return "\n".join(plain_parts), "\n".join(html_parts)

    def _extract_attachments(self, msg):
        attachments = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            filename = part.get_filename()
            disposition = str(part.get("Content-Disposition", "")).lower()
            if not filename and "attachment" not in disposition:
                continue
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        return attachments
