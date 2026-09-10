import hashlib
import io
import ipaddress
import re
import zipfile
import os
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import urljoin


class _SafeHTMLExtractor(HTMLParser):
    """Collect HTML metadata without rendering or executing the document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible_parts: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.hidden_elements: List[Dict[str, str]] = []
        self.links: List[Dict[str, str]] = []
        self.inline_images: List[Dict[str, str]] = []
        self._form: Dict[str, Any] | None = None
        self._form_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self._form = {"action": attributes.get("action", ""), "method": attributes.get("method", "get"), "fields": []}
            self._form_text = []
        elif tag in {"input", "button", "select", "textarea"} and self._form is not None:
            field = {key: attributes.get(key, "") for key in ("name", "type", "value", "id") if attributes.get(key, "")}
            self._form["fields"].append(field)
        if attributes.get("type", "").lower() == "hidden" or "hidden" in attributes:
            self.hidden_elements.append({"tag": tag, "name": attributes.get("name", ""), "id": attributes.get("id", ""), "value": attributes.get("value", "")})
        if tag == "a" and attributes.get("href"):
            self.links.append({"href": attributes["href"], "visible_text": ""})
        if tag == "img" and attributes.get("src"):
            self.inline_images.append({"src": attributes["src"], "alt": attributes.get("alt", ""), "content_id": attributes.get("cid", "")})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self._form["visible_text"] = " ".join(self._form_text).strip()
            self.forms.append(self._form)
            self._form = None
            self._form_text = []

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return
        self.visible_parts.append(text)
        if self._form is not None:
            self._form_text.append(text)
        if self.links:
            self.links[-1]["visible_text"] = (self.links[-1]["visible_text"] + " " + text).strip()


class ForensicEmailParser:
    URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
    IP_REGEX = re.compile(r"(?<![A-Za-z0-9_])(?:(?:\d{1,3}\.){3}\d{1,3}|\[?[0-9A-Fa-f:]{2,}\]?)(?![A-Za-z0-9_])")
    MAX_MIME_PARTS = int(os.getenv("NETRA_MAX_MIME_PARTS", "200"))
    MAX_URLS = int(os.getenv("NETRA_MAX_URLS", "100"))
    MAX_HEADERS = int(os.getenv("NETRA_MAX_HEADERS", "200"))
    MAX_ARCHIVE_MEMBERS = int(os.getenv("NETRA_MAX_ARCHIVE_MEMBERS", "500"))

    def parse_eml_bytes(self, raw_bytes: bytes) -> Dict[str, Any]:
        if not raw_bytes:
            raise ValueError("Empty email file")
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        if len(list(msg.walk())) > self.MAX_MIME_PARTS or len(list(msg.items())) > self.MAX_HEADERS:
            raise ValueError("Email contains too many MIME parts or headers")
        plain, html = self._extract_bodies(msg)
        html_details = self._extract_html_details(html)
        header_text = "\n".join(f"{key}: {value}" for key, value in msg.items())
        urls = self._extract_urls("\n".join([plain, html, header_text]))
        for link in html_details["links"]:
            href = link.get("href", "")
            if href and not href.lower().startswith(("javascript:", "data:")):
                normalized = urljoin("http://placeholder.invalid", href)
                if normalized not in urls and normalized != href:
                    urls.append(normalized)

        metadata = {
            "message_id": str(msg.get("Message-ID", "")).strip(),
            "date": str(msg.get("Date", "")).strip(),
            "subject": str(msg.get("Subject", "")).strip(),
            "from": str(msg.get("From", "")).strip(),
            "to": str(msg.get("To", "")).strip(),
            "cc": str(msg.get("Cc", "")).strip(),
            "bcc": str(msg.get("Bcc", "")).strip(),
            "reply_to": str(msg.get("Reply-To", "")).strip(),
            "return_path": str(msg.get("Return-Path", "")).strip(),
            "sender": str(msg.get("Sender", "")).strip(),
        }
        auth_headers = {
            "authentication_results": self._all_headers(msg, "Authentication-Results"),
            "arc_authentication_results": self._all_headers(msg, "ARC-Authentication-Results"),
            "received_spf": self._all_headers(msg, "Received-SPF"),
            "dkim_signature": self._all_headers(msg, "DKIM-Signature"),
            "spf": self._all_headers(msg, "Received-SPF"),
            "dmarc": self._all_headers(msg, "DMARC-Results"),
        }
        return {
            "metadata": metadata,
            "authentication_headers": auth_headers,
            "received_headers": [str(value) for value in msg.get_all("Received", [])],
            "network_chain": self._parse_received_chain(msg.get_all("Received", [])),
            "body": {"plain": plain, "html": html, "visible_text": html_details["visible_text"], "html_forms": html_details["forms"], "hidden_elements": html_details["hidden_elements"]},
            "html_analysis": {"links": html_details["links"], "inline_images": html_details["inline_images"]},
            "urls": urls,
            "url_references": self._url_references(urls, html_details["links"]),
            "attachments": self._extract_attachments(msg),
            "mime_structure": self._mime_structure(msg),
            "raw_bytes": raw_bytes,
            "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "byte_size": len(raw_bytes),
        }

    @staticmethod
    def _all_headers(msg: Any, name: str) -> List[str]:
        return [str(value).strip() for value in msg.get_all(name, [])]

    @classmethod
    def _extract_urls(cls, text: str) -> List[str]:
        urls: List[str] = []
        for value in cls.URL_REGEX.findall(text):
            value = value.rstrip(".,;:!?)]}>\"'")
            if value.lower().startswith("www."):
                value = "http://" + value
            if value not in urls:
                urls.append(value)
            if len(urls) >= cls.MAX_URLS:
                break
        return urls

    @staticmethod
    def _url_references(urls: List[str], links: List[Dict[str, str]]) -> List[Dict[str, str]]:
        references = []
        for link in links:
            href = link.get("href", "")
            if href and not href.lower().startswith(("javascript:", "data:")):
                references.append({"visible_text": link.get("visible_text", ""), "href": href, "normalized": href})
        known = {item["normalized"] for item in references}
        references.extend({"visible_text": "", "href": url, "normalized": url} for url in urls if url not in known)
        return references

    @staticmethod
    def _extract_html_details(html: str) -> Dict[str, Any]:
        extractor = _SafeHTMLExtractor()
        try:
            extractor.feed(html or "")
            extractor.close()
        except Exception:
            pass
        return {"visible_text": " ".join(extractor.visible_parts), "forms": extractor.forms, "hidden_elements": extractor.hidden_elements, "links": extractor.links, "inline_images": extractor.inline_images}

    @classmethod
    def _parse_received_chain(cls, received_list: List[str]) -> List[Dict[str, Any]]:
        hops = []
        for header_index, header in enumerate(received_list):
            raw = str(header).strip()
            ips = []
            for candidate in cls.IP_REGEX.findall(raw):
                candidate = candidate.strip("[]")
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if candidate not in ips:
                    ips.append(candidate)
            timestamp = None
            timestamp_anomaly = False
            timestamp_text = raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
            if timestamp_text:
                try:
                    timestamp = parsedate_to_datetime(timestamp_text).isoformat()
                except (TypeError, ValueError, IndexError):
                    timestamp_anomaly = True
            else:
                timestamp_anomaly = True
            hostnames = re.findall(r"\b(?:from|by)\s+([^\s(;)]+)", raw, flags=re.I)
            malformed = not re.search(r"\bfrom\b", raw, flags=re.I) or not re.search(r"\bby\b", raw, flags=re.I)
            from_match = re.search(r"\bfrom\s+([^\s(;)]+)(?:\s+\(([^)]*)\))?", raw, flags=re.I)
            by_match = re.search(r"\bby\s+([^\s(;)]+)", raw, flags=re.I)
            source_hostname = from_match.group(1) if from_match else None
            destination_hostname = by_match.group(1) if by_match else None
            source_ip = ips[0] if ips else None
            destination_ip = ips[1] if len(ips) > 1 else None
            hops.append({"hop_index": header_index + 1, "header_order": header_index, "raw_header": raw, "hostnames": hostnames, "source_hostname": source_hostname, "destination_hostname": destination_hostname, "source_ip": source_ip, "destination_ip": destination_ip, "extracted_ips": ips, "ip_classifications": [cls._classify_ip(ip) for ip in ips], "timestamp": timestamp, "timestamp_anomaly": timestamp_anomaly, "malformed": malformed, "originating_ip": source_ip})
        return hops

    @staticmethod
    def _classify_ip(value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
            documentation_ranges = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32"))
            if any(address in network for network in documentation_ranges):
                return "documentation"
            if address.is_loopback:
                return "loopback"
            if address.is_private:
                return "private"
            if address.is_reserved:
                return "reserved"
            if address.is_global:
                return "public"
            return "special"
        except ValueError:
            return "invalid"

    def _extract_bodies(self, msg: Any) -> tuple[str, str]:
        plain_parts: List[str] = []
        html_parts: List[str] = []
        for part in msg.walk() if msg.is_multipart() else [msg]:
            if part.is_multipart() or str(part.get("Content-Disposition", "")).lower().startswith("attachment"):
                continue
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            if part.get_content_type() == "text/plain":
                plain_parts.append(str(content))
            elif part.get_content_type() == "text/html":
                html_parts.append(str(content))
        return "\n".join(plain_parts), "\n".join(html_parts)

    def _extract_attachments(self, msg: Any) -> List[Dict[str, Any]]:
        attachments = []
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = str(part.get("Content-Disposition", "")).lower()
            content_id = str(part.get("Content-ID", "")).strip("<>")
            if not filename and "attachment" not in disposition and not content_id:
                continue
            payload = part.get_payload(decode=True) or b""
            archive_members = []
            if part.get_content_type() == "application/zip" or str(filename or "").lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                        if len(archive.infolist()) > self.MAX_ARCHIVE_MEMBERS:
                            raise ValueError("Archive contains too many members")
                        archive_members = [{"filename": item.filename, "is_directory": item.is_dir(), "encrypted": bool(item.flag_bits & 0x1), "size_bytes": item.file_size} for item in archive.infolist()]
                except (OSError, zipfile.BadZipFile):
                    archive_members = []
            attachments.append({"filename": filename or "inline-resource", "content_type": part.get_content_type(), "declared_mime_type": part.get_content_type(), "content_disposition": disposition, "content_id": content_id, "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "embedded_urls": self._extract_urls(payload.decode("utf-8", errors="ignore")) if part.get_content_type() in {"text/html", "text/plain", "application/javascript"} else [], "archive_members": archive_members})
        return attachments

    def _mime_structure(self, msg: Any) -> Dict[str, Any]:
        def node(part: Any, index: str) -> Dict[str, Any]:
            children = [node(child, f"{index}.{child_index}") for child_index, child in enumerate(part.iter_parts())]
            return {"part": index, "content_type": part.get_content_type(), "content_disposition": str(part.get("Content-Disposition", "")), "filename": part.get_filename() or "", "is_multipart": part.is_multipart(), "children": children}
        return node(msg, "0")
