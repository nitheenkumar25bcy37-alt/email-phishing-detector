"""Static, non-executing attachment analysis."""

from pathlib import PurePosixPath
from typing import Any, Dict, List
from uuid import uuid4


class AttachmentAnalyzer:
    EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".vbs", ".vbe", ".bat", ".cmd", ".com", ".pif", ".dll", ".sys", ".msi", ".ps1", ".psm1"}
    SCRIPT_EXTENSIONS = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".py", ".sh"}
    ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
    MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
    HTML_EXTENSIONS = {".html", ".htm", ".shtml"}
    SHORTCUT_EXTENSIONS = {".lnk", ".url", ".scf"}
    DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf"}
    EXECUTABLE_MIME_TYPES = {"application/x-msdownload", "application/x-dosexec", "application/x-executable", "application/vnd.microsoft.portable-executable"}
    MIME_BY_EXTENSION = {".pdf": {"application/pdf"}, ".html": {"text/html"}, ".htm": {"text/html"}, ".jpg": {"image/jpeg"}, ".jpeg": {"image/jpeg"}, ".png": {"image/png"}, ".zip": {"application/zip"}, ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}}

    @classmethod
    def _finding(cls, rule: str, severity: str, confidence: float, title: str, description: str, evidence: Dict[str, Any], limitations: List[str] | None = None) -> Dict[str, Any]:
        return {"finding_id": str(uuid4()), "category": "Attachment", "rule": rule, "severity": severity, "confidence": confidence, "title": title, "description": description, "evidence": evidence, "limitations": limitations or []}

    @classmethod
    def analyze(cls, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        legacy_items = []
        risk_score = 0
        for attachment in attachments or []:
            filename = str(attachment.get("filename") or "unnamed").strip()
            lower_name = filename.lower()
            suffixes = [suffix.lower() for suffix in PurePosixPath(lower_name).suffixes]
            extension = suffixes[-1] if suffixes else ""
            content_type = str(attachment.get("content_type") or attachment.get("declared_mime_type") or "").lower()
            reasons: List[str] = []
            severity = "LOW"
            evidence = {"filename": filename, "extension": extension, "content_type": content_type, "size_bytes": attachment.get("size_bytes", 0), "sha256": attachment.get("sha256", "")}

            if extension in cls.EXECUTABLE_EXTENSIONS or content_type in cls.EXECUTABLE_MIME_TYPES:
                reasons.append("Executable attachment detected")
                findings.append(cls._finding("executable_attachment", "high", 0.97, "Executable attachment detected", "The attachment uses an executable extension or executable MIME type.", evidence, ["Static inspection does not prove execution or malicious intent."]))
                risk_score += 55
                severity = "HIGH"
            elif extension in cls.SCRIPT_EXTENSIONS:
                reasons.append("Script attachment detected")
                findings.append(cls._finding("script_attachment", "high", 0.94, "Script attachment detected", "The attachment can contain executable script content.", evidence))
                risk_score += 42
                severity = "HIGH"
            elif extension in cls.MACRO_EXTENSIONS:
                reasons.append("Macro-enabled Office document detected")
                findings.append(cls._finding("macro_document", "medium", 0.93, "Macro-enabled document detected", "Macro-enabled Office files can contain active content and require static review.", evidence))
                risk_score += 35
                severity = "MEDIUM"
            elif extension in cls.HTML_EXTENSIONS:
                reasons.append("HTML attachment may contain active content")
                findings.append(cls._finding("html_attachment", "medium", 0.88, "HTML attachment detected", "HTML attachments can contain credential forms or links and should not be rendered as trusted content.", evidence))
                risk_score += 30
                severity = "MEDIUM"
            elif extension in cls.SHORTCUT_EXTENSIONS:
                reasons.append("Shortcut attachment detected")
                findings.append(cls._finding("shortcut_attachment", "high", 0.91, "Shortcut attachment detected", "Shortcut files can launch commands or redirect users.", evidence))
                risk_score += 45
                severity = "HIGH"
            elif extension in cls.ARCHIVE_EXTENSIONS:
                reasons.append("Archive attachment requires inspection")
                findings.append(cls._finding("archive_attachment", "medium", 0.82, "Archive attachment detected", "Archives can conceal nested executable or script content.", {**evidence, "members": attachment.get("archive_members", [])}, ["Only archive metadata was inspected; members were not extracted or executed."]))
                risk_score += 12
                severity = "MEDIUM"

            if len(suffixes) >= 2 and suffixes[-2] in cls.DOCUMENT_EXTENSIONS and extension in (cls.EXECUTABLE_EXTENSIONS | cls.SCRIPT_EXTENSIONS):
                reasons.append("Filename uses a misleading double extension")
                findings.append(cls._finding("double_extension", "high", 0.98, "Misleading double extension detected", "A document-looking filename ends in an executable or script extension.", evidence))
                risk_score += 25
                severity = "HIGH"
            if filename.startswith(".") or "." not in filename.lstrip("."):
                reasons.append("Filename has a hidden or missing extension")
            expected_types = cls.MIME_BY_EXTENSION.get(extension, set())
            if expected_types and content_type and content_type not in expected_types:
                reasons.append("Declared MIME type does not match the filename extension")
                findings.append(cls._finding("mime_mismatch", "medium", 0.86, "Attachment MIME type does not match its extension", "The declared media type differs from the expected type for the filename extension.", {**evidence, "expected_types": sorted(expected_types)}))
                risk_score += 18
                severity = "MEDIUM" if severity == "LOW" else severity

            members = attachment.get("archive_members", []) or []
            nested_suspicious = [member for member in members if PurePosixPath(str(member.get("filename", "")).lower()).suffix in (cls.EXECUTABLE_EXTENSIONS | cls.SCRIPT_EXTENSIONS)]
            if nested_suspicious:
                reasons.append("Archive contains executable or script-looking members")
                findings.append(cls._finding("nested_executable", "high", 0.95, "Archive contains executable-looking content", "Archive member names indicate executable or script content without extracting it.", {**evidence, "suspicious_members": nested_suspicious}, ["Member names are evidence only; content was not executed."]))
                risk_score += 35
                severity = "HIGH"
            if any(member.get("encrypted") for member in members):
                findings.append(cls._finding("password_protected_archive", "medium", 0.8, "Password-protected archive detected", "Encrypted archive members cannot be fully inspected by this static pass.", evidence))
                reasons.append("Password-protected archive")
                risk_score += 10
            if attachment.get("embedded_urls"):
                findings.append(cls._finding("embedded_url", "medium", 0.78, "Attachment contains embedded URL references", "Static content extraction found URL references inside the attachment payload.", {**evidence, "urls": attachment["embedded_urls"][:20]}))
                reasons.append("Embedded URLs detected")
                risk_score += 15
            if reasons:
                legacy_items.append({**evidence, "severity": severity, "reasons": reasons})

        risk_score = min(100, risk_score)
        return {"attachments": legacy_items, "findings": findings, "attachment_count": len(attachments or []), "suspicious_attachment_count": len(legacy_items), "score": risk_score, "risk_level": "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score else "LOW"}
