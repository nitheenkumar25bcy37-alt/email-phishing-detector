"""Static, non-executing analysis of email attachments."""

from pathlib import PurePosixPath
from typing import Any, Dict, List


class AttachmentAnalyzer:
    EXECUTABLE_EXTENSIONS = {
        ".exe", ".scr", ".vbs", ".bat", ".cmd", ".com", ".pif", ".dll", ".sys", ".msi"
    }
    ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
    MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
    DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
    EXECUTABLE_MIME_TYPES = {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
    }

    @classmethod
    def analyze(cls, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        risk_score = 0

        for attachment in attachments or []:
            filename = str(attachment.get("filename") or "unnamed").strip()
            lower_name = filename.lower()
            suffixes = [suffix.lower() for suffix in PurePosixPath(lower_name).suffixes]
            extension = suffixes[-1] if suffixes else ""
            content_type = str(attachment.get("content_type") or "").lower()
            reasons = []
            severity = "LOW"

            if extension in cls.EXECUTABLE_EXTENSIONS or content_type in cls.EXECUTABLE_MIME_TYPES:
                reasons.append("Executable attachment detected")
                risk_score += 55
                severity = "HIGH"
            elif extension in cls.MACRO_EXTENSIONS:
                reasons.append("Macro-enabled document detected")
                risk_score += 35
                severity = "MEDIUM"
            elif extension in cls.ARCHIVE_EXTENSIONS:
                reasons.append("Archive attachment requires inspection")
                risk_score += 12
                severity = "MEDIUM"

            if len(suffixes) >= 2 and suffixes[-2] in cls.DOCUMENT_EXTENSIONS and extension in cls.EXECUTABLE_EXTENSIONS:
                reasons.append("Filename uses a misleading double extension")
                risk_score += 20
                severity = "HIGH"

            if reasons:
                findings.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": attachment.get("size_bytes", 0),
                    "severity": severity,
                    "reasons": reasons,
                    "sha256": attachment.get("sha256", ""),
                })

        return {
            "attachments": findings,
            "attachment_count": len(attachments or []),
            "suspicious_attachment_count": len(findings),
            "score": min(100, risk_score),
            "risk_level": "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score else "LOW",
        }