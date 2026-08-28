"""
Email parser for RFC 822 compliant email analysis
Extracts metadata, headers, body, and attachments from .eml files
"""

import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib
from typing import Dict, List, Tuple, Optional
from datetime import datetime


class EmailParser:
    """Parse RFC 822 email messages and extract forensic metadata"""

    @staticmethod
    def parse_email(content: str) -> Dict[str, any]:
        """
        Parse email content and extract all relevant fields
        
        Args:
            content: Raw email content as string or bytes
            
        Returns:
            Dictionary with parsed email data
        """
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')

        try:
            msg = email.message_from_string(content)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse email: {str(e)}",
                "raw_content": content[:500]
            }

        parsed = {
            "success": True,
            "headers": dict(msg.items()),
            "from_address": msg.get("From", ""),
            "to_address": msg.get("To", ""),
            "cc_address": msg.get("Cc", ""),
            "bcc_address": msg.get("Bcc", ""),
            "subject": msg.get("Subject", ""),
            "date": msg.get("Date", ""),
            "message_id": msg.get("Message-ID", ""),
            "in_reply_to": msg.get("In-Reply-To", ""),
            "references": msg.get("References", ""),
            "reply_to": msg.get("Reply-To", ""),
            "return_path": msg.get("Return-Path", ""),
            "content_type": msg.get("Content-Type", ""),
            "mime_version": msg.get("MIME-Version", ""),
            "user_agent": msg.get("User-Agent", ""),
            "received_headers": msg.get_all("Received", []),
            "received_count": len(msg.get_all("Received", [])),
            "authentication_results": msg.get("Authentication-Results", ""),
            "body": EmailParser._extract_body(msg),
            "attachments": EmailParser._extract_attachments(msg),
            "is_multipart": msg.is_multipart()
        }

        return parsed

    @staticmethod
    def _extract_body(msg: email.message.Message) -> str:
        """Extract plain text body from email message"""
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body = part.get_payload(decode=True)
                        if isinstance(body, bytes):
                            body = body.decode('utf-8', errors='replace')
                        break
                    except Exception:
                        continue
        else:
            try:
                body = msg.get_payload(decode=True)
                if isinstance(body, bytes):
                    body = body.decode('utf-8', errors='replace')
            except Exception:
                body = msg.get_payload()

        return body.strip()

    @staticmethod
    def _extract_attachments(msg: email.message.Message) -> List[Dict[str, any]]:
        """Extract attachment metadata from email"""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    try:
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes):
                            file_size = len(payload)
                            file_hash = hashlib.sha256(payload).hexdigest()
                        else:
                            file_size = len(payload)
                            file_hash = hashlib.sha256(
                                payload.encode()
                            ).hexdigest()

                        attachments.append({
                            "filename": filename,
                            "content_type": part.get_content_type(),
                            "size_bytes": file_size,
                            "sha256_hash": file_hash
                        })
                    except Exception:
                        attachments.append({
                            "filename": filename,
                            "content_type": part.get_content_type(),
                            "error": "Could not extract attachment"
                        })

        return attachments

    @staticmethod
    def hash_email(content: str) -> Tuple[str, int]:
        """
        Generate SHA-256 hash of email content
        
        Args:
            content: Raw email string
            
        Returns:
            Tuple of (hash_hex, byte_size)
        """
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content

        hash_obj = hashlib.sha256(content_bytes)
        return hash_obj.hexdigest(), len(content_bytes)

    @staticmethod
    def extract_headers_dict(parsed_email: Dict) -> Dict[str, str]:
        """Extract clean header dictionary from parsed email"""
        headers = parsed_email.get("headers", {})
        clean_headers = {}

        for key, value in headers.items():
            if isinstance(value, str):
                clean_headers[key] = value
            else:
                clean_headers[key] = str(value)

        return clean_headers

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """
        Extract URLs from email body
        Simple regex-based extraction (will be improved in BATCH 2)
        
        Args:
            text: Email body text
            
        Returns:
            List of URLs found
        """
        import re

        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))  # Remove duplicates

    @staticmethod
    def extract_email_addresses(text: str) -> List[str]:
        """
        Extract email addresses from email body
        
        Args:
            text: Email body text
            
        Returns:
            List of email addresses found
        """
        import re

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        return list(set(emails))  # Remove duplicates
