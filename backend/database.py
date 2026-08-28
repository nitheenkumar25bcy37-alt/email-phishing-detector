"""
SQLite database for forensic evidence storage
Chain-of-custody logging for threat analysis records
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List


class ThreatDatabase:
    """SQLite database for threat records and evidence storage"""

    def __init__(self, db_path: str = "data/threats.db"):
        """Initialize database connection"""
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Evidence vault table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_hash TEXT UNIQUE NOT NULL,
                    email_hash TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    threat_score INTEGER,
                    risk_level TEXT,
                    threat_classification TEXT,
                    ml_confidence REAL,
                    phishing_probability REAL,
                    sender_email TEXT,
                    sender_domain TEXT,
                    subject TEXT,
                    origin_ip TEXT,
                    origin_country TEXT,
                    url_risk_score INTEGER,
                    domain_risk_flags TEXT,
                    nlp_categories TEXT,
                    authentication_status TEXT,
                    forensic_report TEXT,
                    byte_size INTEGER,
                    attachments_count INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    action TEXT,
                    evidence_hash TEXT,
                    details TEXT,
                    ip_address TEXT
                )
            """)

            # Statistics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE,
                    total_analyzed INTEGER DEFAULT 0,
                    phishing_detected INTEGER DEFAULT 0,
                    legitimate_count INTEGER DEFAULT 0,
                    high_risk_count INTEGER DEFAULT 0,
                    critical_risk_count INTEGER DEFAULT 0,
                    average_threat_score REAL DEFAULT 0,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {e}")

    def insert_threat_record(self, evidence: Dict) -> bool:
        """
        Insert threat record into database
        
        Args:
            evidence: Dictionary containing threat data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO threat_evidence (
                    evidence_hash, email_hash, threat_score, risk_level,
                    threat_classification, ml_confidence, phishing_probability,
                    sender_email, sender_domain, subject, origin_ip,
                    origin_country, url_risk_score, domain_risk_flags,
                    nlp_categories, authentication_status, forensic_report,
                    byte_size, attachments_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.get("evidence_hash"),
                evidence.get("email_hash"),
                evidence.get("threat_score", 0),
                evidence.get("risk_level", "UNKNOWN"),
                evidence.get("classification", "UNKNOWN"),
                evidence.get("ml_confidence", 0),
                evidence.get("phishing_probability", 0),
                evidence.get("sender_email"),
                evidence.get("sender_domain"),
                evidence.get("subject"),
                evidence.get("origin_ip"),
                evidence.get("origin_country"),
                evidence.get("url_risk_score", 0),
                json.dumps(evidence.get("domain_risk_flags", [])),
                json.dumps(evidence.get("nlp_categories", [])),
                evidence.get("authentication_status", "UNKNOWN"),
                json.dumps(evidence.get("forensic_report", {})),
                evidence.get("byte_size", 0),
                evidence.get("attachments_count", 0)
            ))

            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            # Duplicate evidence hash
            return False
        except Exception as e:
            print(f"Error inserting threat record: {e}")
            return False

    def get_threat_record(self, evidence_hash: str) -> Optional[Dict]:
        """Retrieve threat record by evidence hash"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM threat_evidence WHERE evidence_hash = ?",
                (evidence_hash,)
            )
            row = cursor.fetchone()
            conn.close()

            if row:
                record = dict(row)
                # Deserialize JSON fields
                record["domain_risk_flags"] = json.loads(
                    record.get("domain_risk_flags", "[]")
                )
                record["nlp_categories"] = json.loads(
                    record.get("nlp_categories", "[]")
                )
                record["forensic_report"] = json.loads(
                    record.get("forensic_report", "{}")
                )
                return record
            return None
        except Exception as e:
            print(f"Error retrieving threat record: {e}")
            return None

    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """Get recent threat records"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM threat_evidence
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            conn.close()

            return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error retrieving recent threats: {e}")
            return []

    def get_statistics(self) -> Dict:
        """Get threat statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT COUNT(*) as total FROM threat_evidence
            """)
            total = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) as phishing
                FROM threat_evidence
                WHERE threat_classification = 'phishing'
            """)
            phishing_count = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) as high_risk
                FROM threat_evidence
                WHERE risk_level IN ('HIGH', 'CRITICAL')
            """)
            high_risk = cursor.fetchone()[0]

            cursor.execute("""
                SELECT AVG(threat_score) as avg_score
                FROM threat_evidence
            """)
            avg_score = cursor.fetchone()[0] or 0

            conn.close()

            return {
                "total_analyzed": total,
                "phishing_detected": phishing_count,
                "high_risk_detected": high_risk,
                "average_threat_score": round(avg_score, 2)
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}

    def log_audit_event(self, action: str, evidence_hash: str = None,
                        details: str = None, ip_address: str = None) -> bool:
        """Log audit event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO audit_log (action, evidence_hash, details, ip_address)
                VALUES (?, ?, ?, ?)
            """, (action, evidence_hash, details, ip_address))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error logging audit event: {e}")
            return False
            
