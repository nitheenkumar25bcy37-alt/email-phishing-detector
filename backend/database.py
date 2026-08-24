import sqlite3
import os
from datetime import datetime
import json
from typing import Dict

class ThreatDatabase:
    """Handles evidence preservation and immutable chain-of-custody logging."""
    
    DB_DIR = "data/evidence"
    DB_PATH = os.path.join(DB_DIR, "threat_logs.db")

    @classmethod
    def initialize(cls):
        """Creates the database and tables if they do not exist."""
        os.makedirs(cls.DB_DIR, exist_ok=True)
        
        with sqlite3.connect(cls.DB_PATH) as conn:
            cursor = conn.cursor()
            # The 'evidence_hash' is UNIQUE to prevent logging the exact same email twice
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_hash TEXT UNIQUE NOT NULL,
                    sealed_timestamp TEXT NOT NULL,
                    origin_ip TEXT,
                    ml_prediction TEXT,
                    is_redacted BOOLEAN,
                    forensic_data TEXT
                )
            ''')
            conn.commit()

    @classmethod
    def log_evidence(cls, evidence_hash: str, ip: str, prediction: str, forensic_data: Dict) -> bool:
        """Saves the threat report into the database."""
        cls.initialize()
        
        with sqlite3.connect(cls.DB_PATH) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO chain_of_custody 
                    (evidence_hash, sealed_timestamp, origin_ip, ml_prediction, is_redacted, forensic_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    evidence_hash, 
                    datetime.utcnow().isoformat() + "Z", 
                    ip or "Unknown", 
                    prediction, 
                    True, 
                    json.dumps(forensic_data)
                ))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # If the exact same email hash is already logged, we ignore it
                return False
