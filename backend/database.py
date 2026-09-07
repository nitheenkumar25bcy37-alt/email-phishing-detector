import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional


GENESIS_HASH = "GENESIS_BLOCK_00000000000000000000000000000000"


class ForensicLedgerDB:
    """
    Tamper-evident SQLite forensic ledger.

    Stores every analyzed email using:

        case_id
        raw SHA-256
        threat score
        verdict
        forensic payload
        previous block hash
        current block hash
    """

    def __init__(self, db_path: str = "forensic_ledger.db"):

        self.db_path = str(
            Path(db_path).resolve()
        )

        self._init_db()

    # ============================================================
    # DATABASE INITIALIZATION
    # ============================================================

    def _init_db(self):

        with sqlite3.connect(
            self.db_path
        ) as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_ledger (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    case_id TEXT UNIQUE NOT NULL,

                    timestamp TEXT NOT NULL,

                    raw_sha256 TEXT NOT NULL,

                    threat_score INTEGER NOT NULL,

                    verdict TEXT NOT NULL,

                    forensic_payload TEXT NOT NULL,

                    previous_hash TEXT NOT NULL,

                    block_hash TEXT NOT NULL
                )
                """
            )

            conn.commit()

    # ============================================================
    # LATEST HASH
    # ============================================================

    def get_latest_hash(self) -> str:

        with sqlite3.connect(
            self.db_path
        ) as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT block_hash
                FROM evidence_ledger
                ORDER BY id DESC
                LIMIT 1
                """
            )

            row = cursor.fetchone()

        if row:

            return row[0]

        return GENESIS_HASH

    # ============================================================
    # RECORD EVIDENCE
    # ============================================================

    def record_evidence(
        self,
        case_id: str,
        raw_sha256: str,
        threat_score: int,
        verdict: str,
        forensic_data: Dict[str, Any],
    ) -> str:

        if not case_id:

            raise ValueError(
                "case_id cannot be empty"
            )

        timestamp = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        previous_hash = (
            self.get_latest_hash()
        )

        payload_json = json.dumps(
            forensic_data,
            sort_keys=True,
            ensure_ascii=False,
        )

        hasher = hashlib.sha256()

        hasher.update(
            (
                f"{case_id}"
                f"{timestamp}"
                f"{raw_sha256}"
                f"{int(threat_score)}"
                f"{payload_json}"
                f"{previous_hash}"
            ).encode(
                "utf-8"
            )
        )

        current_hash = (
            hasher.hexdigest()
        )

        with sqlite3.connect(
            self.db_path
        ) as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO evidence_ledger (
                    case_id,
                    timestamp,
                    raw_sha256,
                    threat_score,
                    verdict,
                    forensic_payload,
                    previous_hash,
                    block_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    timestamp,
                    raw_sha256,
                    int(threat_score),
                    verdict,
                    payload_json,
                    previous_hash,
                    current_hash,
                ),
            )

            conn.commit()

        return current_hash

    # ============================================================
    # GET CASE
    # ============================================================

    def get_case(
        self,
        case_id: str,
    ) -> Optional[Dict[str, Any]]:

        with sqlite3.connect(
            self.db_path
        ) as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    case_id,
                    timestamp,
                    raw_sha256,
                    threat_score,
                    verdict,
                    forensic_payload,
                    previous_hash,
                    block_hash
                FROM evidence_ledger
                WHERE case_id = ?
                LIMIT 1
                """,
                (
                    case_id,
                ),
            )

            row = cursor.fetchone()

        if not row:

            return None

        (
            record_id,
            stored_case_id,
            timestamp,
            raw_sha256,
            threat_score,
            verdict,
            forensic_payload,
            previous_hash,
            block_hash,
        ) = row

        try:

            payload = json.loads(
                forensic_payload
            )

        except Exception:

            payload = {
                "raw_forensic_payload":
                    forensic_payload
            }

        return {

            "id":
                record_id,

            "case_id":
                stored_case_id,

            "timestamp":
                timestamp,

            "raw_sha256":
                raw_sha256,

            "threat_score":
                threat_score,

            "verdict":
                verdict,

            "forensic_payload":
                payload,

            "previous_hash":
                previous_hash,

            "block_hash":
                block_hash,
        }

    # ============================================================
    # VERIFY CHAIN
    # ============================================================

    def verify_chain_integrity(
        self,
    ) -> Dict[str, Any]:

        with sqlite3.connect(
            self.db_path
        ) as conn:

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    case_id,
                    timestamp,
                    raw_sha256,
                    threat_score,
                    forensic_payload,
                    previous_hash,
                    block_hash
                FROM evidence_ledger
                ORDER BY id ASC
                """
            )

            records = cursor.fetchall()

        if not records:

            return {

                "status":
                    "EMPTY",

                "valid":
                    True,

                "total_records":
                    0,

                "database":
                    self.db_path,
            }

        expected_previous = GENESIS_HASH

        for row in records:

            (
                record_id,
                case_id,
                timestamp,
                raw_sha256,
                threat_score,
                payload,
                previous_hash,
                stored_hash,
            ) = row

            if previous_hash != expected_previous:

                return {

                    "status":
                        "TAMPERED",

                    "valid":
                        False,

                    "failed_at_id":
                        record_id,

                    "reason":
                        "Previous hash pointer broken",

                    "database":
                        self.db_path,
                }

            hasher = hashlib.sha256()

            hasher.update(
                (
                    f"{case_id}"
                    f"{timestamp}"
                    f"{raw_sha256}"
                    f"{threat_score}"
                    f"{payload}"
                    f"{previous_hash}"
                ).encode(
                    "utf-8"
                )
            )

            recomputed = (
                hasher.hexdigest()
            )

            if recomputed != stored_hash:

                return {

                    "status":
                        "TAMPERED",

                    "valid":
                        False,

                    "failed_at_id":
                        record_id,

                    "reason":
                        "Payload or metadata modified",

                    "database":
                        self.db_path,
                }

            expected_previous = (
                stored_hash
            )

        return {

            "status":
                "INTEGRAL",

            "valid":
                True,

            "total_records":
                len(records),

            "latest_hash":
                expected_previous,

            "database":
                self.db_path,
        }