import hashlib
from datetime import datetime, timezone


def create_evidence_seal(raw_bytes: bytes) -> dict:
    return {
        "sha256_hash": hashlib.sha256(raw_bytes).hexdigest(),
        "byte_size": len(raw_bytes),
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "encoding": "raw_bytes",
    }
