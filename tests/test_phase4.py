import sys
from pathlib import Path

# Path resolution
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.compliance import ComplianceEngine
from backend.database import ThreatDatabase
import hashlib

# 1. Test Data containing PII
sensitive_email_body = """
URGENT: Verify your account immediately.
Your credit card on file (4532-1122-3344-5566) has been declined.
Please contact support at victim.name@enterprise.com or call us at 555-123-4567.
"""

print("=== 1. Data Masking Engine ===")
print("Original Text:", sensitive_email_body.strip())
print("-" * 30)

redacted_text = ComplianceEngine.mask_text(sensitive_email_body)
print("Redacted Text:", redacted_text.strip())
print("\n")

print("=== 2. Chain-of-Custody Logging ===")
# Simulate an evidence hash from Phase 1
dummy_hash = hashlib.sha256(sensitive_email_body.encode()).hexdigest()

# Initialize DB and log the evidence
ThreatDatabase.initialize()
success = ThreatDatabase.log_evidence(
    evidence_hash=dummy_hash,
    ip="185.220.101.5",
    prediction="Phishing",
    forensic_data={"redacted_body": redacted_text, "threat_score": 95}
)

if success:
    print(f"✓ Evidence successfully sealed and logged in database.")
    print(f"✓ SHA-256 Hash: {dummy_hash}")
else:
    print("⚠ Evidence was already logged in the database (Hash collision).")
