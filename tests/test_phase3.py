import sys
from pathlib import Path

# Path resolution
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.nlp_engine import NLPEngine
from backend.ml_classifier import LocalMLClassifier

# Sample email body combining BEC and Phishing elements
sample_body = """
Hello,

This is an URGENT notice regarding your recent payroll update. 
Your account will be suspended within 24 hours if you do not act.
Please verify your credentials immediately and process the pending wire transfer.

Thanks,
IT Support
"""

print("=== 1. NLP Heuristic Scanning ===")
nlp_results = NLPEngine.analyze_text(sample_body)
print(f"Urgency Cues: {nlp_results['urgency_cues']}")
print(f"Financial Cues: {nlp_results['financial_fraud_cues']}")
print(f"Credential Cues: {nlp_results['credential_harvesting_cues']}\n")

print("=== 2. Local ML Classification ===")
ml_results = LocalMLClassifier.predict(sample_body)
print(f"Prediction: {ml_results['ml_classification']}")
print(f"Confidence: {ml_results['confidence_score']}%")
