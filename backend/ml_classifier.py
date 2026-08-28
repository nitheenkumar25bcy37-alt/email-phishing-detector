# FILE: backend/ml_classifier.py
"""
Agentic MX — ML Classifier (TF-IDF + Logistic Regression)
Loads a pre-trained vectorizer + classifier from disk. If artifacts
are missing or fail to load, the classifier degrades to an explicit
"unavailable" state — it never fabricates a probability or accuracy
figure, and it never raises.
"""

import os
from typing import Dict, Any, Optional

try:
    import joblib
    JOBLIB_AVAILABLE = True
except Exception:
    JOBLIB_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_DIR = os.path.join(BASE_DIR, "ml_models")
DEFAULT_VECTORIZER_PATH = os.path.join(DEFAULT_MODEL_DIR, "vectorizer.pkl")
DEFAULT_CLASSIFIER_PATH = os.path.join(DEFAULT_MODEL_DIR, "classifier.pkl")


class MLClassifier:
    """TF-IDF + Logistic Regression phishing text classifier."""

    def __init__(
        self,
        vectorizer_path: Optional[str] = None,
        classifier_path: Optional[str] = None,
    ):
        self.vectorizer_path = vectorizer_path or DEFAULT_VECTORIZER_PATH
        self.classifier_path = classifier_path or DEFAULT_CLASSIFIER_PATH
        self.vectorizer = None
        self.model = None
        self.model_available = False
        self.load_error: Optional[str] = None

        self._load()

    def _load(self) -> None:
        if not JOBLIB_AVAILABLE:
            self.load_error = "joblib not installed"
            return
        try:
            if os.path.exists(self.vectorizer_path) and os.path.exists(self.classifier_path):
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.model = joblib.load(self.classifier_path)
                self.model_available = True
            else:
                self.load_error = "model artifacts not found"
        except Exception as exc:
            self.load_error = f"{exc.__class__.__name__}: {exc}"
            self.vectorizer = None
            self.model = None
            self.model_available = False

    def classify(self, subject: str, body: str) -> Dict[str, Any]:
        text = f"{subject or ''} {body or ''}".strip()

        if not self.model_available or not text:
            return self._fallback_result(
                reason="model unavailable" if not self.model_available else "empty input"
            )

        try:
            features = self.vectorizer.transform([text])
            prediction = self.model.predict(features)[0]

            probabilities: Dict[str, float] = {}
            phishing_probability = 0.0

            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(features)[0]
                classes = list(self.model.classes_)
                for cls, p in zip(classes, proba):
                    label = str(cls)
                    probabilities[label] = round(float(p) * 100, 2)

                phishing_probability = self._extract_phishing_probability(probabilities)

            classification = "phishing" if self._is_phishing_label(prediction) else "legitimate"
            confidence_score = round(max(probabilities.values()), 2) if probabilities else 0.0

            return {
                "model": "tfidf_logistic_regression",
                "model_available": True,
                "classification": classification,
                "confidence": confidence_score,
                "phishing_probability": round(phishing_probability, 2),
                "probabilities": probabilities,
            }

        except Exception as exc:
            return self._fallback_result(reason=f"inference error: {exc.__class__.__name__}")

    def _is_phishing_label(self, label: Any) -> bool:
        label_str = str(label).strip().lower()
        return label_str in {"1", "phishing", "spam", "malicious", "true"}

    def _extract_phishing_probability(self, probabilities: Dict[str, float]) -> float:
        for key, value in probabilities.items():
            key_lower = key.strip().lower()
            if key_lower in {"1", "phishing", "spam", "malicious", "true"}:
                return value
        if len(probabilities) == 2:
            values = list(probabilities.values())
            return max(values)
        return 0.0

    def _fallback_result(self, reason: str) -> Dict[str, Any]:
        return {
            "model": "tfidf_logistic_regression",
            "model_available": False,
            "classification": "unavailable",
            "confidence": 0,
            "phishing_probability": 0,
            "probabilities": {},
            "fallback_reason": reason,
        }
