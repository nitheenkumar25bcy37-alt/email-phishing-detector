import csv
import os
from pathlib import Path
from typing import Dict, List

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class LocalMLClassifier:
    MODEL_PATH = Path(os.getenv("NETRA_MODEL_PATH", "data/phishing_model.joblib"))
    DATASET_PATH = Path("data/training_data.csv")

    BOOTSTRAP = [
        ("Meeting moved to 3 PM tomorrow. See you then.", "LEGITIMATE"),
        ("Please find the quarterly report attached for review.", "LEGITIMATE"),
        ("Lunch meeting confirmed for Friday at noon.", "LEGITIMATE"),
        ("Your account has been suspended. Verify your identity immediately.", "PHISHING"),
        ("Urgent payment required. Click the secure link to confirm your bank account.", "PHISHING"),
        ("Your password expires today. Login now to prevent account termination.", "PHISHING"),
        ("Please process this wire transfer immediately to the new beneficiary.", "PHISHING"),
        ("Final notice: confirm your payment information within 24 hours.", "PHISHING"),
        ("Your Microsoft account requires security verification. Click here to sign in.", "PHISHING"),
        ("Please review the attached project minutes and action items.", "LEGITIMATE"),
        ("The team standup is scheduled for 10 AM tomorrow.", "LEGITIMATE"),
        ("Thanks for sending the invoice. We will review it this week.", "LEGITIMATE"),
    ]

    @classmethod
    def _dataset(cls):
        if cls.DATASET_PATH.exists():
            rows = []
            with cls.DATASET_PATH.open("r", encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    text = (row.get("text") or "").strip()
                    label = (row.get("label") or "").strip().upper()
                    if text and label in {"PHISHING", "LEGITIMATE"}:
                        rows.append((text, label))
            if len(rows) >= 10 and len({x[1] for x in rows}) == 2:
                return rows
        return cls.BOOTSTRAP

    @classmethod
    def train(cls):
        cls.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = cls._dataset()
        X = [x[0] for x in data]
        y = [x[1] for x in data]

        model = Pipeline([
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True)),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ])
        model.fit(X, y)
        joblib.dump(model, cls.MODEL_PATH)
        return model

    @classmethod
    def _load(cls):
        if not cls.MODEL_PATH.exists():
            return cls.train()
        try:
            return joblib.load(cls.MODEL_PATH)
        except Exception:
            return cls.train()

    @classmethod
    def predict(cls, email_text: str) -> Dict:
        model = cls._load()
        text = email_text or ""
        prediction = str(model.predict([text])[0]).upper()
        probabilities = model.predict_proba([text])[0]
        classes = list(model.classes_)
        probability_map = dict(zip(classes, probabilities))
        phishing_probability = float(probability_map.get("PHISHING", 0.0))

        return {
            "classification": prediction,
            "phishing_probability": round(phishing_probability, 4),
            "confidence": round(max(probabilities) * 100, 2),
            "model": "TF-IDF + Logistic Regression",
            "training_source": "data/training_data.csv" if cls.DATASET_PATH.exists() else "bootstrap fallback",
        }
