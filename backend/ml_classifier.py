import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from typing import Dict

class LocalMLClassifier:
    """Offline ML model for phishing classification using TF-IDF and Naive Bayes."""
    
    MODEL_DIR = "data"
    MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
    
    @classmethod
    def train_dummy_model(cls):
        """
        Trains a basic model for hackathon demonstration. 
        In production, this would use a large corpus like the Enron dataset.
        """
        os.makedirs(cls.MODEL_DIR, exist_ok=True)
        
        # Small sample dataset for initial training
        X_train = [
            "Please review the attached quarterly financial report.",
            "Meeting rescheduled to 3 PM tomorrow.",
            "URGENT: Your account has been suspended. Click here to verify your identity.",
            "Please process this wire transfer immediately for the new vendor.",
            "Looking forward to our lunch on Friday!"
        ]
        y_train = ["Legitimate", "Legitimate", "Phishing", "Phishing", "Legitimate"]
        
        # Build a standard data science text pipeline
        pipeline = make_pipeline(
            TfidfVectorizer(stop_words='english', lowercase=True),
            MultinomialNB()
        )
        
        pipeline.fit(X_train, y_train)
        joblib.dump(pipeline, cls.MODEL_PATH)
        return pipeline

    @classmethod
    def predict(cls, email_text: str) -> Dict:
        # Load model, train if it doesn't exist
        if not os.path.exists(cls.MODEL_PATH):
            pipeline = cls.train_dummy_model()
        else:
            pipeline = joblib.load(cls.MODEL_PATH)
            
        prediction = pipeline.predict([email_text])[0]
        probabilities = pipeline.predict_proba([email_text])[0]
        
        # Get confidence score of the predicted class
        confidence = max(probabilities)
        
        return {
            "ml_classification": prediction,
            "confidence_score": round(confidence * 100, 2)
        }
