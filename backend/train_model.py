from backend.ml_classifier import LocalMLClassifier


if __name__ == "__main__":
    model = LocalMLClassifier.train()
    print(f"Model trained and saved to: {LocalMLClassifier.MODEL_PATH}")