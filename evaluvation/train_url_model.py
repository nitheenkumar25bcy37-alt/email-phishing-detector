"""
Agentic MX - URL Phishing Model Training

Trains a Random Forest classifier using extracted URL features.

Important:
- All paths are resolved relative to the project root.
- Model is saved using joblib.
- The trained model can be loaded by backend/ml_classifier.py.
"""

from pathlib import Path
import sys
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# PROJECT PATHS
# ============================================================

# train_url_model.py is inside:
# project_root/evaluvation/

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"

TRAIN_FILE = DATA_DIR / "url_features_train.csv"
TEST_FILE = DATA_DIR / "url_features_test.csv"

MODEL_FILE = DATA_DIR / "url_random_forest.pkl"
PREDICTION_FILE = DATA_DIR / "random_forest_test_predictions.csv"
IMPORTANCE_FILE = DATA_DIR / "final_feature_importance.csv"


# ============================================================
# CONFIGURATION
# ============================================================

N_ESTIMATORS = 300
MIN_SAMPLES_LEAF = 2
RANDOM_STATE = 42
THRESHOLD = 0.55


# ============================================================
# HEADER
# ============================================================

print("=" * 60)
print("URL PHISHING MODEL TRAINING")
print("=" * 60)

print()
print("Project root:")
print(PROJECT_ROOT)

print()
print("Data directory:")
print(DATA_DIR)

print()
print("Training file:")
print(TRAIN_FILE)

print()
print("Testing file:")
print(TEST_FILE)


# ============================================================
# VERIFY FILES
# ============================================================

print()
print("=" * 60)
print("FILE VERIFICATION")
print("=" * 60)

if not TRAIN_FILE.exists():
    print()
    print("ERROR: Training dataset not found!")
    print()
    print("Expected:")
    print(TRAIN_FILE)
    print()
    print("Please make sure url_features_train.csv exists inside:")
    print(DATA_DIR)
    sys.exit(1)

if not TEST_FILE.exists():
    print()
    print("ERROR: Testing dataset not found!")
    print()
    print("Expected:")
    print(TEST_FILE)
    print()
    print("Please make sure url_features_test.csv exists inside:")
    print(DATA_DIR)
    sys.exit(1)

print("Training dataset : FOUND")
print("Testing dataset  : FOUND")


# ============================================================
# LOAD TRAINING DATA
# ============================================================

print()
print("=" * 60)
print("LOADING TRAINING DATA")
print("=" * 60)

train_df = pd.read_csv(TRAIN_FILE)

print()
print("Training samples:", len(train_df))
print("Training columns:", len(train_df.columns))


# ============================================================
# LOAD TEST DATA
# ============================================================

print()
print("=" * 60)
print("LOADING TEST DATA")
print("=" * 60)

test_df = pd.read_csv(TEST_FILE)

print()
print("Testing samples:", len(test_df))
print("Testing columns:", len(test_df.columns))


# ============================================================
# VERIFY LABEL
# ============================================================

if "label" not in train_df.columns:
    print("ERROR: 'label' column missing from training dataset.")
    sys.exit(1)

if "label" not in test_df.columns:
    print("ERROR: 'label' column missing from testing dataset.")
    sys.exit(1)


# ============================================================
# FEATURE SELECTION
# ============================================================

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_ampersands",
    "num_percent_encoded",
    "num_at_symbols",
    "num_subdomains",
    "hostname_entropy",
    "path_entropy",
    "has_ip",
    "is_https",
    "is_shortener",
    "has_punycode",
    "has_port",
    "has_userinfo",
    "suspicious_tld",
    "suspicious_word_count",
    "brand_word_count",
    "long_url",
    "very_long_url"
]


# ============================================================
# VERIFY FEATURES
# ============================================================

print()
print("=" * 60)
print("DATA VERIFICATION")
print("=" * 60)

missing_train = [
    feature for feature in FEATURE_COLUMNS
    if feature not in train_df.columns
]

missing_test = [
    feature for feature in FEATURE_COLUMNS
    if feature not in test_df.columns
]

if missing_train:
    print("Missing training features:")
    print(missing_train)
    sys.exit(1)

if missing_test:
    print("Missing testing features:")
    print(missing_test)
    sys.exit(1)

print()
print("Training features :", len(FEATURE_COLUMNS))
print("Testing features  :", len(FEATURE_COLUMNS))
print("Feature verification: PASSED")


# ============================================================
# CREATE X / Y
# ============================================================

X_train = train_df[FEATURE_COLUMNS]
y_train = train_df["label"]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["label"]


# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print()
print("=" * 60)
print("CLASS DISTRIBUTION")
print("=" * 60)

print()
print("Training:")

print(
    y_train
    .map({0: "BENIGN", 1: "PHISHING"})
    .value_counts()
)

print()
print("Testing:")

print(
    y_test
    .map({0: "BENIGN", 1: "PHISHING"})
    .value_counts()
)


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print()
print("=" * 60)
print("TRAINING RANDOM FOREST")
print("=" * 60)

print()
print("Configuration:")
print("  Number of trees :", N_ESTIMATORS)
print("  Min samples leaf:", MIN_SAMPLES_LEAF)
print("  Class weight    : balanced")
print("  Random state    :", RANDOM_STATE)

model = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    min_samples_leaf=MIN_SAMPLES_LEAF,
    class_weight="balanced",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print()
print("Training model...")

model.fit(X_train, y_train)

print("Training complete.")


# ============================================================
# PREDICTIONS
# ============================================================

print()
print("Generating phishing probabilities...")

probabilities = model.predict_proba(X_test)[:, 1]

predictions = (
    probabilities >= THRESHOLD
).astype(int)


# ============================================================
# EVALUATION
# ============================================================

accuracy = accuracy_score(y_test, predictions)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

tn, fp, fn, tp = confusion_matrix(
    y_test,
    predictions
).ravel()

fpr = fp / (fp + tn)

fnr = fn / (fn + tp)


# ============================================================
# RESULTS
# ============================================================

print()
print("=" * 60)
print("RANDOM FOREST EVALUATION")
print("=" * 60)

print()
print("Test samples :", len(y_test))
print("Threshold    :", THRESHOLD)

print()
print("----- Classification Metrics -----")

print(f"Accuracy      : {accuracy:.4f}")
print(f"Precision     : {precision:.4f}")
print(f"Recall        : {recall:.4f}")
print(f"F1 Score      : {f1:.4f}")
print(f"ROC-AUC       : {roc_auc:.4f}")

print()
print("----- Error Metrics -----")

print(f"False Positive Rate : {fpr:.4f}")
print(f"False Negative Rate : {fnr:.4f}")

print()
print("----- Confusion Matrix -----")

print()
print("                    Predicted")
print("                 Benign  Phishing")
print(f"Actual Benign    {tn:6d}  {fp:8d}")
print(f"Actual Phishing  {fn:6d}  {tp:8d}")

print()
print("----- Classification Report -----")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["BENIGN", "PHISHING"],
        zero_division=0
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print()
print("=" * 60)
print("FEATURE IMPORTANCE")
print("=" * 60)

importance_df = pd.DataFrame({
    "feature": FEATURE_COLUMNS,
    "importance": model.feature_importances_
})

importance_df = importance_df.sort_values(
    "importance",
    ascending=False
)

print()
print(importance_df.to_string(index=False))


# ============================================================
# SAVE PREDICTIONS
# ============================================================

prediction_df = test_df.copy()

prediction_df["phishing_probability"] = probabilities

prediction_df["prediction"] = predictions

prediction_df.to_csv(
    PREDICTION_FILE,
    index=False
)


# ============================================================
# SAVE FEATURE IMPORTANCE
# ============================================================

importance_df.to_csv(
    IMPORTANCE_FILE,
    index=False
)


# ============================================================
# SAVE MODEL
# ============================================================

print()
print("=" * 60)
print("SAVING MODEL")
print("=" * 60)

# IMPORTANT:
# Use joblib because sklearn RandomForest models
# are being saved/loaded consistently with joblib.

joblib.dump(
    model,
    MODEL_FILE
)

print()
print("Model saved to:")
print(MODEL_FILE)


# ============================================================
# VERIFY SAVED MODEL
# ============================================================

print()
print("Verifying saved model...")

try:

    test_model = joblib.load(MODEL_FILE)

    print("Model verification: PASSED")
    print("Loaded model type :", type(test_model).__name__)
    print("Number of trees   :", test_model.n_estimators)

except Exception as e:

    print("Model verification FAILED")
    print("Error:", e)

    sys.exit(1)


# ============================================================
# FINAL
# ============================================================

print()
print("=" * 60)
print("MODEL TRAINING COMPLETE")
print("=" * 60)

print()
print("Final Results:")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")
print(f"FPR       : {fpr:.4f}")
print(f"FNR       : {fnr:.4f}")

print()
print("Files saved:")

print(" ", MODEL_FILE)
print(" ", PREDICTION_FILE)
print(" ", IMPORTANCE_FILE)

print()
print("=" * 60)
print("DONE")
print("=" * 60)