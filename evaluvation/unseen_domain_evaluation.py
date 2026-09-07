import pandas as pd
import numpy as np

from urllib.parse import urlparse

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
# CONFIGURATION
# ============================================================

TRAIN_FILE = "data/train.csv"
TEST_FILE = "data/test.csv"

RANDOM_STATE = 42
N_ESTIMATORS = 300
MIN_SAMPLES_LEAF = 2

THRESHOLD = 0.55


# ============================================================
# EXTRACT DOMAIN
# ============================================================

def extract_domain(url):

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return ""

        hostname = hostname.lower()

        # Remove www.
        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    except Exception:
        return ""


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 60)
print("UNSEEN DOMAIN EVALUATION")
print("=" * 60)

print("\nLoading training dataset...")

train_df = pd.read_csv(TRAIN_FILE)

print(f"Training samples: {len(train_df)}")

print("\nLoading test dataset...")

test_df = pd.read_csv(TEST_FILE)

print(f"Testing samples : {len(test_df)}")


# ============================================================
# EXTRACT DOMAINS
# ============================================================

print("\nExtracting domains...")

train_df["domain"] = train_df["url"].apply(extract_domain)
test_df["domain"] = test_df["url"].apply(extract_domain)


# Remove empty domains

train_df = train_df[train_df["domain"] != ""].copy()
test_df = test_df[test_df["domain"] != ""].copy()


# ============================================================
# REMOVE TEST DOMAINS THAT APPEAR IN TRAINING
# ============================================================

train_domains = set(train_df["domain"])

test_before = len(test_df)

unseen_test_df = test_df[
    ~test_df["domain"].isin(train_domains)
].copy()

test_after = len(unseen_test_df)


print("\n" + "=" * 60)
print("DOMAIN OVERLAP ANALYSIS")
print("=" * 60)

print(f"Training domains : {len(train_domains)}")
print(f"Original test URLs: {test_before}")
print(f"Unseen-domain URLs: {test_after}")

removed = test_before - test_after

print(f"Removed overlapping test URLs: {removed}")


if test_after == 0:

    print("\nERROR:")
    print("No unseen domains available in the test set.")

    raise SystemExit


# ============================================================
# FEATURE COLUMNS
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

missing_train = [
    col for col in FEATURE_COLUMNS
    if col not in train_df.columns
]

missing_test = [
    col for col in FEATURE_COLUMNS
    if col not in unseen_test_df.columns
]

if missing_train:

    raise ValueError(
        f"Missing training features: {missing_train}"
    )

if missing_test:

    raise ValueError(
        f"Missing testing features: {missing_test}"
    )


# ============================================================
# PREPARE DATA
# ============================================================

X_train = train_df[FEATURE_COLUMNS]

y_train = train_df["label"]

X_test = unseen_test_df[FEATURE_COLUMNS]

y_test = unseen_test_df["label"]


# ============================================================
# CONVERT LABELS
# ============================================================

if y_train.dtype == object:

    y_train = y_train.map({
        "BENIGN": 0,
        "PHISHING": 1
    })

if y_test.dtype == object:

    y_test = y_test.map({
        "BENIGN": 0,
        "PHISHING": 1
    })


y_train = y_train.astype(int)
y_test = y_test.astype(int)


# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\n" + "=" * 60)
print("CLASS DISTRIBUTION")
print("=" * 60)

print("\nTraining:")
print(y_train.value_counts())

print("\nUnseen-domain testing:")
print(y_test.value_counts())


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print("\n" + "=" * 60)
print("TRAINING RANDOM FOREST")
print("=" * 60)

model = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    min_samples_leaf=MIN_SAMPLES_LEAF,
    class_weight="balanced",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training complete.")


# ============================================================
# PREDICTIONS
# ============================================================

print("\nGenerating phishing probabilities...")

phishing_probability = model.predict_proba(X_test)[:, 1]

y_pred = (
    phishing_probability >= THRESHOLD
).astype(int)


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    phishing_probability
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

tn, fp, fn, tp = confusion_matrix(
    y_test,
    y_pred,
    labels=[0, 1]
).ravel()


fpr = fp / (fp + tn) if (fp + tn) else 0

fnr = fn / (fn + tp) if (fn + tp) else 0


# ============================================================
# RESULTS
# ============================================================

print("\n" + "=" * 60)
print("UNSEEN DOMAIN EVALUATION RESULTS")
print("=" * 60)

print(f"\nTest samples : {len(y_test)}")
print(f"Threshold    : {THRESHOLD}")

print("\n----- Classification Metrics -----")

print(f"Accuracy      : {accuracy:.4f}")
print(f"Precision     : {precision:.4f}")
print(f"Recall        : {recall:.4f}")
print(f"F1 Score      : {f1:.4f}")
print(f"ROC-AUC       : {roc_auc:.4f}")

print("\n----- Error Metrics -----")

print(f"False Positive Rate : {fpr:.4f}")
print(f"False Negative Rate : {fnr:.4f}")


print("\n----- Confusion Matrix -----")

print("""
                    Predicted
                 Benign  Phishing
Actual Benign
Actual Phishing
""")


print(
    f"Actual Benign      {tn:6d}   {fp:6d}"
)

print(
    f"Actual Phishing    {fn:6d}   {tp:6d}"
)


print("\n----- Classification Report -----")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "PHISHING"],
        zero_division=0
    )
)


# ============================================================
# SAVE RESULTS
# ============================================================

results = pd.DataFrame({
    "url": unseen_test_df["url"],
    "domain": unseen_test_df["domain"],
    "label": y_test,
    "phishing_probability": phishing_probability,
    "prediction": y_pred
})

output_file = "data/unseen_domain_predictions.csv"

results.to_csv(
    output_file,
    index=False
)


print("\nSaved:")
print(f"  {output_file}")

print("\n" + "=" * 60)
print("DONE")
print("=" * 60)