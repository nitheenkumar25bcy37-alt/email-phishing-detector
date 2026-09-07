import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


# ============================================================
# 1. FIND PROJECT DIRECTORIES
# ============================================================

EVALUATION_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = EVALUATION_DIR.parent
DATA_DIR = EVALUATION_DIR / "data"

# Allow Python to find backend modules
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))


# ============================================================
# 2. IMPORT YOUR EXISTING URL ANALYZER
# ============================================================

from url_analyzer import URLAnalyzer


# ============================================================
# 3. FILE PATHS
# ============================================================

TEST_FILE = DATA_DIR / "test.csv"

PREDICTIONS_FILE = DATA_DIR / "url_predictions.csv"

CONFUSION_MATRIX_FILE = EVALUATION_DIR / "confusion_matrix.png"


# ============================================================
# 4. SETTINGS
# ============================================================

# Initial threshold:
# HIGH or CRITICAL risk = phishing
PHISHING_THRESHOLD = 45.0


# ============================================================
# 5. LOAD TEST DATASET
# ============================================================

print("============================================")
print("AGENTIC MX - URL DETECTOR EVALUATION")
print("============================================")

print("\nLoading test dataset...")

df = pd.read_csv(TEST_FILE)

print(f"Test URLs loaded: {len(df)}")


# Check required columns
required_columns = {"url", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        f"Dataset must contain columns: {required_columns}"
    )


# ============================================================
# 6. INITIALIZE YOUR REAL DETECTOR
# ============================================================

print("\nInitializing existing URLAnalyzer...")

analyzer = URLAnalyzer()


# ============================================================
# 7. RUN DETECTOR
# ============================================================

print("\nRunning detector...")
print("This may take a little while.\n")

predictions = []
risk_scores = []
risk_levels = []


for index, row in df.iterrows():

    url = str(row["url"])

    try:
        result = analyzer.analyze(url)

        # URLAnalyzer returns extracted findings
        findings = result.get("extracted_urls", [])

        if findings:
            # Dataset contains one URL per row.
            # Take the first extracted URL finding.
            finding = findings[0]

            risk_score = float(
                finding.get("risk_score", 0.0)
            )

            risk_level = finding.get(
                "risk_level",
                "LOW"
            )

        else:
            risk_score = 0.0
            risk_level = "LOW"

    except Exception as e:

        print(
            f"Warning: failed to analyze row {index}: {e}"
        )

        risk_score = 0.0
        risk_level = "LOW"


    # Convert risk score into binary prediction
    predicted_label = (
        1 if risk_score >= PHISHING_THRESHOLD else 0
    )

    risk_scores.append(risk_score)
    risk_levels.append(risk_level)
    predictions.append(predicted_label)


    # Progress indicator
    if (index + 1) % 1000 == 0:
        print(
            f"Processed {index + 1}/{len(df)} URLs..."
        )


# ============================================================
# 8. STORE PREDICTIONS
# ============================================================

df["risk_score"] = risk_scores
df["risk_level"] = risk_levels
df["predicted_label"] = predictions


# ============================================================
# 9. ACTUAL AND PREDICTED LABELS
# ============================================================

y_true = df["label"].astype(int)
y_pred = df["predicted_label"].astype(int)

# Risk score can also be used as a continuous score
y_score = df["risk_score"] / 100.0


# ============================================================
# 10. CALCULATE METRICS
# ============================================================

accuracy = accuracy_score(y_true, y_pred)

precision = precision_score(
    y_true,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_true,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_true,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_true,
    y_score
)


# ============================================================
# 11. CONFUSION MATRIX
# ============================================================

tn, fp, fn, tp = confusion_matrix(
    y_true,
    y_pred,
    labels=[0, 1]
).ravel()


# ============================================================
# 12. FALSE POSITIVE / FALSE NEGATIVE RATES
# ============================================================

false_positive_rate = fp / (fp + tn)

false_negative_rate = fn / (fn + tp)


# ============================================================
# 13. PRINT RESULTS
# ============================================================

print("\n")
print("============================================")
print("FINAL EVALUATION RESULTS")
print("============================================")

print(f"\nTest samples : {len(df)}")
print(f"Threshold    : {PHISHING_THRESHOLD}")

print("\n----- Classification Metrics -----")

print(f"Accuracy      : {accuracy:.4f}")
print(f"Precision     : {precision:.4f}")
print(f"Recall        : {recall:.4f}")
print(f"F1 Score      : {f1:.4f}")
print(f"ROC-AUC       : {roc_auc:.4f}")

print("\n----- Error Metrics -----")

print(f"False Positive Rate : {false_positive_rate:.4f}")
print(f"False Negative Rate : {false_negative_rate:.4f}")

print("\n----- Confusion Matrix -----")

print(
    f"""
                    Predicted
                 Benign  Phishing
Actual Benign     {tn:6d}  {fp:8d}
Actual Phishing   {fn:6d}  {tp:8d}
"""
)

print("\n----- Classification Report -----")

print(
    classification_report(
        y_true,
        y_pred,
        target_names=["BENIGN", "PHISHING"],
        zero_division=0
    )
)


# ============================================================
# 14. SAVE PREDICTIONS
# ============================================================

df.to_csv(
    PREDICTIONS_FILE,
    index=False
)

print(
    f"\nDetailed predictions saved to:"
)
print(PREDICTIONS_FILE)


# ============================================================
# 15. CREATE CONFUSION MATRIX IMAGE
# ============================================================

cm = confusion_matrix(
    y_true,
    y_pred,
    labels=[0, 1]
)

plt.figure(figsize=(7, 6))

plt.imshow(cm)

plt.title(
    "Agentic MX - URL Detector Confusion Matrix"
)

plt.xlabel("Predicted Label")
plt.ylabel("Actual Label")

plt.xticks(
    [0, 1],
    ["BENIGN", "PHISHING"]
)

plt.yticks(
    [0, 1],
    ["BENIGN", "PHISHING"]
)


# Write numbers inside matrix
for i in range(2):
    for j in range(2):
        plt.text(
            j,
            i,
            str(cm[i, j]),
            ha="center",
            va="center"
        )


plt.colorbar()

plt.tight_layout()

plt.savefig(
    CONFUSION_MATRIX_FILE,
    dpi=200
)

plt.close()


print(
    f"Confusion matrix saved to:"
)

print(CONFUSION_MATRIX_FILE)


print("\n============================================")
print("EVALUATION COMPLETE")
print("============================================")