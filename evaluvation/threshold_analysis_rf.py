import pandas as pd
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

DATA_FILE = "data/random_forest_test_predictions.csv"

print("=" * 60)
print("RANDOM FOREST THRESHOLD ANALYSIS")
print("=" * 60)

df = pd.read_csv(DATA_FILE)

print("\nColumns:")
print(df.columns.tolist())

# Automatically identify columns
label_col = "label"

possible_prob_cols = [
    "phishing_probability",
    "probability",
    "phishing_prob",
    "prediction_probability"
]

prob_col = None

for col in possible_prob_cols:
    if col in df.columns:
        prob_col = col
        break

if prob_col is None:
    raise ValueError(
        "Could not find phishing probability column. "
        "Check the CSV columns above."
    )

print(f"\nLabel column      : {label_col}")
print(f"Probability column: {prob_col}")

y_true = df[label_col]

# Convert labels if stored as strings
if y_true.dtype == object:
    y_true = y_true.map({
        "BENIGN": 0,
        "PHISHING": 1
    })

y_true = y_true.astype(int)

probabilities = df[prob_col].astype(float)

thresholds = np.arange(0.10, 0.91, 0.05)

results = []

for threshold in thresholds:

    y_pred = (probabilities >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

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

    fpr = fp / (fp + tn) if (fp + tn) else 0

    fnr = fn / (fn + tp) if (fn + tp) else 0

    results.append({
        "threshold": round(threshold, 2),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn
    })

results_df = pd.DataFrame(results)

print("\n" + "=" * 60)
print("THRESHOLD RESULTS")
print("=" * 60)

print(results_df.to_string(index=False))

# Best threshold by F1
best_f1 = results_df.loc[
    results_df["f1"].idxmax()
]

print("\n" + "=" * 60)
print("BEST THRESHOLD BY F1")
print("=" * 60)

print(f"Threshold : {best_f1['threshold']}")
print(f"Accuracy  : {best_f1['accuracy']}")
print(f"Precision : {best_f1['precision']}")
print(f"Recall    : {best_f1['recall']}")
print(f"F1        : {best_f1['f1']}")
print(f"FPR       : {best_f1['fpr']}")
print(f"FNR       : {best_f1['fnr']}")

output_file = "data/random_forest_threshold_analysis.csv"

results_df.to_csv(
    output_file,
    index=False
)

print(f"\nSaved to: {output_file}")