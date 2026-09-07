import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


# ============================================================
# LOAD EXISTING PREDICTIONS
# ============================================================

FILE = "data/url_predictions.csv"

df = pd.read_csv(FILE)

y_true = df["label"].astype(int)
risk_scores = df["risk_score"].astype(float)


# ============================================================
# TEST MULTIPLE THRESHOLDS
# ============================================================

thresholds = [
    5,
    10,
    15,
    20,
    25,
    30,
    35,
    40,
    45,
    50,
    55,
    60,
    65,
    70,
    75,
]


results = []


for threshold in thresholds:

    y_pred = (
        risk_scores >= threshold
    ).astype(int)

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

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

    # Confusion matrix values
    tp = (
        ((y_true == 1) & (y_pred == 1))
        .sum()
    )

    tn = (
        ((y_true == 0) & (y_pred == 0))
        .sum()
    )

    fp = (
        ((y_true == 0) & (y_pred == 1))
        .sum()
    )

    fn = (
        ((y_true == 1) & (y_pred == 0))
        .sum()
    )

    fpr = fp / (fp + tn)

    fnr = fn / (fn + tp)

    results.append({
        "Threshold": threshold,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "FPR": fpr,
        "FNR": fnr,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
    })


# ============================================================
# DISPLAY RESULTS
# ============================================================

results_df = pd.DataFrame(results)

pd.set_option(
    "display.max_columns",
    None
)

pd.set_option(
    "display.width",
    200
)

print("\n============================================")
print("THRESHOLD ANALYSIS")
print("============================================\n")

print(
    results_df.to_string(
        index=False,
        formatters={
            "Accuracy": "{:.4f}".format,
            "Precision": "{:.4f}".format,
            "Recall": "{:.4f}".format,
            "F1": "{:.4f}".format,
            "FPR": "{:.4f}".format,
            "FNR": "{:.4f}".format,
        }
    )
)


# ============================================================
# BEST F1
# ============================================================

best_f1 = results_df.loc[
    results_df["F1"].idxmax()
]

print("\n============================================")
print("BEST THRESHOLD BY F1")
print("============================================")

print(
    f"Threshold : {best_f1['Threshold']}"
)

print(
    f"Accuracy  : {best_f1['Accuracy']:.4f}"
)

print(
    f"Precision : {best_f1['Precision']:.4f}"
)

print(
    f"Recall    : {best_f1['Recall']:.4f}"
)

print(
    f"F1        : {best_f1['F1']:.4f}"
)

print(
    f"FPR       : {best_f1['FPR']:.4f}"
)

print(
    f"FNR       : {best_f1['FNR']:.4f}"
)