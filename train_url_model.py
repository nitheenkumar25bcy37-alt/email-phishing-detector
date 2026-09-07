#!/usr/bin/env python3

"""
NETRA-Mail
URL Phishing ML Training

Dataset format:

    url,label

Labels:
    1 = phishing
    0 = legitimate

Creates:

    data/url_ml_model.joblib

The model uses character-level TF-IDF features because
character n-grams work well for URL lexical patterns.
"""

from pathlib import Path
import json
import random

import joblib
import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

SEED = 42

DATA_PATH = Path("data/training_data.csv")
MODEL_PATH = Path("data/url_ml_model.joblib")
METRICS_PATH = Path("data/url_ml_training_metrics.json")

random.seed(SEED)
np.random.seed(SEED)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("NETRA-MAIL URL ML TRAINING")
print("=" * 70)

print(f"\nDataset: {DATA_PATH}")

if not DATA_PATH.exists():

    raise FileNotFoundError(
        f"\nDataset not found:\n{DATA_PATH}\n"
    )


df = pd.read_csv(
    DATA_PATH,
    encoding="utf-8",
    on_bad_lines="skip",
)


print(f"Rows loaded: {len(df):,}")
print(f"Columns: {list(df.columns)}")


# ============================================================
# VALIDATE COLUMNS
# ============================================================

required_columns = {
    "url",
    "label",
}

missing = required_columns - set(
    df.columns
)

if missing:

    raise ValueError(
        f"\nMissing required columns: {missing}\n"
        f"Expected columns: url,label"
    )


# ============================================================
# CLEAN DATA
# ============================================================

df = df[
    ["url", "label"]
].copy()

df["url"] = (
    df["url"]
    .astype(str)
    .str.strip()
)

# Convert labels robustly.
#
# Supported:
# 0 / 1
# phishing / legitimate
# phish / legit
# malicious / benign

def normalize_label(value):

    text = str(value).strip().lower()

    if text in {
        "1",
        "phishing",
        "phish",
        "malicious",
        "malware",
        "bad",
    }:

        return 1

    if text in {
        "0",
        "legitimate",
        "legit",
        "benign",
        "safe",
        "good",
    }:

        return 0

    try:

        numeric = int(float(text))

        if numeric in {
            0,
            1,
        }:

            return numeric

    except Exception:

        pass

    return np.nan


df["label"] = df["label"].apply(
    normalize_label
)

# Remove invalid records.

df = df.dropna(
    subset=[
        "url",
        "label",
    ]
)

df = df[
    df["url"].str.len() > 3
]

df["label"] = df[
    "label"
].astype(int)


# ============================================================
# REMOVE DUPLICATES
# ============================================================

before = len(df)

df = df.drop_duplicates(
    subset=["url"],
    keep="first",
)

removed = before - len(df)

print(
    f"Duplicate URLs removed: {removed:,}"
)


# ============================================================
# DATASET SUMMARY
# ============================================================

class_counts = df[
    "label"
].value_counts().sort_index()

print("\nClass distribution:")

for label, count in class_counts.items():

    name = (
        "LEGITIMATE"
        if label == 0
        else "PHISHING"
    )

    percentage = (
        count / len(df) * 100
    )

    print(
        f"  {label} = {name:12s}"
        f" {count:8,}"
        f" ({percentage:6.2f}%)"
    )


if len(class_counts) < 2:

    raise ValueError(
        "\nDataset must contain BOTH classes."
    )


if len(df) < 20:

    raise ValueError(
        "\nDataset is too small for a meaningful 80/20 evaluation."
    )


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X = df["url"].values
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=SEED,
    stratify=y,
)

print("\n80/20 split:")
print(
    f"  Training: {len(X_train):,}"
)

print(
    f"  Test:     {len(X_test):,}"
)


# ============================================================
# TF-IDF FEATURE EXTRACTION
# ============================================================

print(
    "\nBuilding character-level TF-IDF features..."
)

vectorizer = TfidfVectorizer(

    analyzer="char",

    ngram_range=(
        3,
        5,
    ),

    min_df=2,

    max_features=200_000,

    sublinear_tf=True,

    lowercase=True,

)


X_train_features = vectorizer.fit_transform(
    X_train
)

X_test_features = vectorizer.transform(
    X_test
)


print(
    f"Training feature matrix: "
    f"{X_train_features.shape}"
)

print(
    f"Test feature matrix: "
    f"{X_test_features.shape}"
)


# ============================================================
# TRAIN CLASSIFIER
# ============================================================

print(
    "\nTraining Logistic Regression..."
)

model = LogisticRegression(

    max_iter=2000,

    class_weight="balanced",

    random_state=SEED,

    solver="liblinear",

)


model.fit(
    X_train_features,
    y_train,
)


# ============================================================
# TEST
# ============================================================

predictions = model.predict(
    X_test_features
)

probabilities = model.predict_proba(
    X_test_features
)[:, 1]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions,
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0,
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0,
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0,
)

tn, fp, fn, tp = confusion_matrix(
    y_test,
    predictions,
    labels=[0, 1],
).ravel()

specificity = (
    tn / (tn + fp)
    if (tn + fp)
    else 0
)

fpr = (
    fp / (fp + tn)
    if (fp + tn)
    else 0
)

fnr = (
    fn / (fn + tp)
    if (fn + tp)
    else 0
)


# ============================================================
# PRINT RESULTS
# ============================================================

print("\n" + "=" * 70)
print("URL ML HOLD-OUT RESULTS")
print("=" * 70)

print(
    f"\nAccuracy:       {accuracy * 100:7.2f}%"
)

print(
    f"Precision:      {precision * 100:7.2f}%"
)

print(
    f"Recall:         {recall * 100:7.2f}%"
)

print(
    f"F1:             {f1 * 100:7.2f}%"
)

print(
    f"Specificity:    {specificity * 100:7.2f}%"
)

print(
    f"False Positive: {fpr * 100:7.2f}%"
)

print(
    f"False Negative: {fnr * 100:7.2f}%"
)

print(
    "\nConfusion Matrix:"
)

print(
    f"  TP = {tp:,}"
)

print(
    f"  TN = {tn:,}"
)

print(
    f"  FP = {fp:,}"
)

print(
    f"  FN = {fn:,}"
)


print("\nClassification report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "LEGITIMATE",
            "PHISHING",
        ],
        zero_division=0,
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

artifact = {

    "model": model,

    "vectorizer": vectorizer,

    "label_mapping": {
        "0": "LEGITIMATE",
        "1": "PHISHING",
    },

    "seed": SEED,

    "model_type":
        "LogisticRegression",

    "feature_type":
        "character_tfidf",

}


joblib.dump(
    artifact,
    MODEL_PATH,
)


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {

    "dataset":
        str(DATA_PATH),

    "total_rows":
        int(len(df)),

    "train_rows":
        int(len(X_train)),

    "test_rows":
        int(len(X_test)),

    "seed":
        SEED,

    "accuracy":
        float(accuracy),

    "precision":
        float(precision),

    "recall":
        float(recall),

    "f1":
        float(f1),

    "specificity":
        float(specificity),

    "false_positive_rate":
        float(fpr),

    "false_negative_rate":
        float(fnr),

    "tp":
        int(tp),

    "tn":
        int(tn),

    "fp":
        int(fp),

    "fn":
        int(fn),

}


with open(
    METRICS_PATH,
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        metrics,
        f,
        indent=2,
    )


print(
    "\nModel saved:"
)

print(
    f"  {MODEL_PATH}"
)

print(
    "\nMetrics saved:"
)

print(
    f"  {METRICS_PATH}"
)

print(
    "\nTraining complete."
)