#!/usr/bin/env python3

"""
NETRA-Mail
Domain-Grouped 80/20 URL Hold-Out Evaluation

Purpose:
    Evaluate whether the URL ML classifier generalizes to
    previously unseen domains.

Dataset:
    data/training_data.csv

Format:
    url,label

Labels:
    0 = legitimate
    1 = phishing

Important:
    URLs belonging to the same registered domain are kept
    entirely within either TRAIN or TEST.

This reduces domain-level leakage that can occur with
a normal random URL split.
"""

from pathlib import Path
import json
import random
import warnings

import joblib
import numpy as np
import pandas as pd
import tldextract

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
# CONFIG
# ============================================================

SEED = 42

DATA_PATH = Path("data/training_data.csv")

MODEL_PATH = Path(
    "data/url_domain_holdout_model.joblib"
)

METRICS_PATH = Path(
    "data/url_domain_holdout_metrics.json"
)

RESULTS_PATH = Path(
    "data/url_domain_holdout_predictions.csv"
)

warnings.filterwarnings(
    "ignore"
)

random.seed(SEED)
np.random.seed(SEED)


# ============================================================
# HEADER
# ============================================================

print("=" * 78)
print("NETRA-MAIL — DOMAIN-GROUPED URL EVALUATION")
print("=" * 78)

print(
    "\nPurpose:"
)

print(
    "Test generalization to previously unseen domains."
)

print(
    "\nDataset:",
    DATA_PATH
)


# ============================================================
# CHECK DATASET
# ============================================================

if not DATA_PATH.exists():

    raise FileNotFoundError(
        f"\nDataset not found: {DATA_PATH}"
    )


# ============================================================
# LOAD
# ============================================================

df = pd.read_csv(
    DATA_PATH,
    encoding="utf-8",
    on_bad_lines="skip",
)

print(
    f"\nRows loaded: {len(df):,}"
)

print(
    f"Columns: {list(df.columns)}"
)


# ============================================================
# VALIDATE
# ============================================================

required = {
    "url",
    "label",
}

missing = required - set(df.columns)

if missing:

    raise ValueError(
        f"\nMissing columns: {missing}\n"
        "Expected: url,label"
    )


df = df[
    [
        "url",
        "label",
    ]
].copy()


# ============================================================
# LABEL NORMALIZATION
# ============================================================

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

        if numeric in (0, 1):
            return numeric

    except Exception:
        pass

    return np.nan


df["label"] = df[
    "label"
].apply(normalize_label)

df["url"] = (
    df["url"]
    .astype(str)
    .str.strip()
)

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
# DUPLICATE CHECK
# ============================================================

before = len(df)

df = df.drop_duplicates(
    subset=["url"],
    keep="first",
)

removed = before - len(df)

print(
    f"\nDuplicate URLs removed: {removed:,}"
)


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

print(
    "\nExtracting registered domains..."
)


def get_registered_domain(url):

    try:

        result = tldextract.extract(
            url
        )

        if result.domain and result.suffix:

            return (
                result.domain
                + "."
                + result.suffix
            )

        # Fallback for unusual URLs.

        if result.domain:

            return result.domain

    except Exception:

        pass

    return None


df["domain"] = df[
    "url"
].apply(
    get_registered_domain
)


# Remove URLs where a domain could not be extracted.

invalid_domains = df[
    "domain"
].isna().sum()

if invalid_domains:

    print(
        "Rows with unrecognized domains removed:",
        invalid_domains,
    )

    df = df.dropna(
        subset=["domain"]
    )


# ============================================================
# DATASET SUMMARY
# ============================================================

print(
    "\nDataset after cleaning:"
)

print(
    f"URLs:     {len(df):,}"
)

print(
    f"Domains:  {df['domain'].nunique():,}"
)


class_counts = (
    df["label"]
    .value_counts()
    .sort_index()
)

print(
    "\nClass distribution:"
)

for label, count in class_counts.items():

    name = (
        "LEGITIMATE"
        if label == 0
        else "PHISHING"
    )

    pct = (
        count / len(df) * 100
    )

    print(
        f"  {label} = {name:12s}"
        f"{count:9,}"
        f" ({pct:6.2f}%)"
    )


if len(class_counts) < 2:

    raise ValueError(
        "Dataset must contain both classes."
    )


# ============================================================
# DOMAIN LABEL ANALYSIS
# ============================================================

print(
    "\nAnalyzing domain/class structure..."
)

domain_summary = (
    df.groupby("domain")["label"]
    .agg(
        urls="count",
        positives="sum",
        classes="nunique",
    )
)

mixed_domains = (
    domain_summary[
        domain_summary["classes"] > 1
    ]
)

single_class_domains = (
    domain_summary[
        domain_summary["classes"] == 1
    ]
)

print(
    f"Domains containing BOTH labels: "
    f"{len(mixed_domains):,}"
)

print(
    f"Domains containing one label only: "
    f"{len(single_class_domains):,}"
)


if len(mixed_domains) > 0:

    print(
        "\nNOTE:"
    )

    print(
        "Some domains contain both legitimate and phishing URLs."
    )

    print(
        "These domains will still remain entirely in either"
    )

    print(
        "TRAIN or TEST, preventing cross-domain leakage."
    )


# ============================================================
# DOMAIN-LEVEL STRATIFICATION
# ============================================================

"""
We want approximately 80% of domains for training and
20% for testing.

However, a domain can contain both labels.

For stratification, assign each domain a representative
class:

    1 if it contains at least one phishing URL
    0 otherwise

This gives us a reasonably balanced domain split while
keeping every domain intact.
"""

domain_labels = (
    df.groupby("domain")["label"]
    .max()
    .reset_index()
)

domain_labels.columns = [
    "domain",
    "domain_label",
]


# ============================================================
# DOMAIN TRAIN/TEST SPLIT
# ============================================================

train_domains, test_domains = train_test_split(

    domain_labels,

    test_size=0.20,

    random_state=SEED,

    stratify=domain_labels[
        "domain_label"
    ],

)


train_domain_set = set(
    train_domains["domain"]
)

test_domain_set = set(
    test_domains["domain"]
)


# Safety assertion.

overlap = (
    train_domain_set
    &
    test_domain_set
)

if overlap:

    raise RuntimeError(
        "DOMAIN LEAKAGE DETECTED!"
    )


# ============================================================
# CREATE TRAIN / TEST
# ============================================================

train_df = df[
    df["domain"].isin(
        train_domain_set
    )
].copy()

test_df = df[
    df["domain"].isin(
        test_domain_set
    )
].copy()


print(
    "\n" + "=" * 78
)

print(
    "DOMAIN-GROUPED SPLIT"
)

print(
    "=" * 78
)

print(
    f"\nTraining domains: "
    f"{len(train_domain_set):,}"
)

print(
    f"Testing domains:  "
    f"{len(test_domain_set):,}"
)

print(
    f"\nTraining URLs: "
    f"{len(train_df):,}"
)

print(
    f"Testing URLs:  "
    f"{len(test_df):,}"
)

print(
    f"\nActual URL split: "
    f"{len(train_df) / len(df) * 100:.2f}% / "
    f"{len(test_df) / len(df) * 100:.2f}%"
)


# ============================================================
# TEST CLASS DISTRIBUTION
# ============================================================

print(
    "\nTest-set class distribution:"
)

test_counts = (
    test_df["label"]
    .value_counts()
    .sort_index()
)

for label, count in test_counts.items():

    name = (
        "LEGITIMATE"
        if label == 0
        else "PHISHING"
    )

    pct = (
        count / len(test_df) * 100
    )

    print(
        f"  {name:12s}: "
        f"{count:8,}"
        f" ({pct:6.2f}%)"
    )


if test_df["label"].nunique() < 2:

    raise ValueError(
        "Domain-grouped test set contains only one class."
    )


# ============================================================
# VERIFY NO DOMAIN LEAKAGE
# ============================================================

train_domains_check = set(
    train_df["domain"]
)

test_domains_check = set(
    test_df["domain"]
)

assert not (
    train_domains_check
    &
    test_domains_check
)

print(
    "\n✓ Domain leakage check: PASSED"
)


# ============================================================
# PREPARE X/Y
# ============================================================

X_train = train_df[
    "url"
].values

y_train = train_df[
    "label"
].values

X_test = test_df[
    "url"
].values

y_test = test_df[
    "label"
].values


# ============================================================
# TF-IDF
# ============================================================

print(
    "\n" + "=" * 78
)

print(
    "CHARACTER TF-IDF"
)

print(
    "=" * 78
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


print(
    "\nFitting vectorizer on TRAINING URLs only..."
)

X_train_features = (
    vectorizer.fit_transform(
        X_train
    )
)

print(
    f"Training feature matrix: "
    f"{X_train_features.shape}"
)


print(
    "\nTransforming TEST URLs..."
)

X_test_features = (
    vectorizer.transform(
        X_test
    )
)

print(
    f"Test feature matrix: "
    f"{X_test_features.shape}"
)


# ============================================================
# MODEL
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
# PREDICTION
# ============================================================

print(
    "\nGenerating predictions..."
)

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
    labels=[
        0,
        1,
    ],
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
# RESULTS
# ============================================================

print(
    "\n" + "=" * 78
)

print(
    "DOMAIN-GROUPED URL ML RESULTS"
)

print(
    "=" * 78
)

print(
    f"\nAccuracy:         {accuracy * 100:7.2f}%"
)

print(
    f"Precision:        {precision * 100:7.2f}%"
)

print(
    f"Recall:           {recall * 100:7.2f}%"
)

print(
    f"F1-score:         {f1 * 100:7.2f}%"
)

print(
    f"Specificity:      {specificity * 100:7.2f}%"
)

print(
    f"False Positive:   {fpr * 100:7.2f}%"
)

print(
    f"False Negative:   {fnr * 100:7.2f}%"
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


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print(
    "\nClassification report:"
)

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
# SAVE PREDICTIONS
# ============================================================

prediction_output = test_df[
    [
        "url",
        "domain",
        "label",
    ]
].copy()

prediction_output[
    "predicted"
] = predictions

prediction_output[
    "phishing_probability"
] = probabilities


prediction_output.to_csv(
    RESULTS_PATH,
    index=False,
)


# ============================================================
# SAVE MODEL
# ============================================================

artifact = {

    "model": model,

    "vectorizer": vectorizer,

    "label_mapping": {
        "0": "LEGITIMATE",
        "1": "PHISHING",
    },

    "evaluation": {
        "type":
            "domain_grouped_80_20",

        "seed":
            SEED,

        "train_domains":
            len(train_domain_set),

        "test_domains":
            len(test_domain_set),
    },

}


joblib.dump(
    artifact,
    MODEL_PATH,
)


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {

    "evaluation_type":
        "domain_grouped_80_20",

    "dataset":
        str(DATA_PATH),

    "seed":
        SEED,

    "total_urls":
        int(len(df)),

    "total_domains":
        int(df["domain"].nunique()),

    "train_urls":
        int(len(train_df)),

    "test_urls":
        int(len(test_df)),

    "train_domains":
        int(len(train_domain_set)),

    "test_domains":
        int(len(test_domain_set)),

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

    "mixed_label_domains":
        int(len(mixed_domains)),

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


# ============================================================
# FINAL COMPARISON
# ============================================================

print(
    "\n" + "=" * 78
)

print(
    "COMPARISON WITH RANDOM HOLD-OUT"
)

print(
    "=" * 78
)

print(
    "\nRandom URL hold-out:"
)

print(
    "  Accuracy : 99.03%"
)

print(
    "  Precision: 99.94%"
)

print(
    "  Recall   : 98.20%"
)

print(
    "  F1       : 99.06%"
)

print(
    "\nDomain-grouped hold-out:"
)

print(
    f"  Accuracy : {accuracy * 100:.2f}%"
)

print(
    f"  Precision: {precision * 100:.2f}%"
)

print(
    f"  Recall   : {recall * 100:.2f}%"
)

print(
    f"  F1       : {f1 * 100:.2f}%"
)


print(
    "\nFiles written:"
)

print(
    f"  {MODEL_PATH}"
)

print(
    f"  {METRICS_PATH}"
)

print(
    f"  {RESULTS_PATH}"
)

print(
    "\nDomain-grouped evaluation complete."
)

print(
    "=" * 78
)