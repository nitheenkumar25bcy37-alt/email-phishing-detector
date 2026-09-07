import pandas as pd


# ============================================================
# LOAD PREDICTIONS
# ============================================================

FILE = "data/url_predictions.csv"

df = pd.read_csv(FILE)


# ============================================================
# CREATE SCORE BINS
# ============================================================

bins = [-1, 0, 4, 9, 14, 19, 24, 29, 34, 39, 44, 49, 59, 69, 79, 89, 100]

labels = [
    "0",
    "1-4",
    "5-9",
    "10-14",
    "15-19",
    "20-24",
    "25-29",
    "30-34",
    "35-39",
    "40-44",
    "45-49",
    "50-59",
    "60-69",
    "70-79",
    "80-89",
    "90-100"
]


df["score_range"] = pd.cut(
    df["risk_score"],
    bins=bins,
    labels=labels
)


# ============================================================
# PHISHING DISTRIBUTION
# ============================================================

print("\n============================================")
print("PHISHING RISK SCORE DISTRIBUTION")
print("============================================")

phishing = df[df["label"] == 1]

phishing_distribution = (
    phishing["score_range"]
    .value_counts()
    .reindex(labels, fill_value=0)
)

print("\nPhishing URLs:")
print(phishing_distribution.to_string())


# ============================================================
# BENIGN DISTRIBUTION
# ============================================================

print("\n============================================")
print("BENIGN RISK SCORE DISTRIBUTION")
print("============================================")

benign = df[df["label"] == 0]

benign_distribution = (
    benign["score_range"]
    .value_counts()
    .reindex(labels, fill_value=0)
)

print("\nBenign URLs:")
print(benign_distribution.to_string())


# ============================================================
# SUMMARY STATISTICS
# ============================================================

print("\n============================================")
print("SCORE STATISTICS")
print("============================================")

print("\nPHISHING:")
print(phishing["risk_score"].describe())


print("\nBENIGN:")
print(benign["risk_score"].describe())


# ============================================================
# PERCENTILES
# ============================================================

percentiles = [0, 10, 25, 50, 75, 90, 95, 99, 100]

print("\n============================================")
print("PHISHING SCORE PERCENTILES")
print("============================================")

print(
    phishing["risk_score"]
    .quantile(
        [p / 100 for p in percentiles]
    )
    .to_string()
)


print("\n============================================")
print("BENIGN SCORE PERCENTILES")
print("============================================")

print(
    benign["risk_score"]
    .quantile(
        [p / 100 for p in percentiles]
    )
    .to_string()
)


# ============================================================
# TOP PHISHING URLS WITH LOW SCORES
# ============================================================

print("\n============================================")
print("EXAMPLES: PHISHING URLs WITH LOW SCORES")
print("============================================")

low_score_phishing = (
    phishing
    .sort_values("risk_score")
    [["url", "risk_score", "risk_level"]]
    .head(30)
)

print(
    low_score_phishing.to_string(
        index=False
    )
)


print("\n============================================")
print("ANALYSIS COMPLETE")
print("============================================")