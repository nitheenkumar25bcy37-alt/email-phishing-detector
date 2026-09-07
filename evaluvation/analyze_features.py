import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = "data/url_features_train.csv"


# ============================================================
# LOAD DATA
# ============================================================

print("============================================")
print("URL FEATURE ANALYSIS")
print("============================================")

print("\nLoading feature dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Samples: {len(df)}")
print(f"Features: {len(df.columns) - 1}")


# ============================================================
# SEPARATE FEATURES AND LABEL
# ============================================================

X = df.drop(columns=["label"])
y = df["label"]


# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\n============================================")
print("CLASS DISTRIBUTION")
print("============================================")

print(
    y.value_counts()
    .rename({
        0: "BENIGN",
        1: "PHISHING"
    })
)


# ============================================================
# COMPARE FEATURE MEANS
# ============================================================

print("\n============================================")
print("FEATURE MEAN COMPARISON")
print("============================================")

comparison = pd.DataFrame({
    "Benign Mean": X[y == 0].mean(),
    "Phishing Mean": X[y == 1].mean()
})

comparison["Difference"] = (
    comparison["Phishing Mean"]
    - comparison["Benign Mean"]
)

comparison["Absolute Difference"] = (
    comparison["Difference"]
    .abs()
)

comparison = comparison.sort_values(
    "Absolute Difference",
    ascending=False
)

print(
    comparison.to_string()
)


# ============================================================
# RANDOM FOREST FEATURE IMPORTANCE
# ============================================================

print("\n============================================")
print("RANDOM FOREST FEATURE IMPORTANCE")
print("============================================")

print("\nTraining a temporary Random Forest...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

rf = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

rf.fit(
    X_train,
    y_train
)


importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": rf.feature_importances_
})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

print("\nFeature importance ranking:")

print(
    importance.to_string(
        index=False
    )
)


# ============================================================
# TOP FEATURES
# ============================================================

print("\n============================================")
print("TOP 15 FEATURES")
print("============================================")

print(
    importance
    .head(15)
    .to_string(index=False)
)


# ============================================================
# MUTUAL INFORMATION
# ============================================================

print("\n============================================")
print("MUTUAL INFORMATION")
print("============================================")

print("\nCalculating mutual information...")

mi_scores = mutual_info_classif(
    X,
    y,
    random_state=42
)

mi = pd.DataFrame({
    "Feature": X.columns,
    "MI Score": mi_scores
})

mi = mi.sort_values(
    "MI Score",
    ascending=False
)

print(
    mi.to_string(
        index=False
    )
)


# ============================================================
# SAVE RESULTS
# ============================================================

comparison.to_csv(
    "data/feature_mean_comparison.csv"
)

importance.to_csv(
    "data/random_forest_feature_importance.csv",
    index=False
)

mi.to_csv(
    "data/mutual_information.csv",
    index=False
)


# ============================================================
# COMPLETE
# ============================================================

print("\n============================================")
print("FEATURE ANALYSIS COMPLETE")
print("============================================")

print("\nSaved:")
print("  data/feature_mean_comparison.csv")
print("  data/random_forest_feature_importance.csv")
print("  data/mutual_information.csv")