import pandas as pd
from pathlib import Path

# ============================================
# 1. File locations
# ============================================

DATA_DIR = Path(__file__).parent / "data"

INPUT_FILE = DATA_DIR / "clean_dataset.csv"
OUTPUT_FILE = DATA_DIR / "balanced_dataset.csv"


# ============================================
# 2. Load dataset
# ============================================

print("Loading clean dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Total URLs available: {len(df)}")


# ============================================
# 3. Separate phishing and legitimate URLs
# ============================================

phishing = df[df["label"] == 1]
legitimate = df[df["label"] == 0]

print(f"Phishing available   : {len(phishing)}")
print(f"Legitimate available : {len(legitimate)}")


# ============================================
# 4. Find the smaller class
# ============================================

sample_size = min(
    len(phishing),
    len(legitimate)
)

print(f"\nUsing {sample_size} URLs from each class.")


# ============================================
# 5. Randomly sample equal amounts
# ============================================

phishing_sample = phishing.sample(
    n=sample_size,
    random_state=42
)

legitimate_sample = legitimate.sample(
    n=sample_size,
    random_state=42
)


# ============================================
# 6. Combine
# ============================================

balanced = pd.concat(
    [phishing_sample, legitimate_sample],
    ignore_index=True
)


# ============================================
# 7. Shuffle
# ============================================

balanced = balanced.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# ============================================
# 8. Save
# ============================================

balanced.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================
# 9. Show results
# ============================================

print("\n============================================")
print("BALANCED DATASET CREATED")
print("============================================")

print(f"Total URLs      : {len(balanced)}")
print(f"Phishing URLs   : {(balanced['label'] == 1).sum()}")
print(f"Legitimate URLs : {(balanced['label'] == 0).sum()}")

print("\nClass distribution:")
print(balanced["label"].value_counts())

print("\nSaved to:")
print(OUTPUT_FILE)
