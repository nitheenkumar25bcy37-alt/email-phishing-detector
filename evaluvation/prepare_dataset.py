import pandas as pd
from pathlib import Path

# ============================================
# 1. File locations
# ============================================

DATA_DIR = Path(__file__).parent / "data"

PHISHTANK_FILE = DATA_DIR / "phishtank.csv"
TRANCO_FILE = DATA_DIR / "tranco.csv"

OUTPUT_FILE = DATA_DIR / "clean_dataset.csv"


# ============================================
# 2. Load PhishTank
# ============================================

print("Loading PhishTank...")

phish = pd.read_csv(PHISHTANK_FILE)

# Keep only the URL column
phish = phish[["url"]].copy()

# Remove empty URLs
phish = phish.dropna(subset=["url"])

# Assign phishing label
# 1 = phishing
phish["label"] = 1


# ============================================
# 3. Load Tranco
# ============================================

print("Loading Tranco...")

tranco = pd.read_csv(TRANCO_FILE)

# Keep only domain
tranco = tranco[["domain"]].copy()

# Remove empty domains
tranco = tranco.dropna(subset=["domain"])

# Convert domain → URL
tranco["url"] = "https://" + tranco["domain"].astype(str)

# Remove the original domain column
tranco = tranco[["url"]]

# Assign legitimate label
# 0 = legitimate
tranco["label"] = 0


# ============================================
# 4. Combine both datasets
# ============================================

print("Combining datasets...")

dataset = pd.concat(
    [phish, tranco],
    ignore_index=True
)


# ============================================
# 5. Remove duplicate URLs
# ============================================

print("Removing duplicates...")

dataset["url"] = dataset["url"].astype(str).str.strip()

dataset = dataset.drop_duplicates(
    subset=["url"]
)


# ============================================
# 6. Remove invalid/empty URLs
# ============================================

dataset = dataset[
    dataset["url"].str.len() > 0
]


# ============================================
# 7. Shuffle the dataset
# ============================================

dataset = dataset.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# ============================================
# 8. Save dataset
# ============================================

dataset.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================
# 9. Print summary
# ============================================

print("\n============================================")
print("DATASET CREATED SUCCESSFULLY")
print("============================================")

print(f"Total URLs      : {len(dataset)}")
print(f"Phishing URLs   : {(dataset['label'] == 1).sum()}")
print(f"Legitimate URLs : {(dataset['label'] == 0).sum()}")

print("\nFirst 10 rows:")
print(dataset.head(10))

print("\nSaved to:")
print(OUTPUT_FILE)

