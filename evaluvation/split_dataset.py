
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split


# ============================================
# 1. File locations
# ============================================

DATA_DIR = Path(__file__).parent / "data"

INPUT_FILE = DATA_DIR / "balanced_dataset.csv"

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"


# ============================================
# 2. Extract domain from URL
# ============================================

def get_domain(url):
    try:
        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # Remove www.
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return ""


# ============================================
# 3. Load dataset
# ============================================

print("Loading balanced dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Total URLs: {len(df)}")


# ============================================
# 4. Extract domains
# ============================================

print("Extracting domains...")

df["domain"] = df["url"].apply(get_domain)

# Remove rows where domain extraction failed
df = df[df["domain"] != ""]


# ============================================
# 5. Find unique domains
# ============================================

unique_domains = df["domain"].unique()

print(f"Unique domains: {len(unique_domains)}")


# ============================================
# 6. Split DOMAINS
# ============================================

train_domains, test_domains = train_test_split(
    unique_domains,
    test_size=0.20,
    random_state=42
)


# ============================================
# 7. Create train/test datasets
# ============================================

train = df[df["domain"].isin(train_domains)].copy()

test = df[df["domain"].isin(test_domains)].copy()


# ============================================
# 8. Remove helper column
# ============================================

train = train.drop(columns=["domain"])
test = test.drop(columns=["domain"])


# ============================================
# 9. Shuffle
# ============================================

train = train.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

test = test.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# ============================================
# 10. Save
# ============================================

train.to_csv(TRAIN_FILE, index=False)
test.to_csv(TEST_FILE, index=False)


# ============================================
# 11. Display results
# ============================================

print("\n============================================")
print("TRAIN / TEST SPLIT COMPLETE")
print("============================================")

print(f"Training URLs : {len(train)}")
print(f"Testing URLs  : {len(test)}")

print("\nTraining distribution:")
print(train["label"].value_counts())

print("\nTesting distribution:")
print(test["label"].value_counts())

print("\nSaved files:")
print(TRAIN_FILE)
print(TEST_FILE)
