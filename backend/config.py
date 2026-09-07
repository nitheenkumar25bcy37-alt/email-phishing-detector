import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = os.getenv("NETRA_DATABASE_PATH", str(BASE_DIR / "forensic_ledger.db"))
MODEL_PATH = os.getenv("NETRA_MODEL_PATH", str(DATA_DIR / "phishing_model.joblib"))
MAX_EMAIL_SIZE_MB = int(os.getenv("NETRA_MAX_EMAIL_SIZE_MB", "10"))
MAX_EMAIL_SIZE_BYTES = MAX_EMAIL_SIZE_MB * 1024 * 1024
GEOIP_ENABLED = os.getenv("NETRA_GEOIP_ENABLED", "true").lower() == "true"
AI_ENABLED = os.getenv("NETRA_AI_ENABLED", "true").lower() == "true"
APP_VERSION = "3.0.0"

DATA_DIR.mkdir(parents=True, exist_ok=True)
