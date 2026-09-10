import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_STORAGE_DIR = Path(os.getenv("NETRA_EVIDENCE_STORAGE_DIR", str(DATA_DIR / "evidence")))
DATABASE_PATH = os.getenv("NETRA_DATABASE_PATH", str(BASE_DIR / "forensic_ledger.db"))
MODEL_PATH = os.getenv("NETRA_MODEL_PATH", str(DATA_DIR / "phishing_model.joblib"))
MAX_EMAIL_SIZE_MB = int(os.getenv("NETRA_MAX_EMAIL_SIZE_MB", "10"))
MAX_EMAIL_SIZE_BYTES = MAX_EMAIL_SIZE_MB * 1024 * 1024
MAX_EVIDENCE_SIZE_BYTES = int(os.getenv("NETRA_MAX_EVIDENCE_SIZE_MB", str(MAX_EMAIL_SIZE_MB))) * 1024 * 1024
MAX_TEXT_SIZE_BYTES = int(os.getenv("NETRA_MAX_TEXT_SIZE_KB", "512")) * 1024
MAX_MIME_PARTS = int(os.getenv("NETRA_MAX_MIME_PARTS", "200"))
MAX_URLS = int(os.getenv("NETRA_MAX_URLS", "100"))
MAX_HEADERS = int(os.getenv("NETRA_MAX_HEADERS", "200"))
MAX_ARCHIVE_MEMBERS = int(os.getenv("NETRA_MAX_ARCHIVE_MEMBERS", "500"))
RATE_LIMIT_REQUESTS = int(os.getenv("NETRA_RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("NETRA_RATE_LIMIT_WINDOW_SECONDS", "60"))
GEOIP_ENABLED = os.getenv("NETRA_GEOIP_ENABLED", "true").lower() == "true"
AI_ENABLED = os.getenv("NETRA_AI_ENABLED", "true").lower() == "true"
ALLOWED_ORIGINS = [
	origin.strip()
	for origin in os.getenv("NETRA_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8501").split(",")
	if origin.strip()
]
APP_VERSION = "3.0.0"

DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
