from pathlib import Path

APP_NAME = "Email Forensics and Phishing Investigator"
APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "app_data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DATABASE_PATH = DATA_DIR / "investigations.sqlite3"
MAX_UPLOAD_MB = 20
MAX_ATTACHMENT_MB = 10
MAX_EMAILS_PER_IMPORT = 25
MAX_IMPORT_TOTAL_MB = 100
