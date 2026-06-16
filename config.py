"""Application configuration loaded from environment variables."""

import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

TARGET_URL = os.getenv("TARGET_URL", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "database" / "bugdb.sqlite"))
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", str(BASE_DIR / "reports"))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "10"))
MAX_THREADS = int(os.getenv("MAX_THREADS", "10"))

ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
NUCLEI_PATH = os.getenv("NUCLEI_PATH", "nuclei")
OOB_HTTP_PORT = int(os.getenv("OOB_HTTP_PORT", "8888"))
OOB_DNS_PORT = int(os.getenv("OOB_DNS_PORT", "5353"))
H1_API_USERNAME = os.getenv("H1_API_USERNAME", "")
H1_API_TOKEN = os.getenv("H1_API_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
BUG_BOUNTY_MODE = os.getenv("BUG_BOUNTY_MODE", "false").lower() == "true"
BUG_BOUNTY_PROGRAM = os.getenv("BUG_BOUNTY_PROGRAM", "")
HACKERONE_HANDLE = os.getenv("HACKERONE_HANDLE", "")
RESEARCHER_USER_AGENT = os.getenv("RESEARCHER_USER_AGENT", "")
RESEARCHER_HEADER_NAME = os.getenv("RESEARCHER_HEADER_NAME", "")
RESEARCHER_HEADER_VALUE = os.getenv("RESEARCHER_HEADER_VALUE", "")
REQUESTS_PER_SECOND = float(os.getenv("REQUESTS_PER_SECOND", "2"))

MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", "86400"))
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1
APP_VERSION = "1.0.0"


def apply_runtime_config(target=None, timeout=None, max_threads=None, flask_port=None):
    """Apply values supplied by CLI or the dashboard for this process."""
    global TARGET_URL, SCAN_TIMEOUT, MAX_THREADS, FLASK_PORT
    if target:
        TARGET_URL = target
    if timeout is not None:
        SCAN_TIMEOUT = int(timeout)
    if max_threads is not None:
        MAX_THREADS = int(max_threads)
    if flask_port is not None:
        FLASK_PORT = int(flask_port)


def validate_bug_bounty_settings():
    """Validate process-wide safeguards before production bounty testing."""
    if not BUG_BOUNTY_MODE:
        return
    if not str(HACKERONE_HANDLE).strip():
        raise ValueError("HackerOne username is required in bug bounty mode")
    if not 0.1 <= float(REQUESTS_PER_SECOND) <= 5:
        raise ValueError("Requests per second must be between 0.1 and 5")
    profile = str(BUG_BOUNTY_PROGRAM).strip().lower()
    if profile == "ring":
        if RESEARCHER_HEADER_NAME or RESEARCHER_HEADER_VALUE:
            raise ValueError(
                "Ring identifies testing with its required User-Agent; "
                "remove the optional custom header"
            )
    elif not RESEARCHER_USER_AGENT and not (
        RESEARCHER_HEADER_NAME and RESEARCHER_HEADER_VALUE
    ):
        raise ValueError(
            "Select the Ring profile or configure a researcher User-Agent/header"
        )
