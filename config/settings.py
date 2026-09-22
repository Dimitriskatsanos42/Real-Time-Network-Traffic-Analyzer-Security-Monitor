"""
Ρυθμίσεις εφαρμογής (Application Configuration).

Όλες οι παράμετροι μπορούν να οριστούν μέσω environment variables
για ευελιξία σε development, staging και production περιβάλλοντα.
"""

import base64
import hashlib
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")


class Config:
    """Κεντρική κλάση ρυθμίσεων για το Network Security Monitor."""

    # ── Flask / Γενικά ──────────────────────────────────────────────
    APP_ENV = os.environ.get("APP_ENV", "development").lower()
    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "dev-secret-change-in-production-32-characters"
    )

    # SQLite by default · PostgreSQL: postgresql://user:pass@host:5432/db
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'network_monitor.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── JWT Authentication ──────────────────────────────────────────
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION = timedelta(hours=int(os.environ.get("JWT_EXPIRATION_HOURS", 24)))
    # Default admin credentials (ΑΛΛΑΞΕ σε production!)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

    # Fernet key must be stable so encrypted data remains decryptable after restart.
    _derived_encryption_key = base64.urlsafe_b64encode(
        hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    ).decode("ascii")
    DATA_ENCRYPTION_KEY = os.environ.get(
        "DATA_ENCRYPTION_KEY", _derived_encryption_key
    )
    LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", 5))
    LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", 900))

    # ── Packet Capture (Scapy) ──────────────────────────────────────
    CAPTURE_INTERFACE = os.environ.get("CAPTURE_INTERFACE")  # None = auto
    PACKET_BUFFER_SIZE = int(os.environ.get("PACKET_BUFFER_SIZE", 500))
    STATS_REFRESH_SECONDS = int(os.environ.get("STATS_REFRESH_SECONDS", 3))
    AUTO_START_CAPTURE = os.environ.get("AUTO_START_CAPTURE", "false").lower() == "true"

    # ── Threat Detection Thresholds ───────────────────────────────────
    PORT_SCAN_THRESHOLD = int(os.environ.get("PORT_SCAN_THRESHOLD", 15))
    PORT_SCAN_WINDOW_SECONDS = int(os.environ.get("PORT_SCAN_WINDOW_SECONDS", 60))
    DNS_SUSPICIOUS_QUERY_LENGTH = int(os.environ.get("DNS_SUSPICIOUS_QUERY_LENGTH", 80))

    # Brute-force: πόσες αποτυχημένες προσπάθειες σε πόσα δευτερόλεπτα
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", 10))
    BRUTE_FORCE_WINDOW_SECONDS = int(os.environ.get("BRUTE_FORCE_WINDOW_SECONDS", 120))
    FAILED_LOGIN_THRESHOLD = int(os.environ.get("FAILED_LOGIN_THRESHOLD", 5))

    # ── GeoIP ─────────────────────────────────────────────────────────
    # Διαδρομή προς MaxMind GeoLite2-Country.mmdb (προαιρετικό)
    GEOIP_DB_PATH = os.environ.get(
        "GEOIP_DB_PATH", os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")
    )
    GEOIP_FALLBACK_API = os.environ.get("GEOIP_FALLBACK_API", "http://ip-api.com/json/{ip}")

    # ── Blacklist ─────────────────────────────────────────────────────
    BLACKLIST_FILE = os.environ.get(
        "BLACKLIST_FILE", os.path.join(DATA_DIR, "blacklist.txt")
    )

    # ── Reports & Data Retention ──────────────────────────────────────
    TOP_IPS_LIMIT = int(os.environ.get("TOP_IPS_LIMIT", 20))
    ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", 30))
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

    # ── Flask Server ──────────────────────────────────────────────────
    FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
    FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))
    FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
