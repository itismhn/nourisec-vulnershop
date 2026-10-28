import os
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# "vulnerable" (default) keeps the intentionally broken authentication used by the lab.
# "secure" switches on the hardened implementation in app/security.py + app/auth.py,
# mapped control-by-control to OWASP WSTG v4.2 section 4.4 in AUTH_HARDENING.md.
# Set VULNERSHOP_AUTH_MODE=secure, then re-run scripts/reset_db.py to reseed.
AUTH_MODE = os.environ.get("VULNERSHOP_AUTH_MODE", "vulnerable").strip().lower()
if AUTH_MODE not in ("vulnerable", "secure"):
    raise RuntimeError("VULNERSHOP_AUTH_MODE must be 'vulnerable' or 'secure'")
AUTH_SECURE = AUTH_MODE == "secure"


class Config:
    AUTH_MODE = AUTH_MODE
    AUTH_SECURE = AUTH_SECURE

    if AUTH_SECURE:
        # Secure mode: key comes from the environment, or is random per process (which
        # invalidates all cookies on restart - set SECRET_KEY to keep sessions alive).
        SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    else:
        # VULN: Sensitive Data Exposure (WSTG-CRYP-04) - hardcoded, weak, guessable secret key
        SECRET_KEY = "supersecret123"

    # --- Secure-mode session / transport settings (WSTG-ATHN-01/06, WSTG-SESS-02/07) ---
    if AUTH_SECURE:
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = "Lax"
        # Must be on behind HTTPS; off by default only so the plain-HTTP localhost lab works.
        SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
        FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "0") == "1"
    SESSION_IDLE_TIMEOUT = 20 * 60          # seconds of inactivity
    SESSION_ABSOLUTE_TIMEOUT = 8 * 60 * 60  # hard cap regardless of activity
    PERMANENT_SESSION_LIFETIME = SESSION_ABSOLUTE_TIMEOUT

    DATABASE = os.environ.get("VULNERSHOP_DB") or os.path.join(BASE_DIR, "instance", "vulnershop.db")
    SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

    # VULN (vulnerable mode only): Security Misconfiguration (WSTG-CONF-06) - debug mode on in a "production-like" demo
    # shows full Werkzeug stack traces (file paths, source, framework version) on any unhandled error.
    DEBUG = not AUTH_SECURE

    # --- Business-logic settings (WSTG-BUSL) ---
    # Simulated payment-gateway latency between "check stock" and "reserve stock". It widens the
    # race window the lab teaches (BUSL-04); secure mode closes it with an atomic guarded UPDATE.
    CHECKOUT_LATENCY = float(os.environ.get("VULNERSHOP_CHECKOUT_LATENCY", "0.25"))
    MAX_QTY_PER_LINE = 10          # secure mode: units of one product per cart line
    MAX_CART_LINES = 20
    ORDER_PAY_WINDOW = 15 * 60     # secure mode: seconds an unpaid order holds its stock
    REFUND_WINDOW_DAYS = 7         # matches the "7-day return policy" shown on product pages

    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    # VULN: Insecure File Upload (WSTG-BUSL-09) - allow-list checks extension only, not content
    ALLOWED_UPLOAD_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "svg"}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    # Secure mode (WSTG-BUSL-08/09): raster images only (no SVG), verified by content, small.
    SECURE_UPLOAD_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}
    AVATAR_MAX_BYTES = 1024 * 1024

    BACKUP_DIR = os.path.join(BASE_DIR, "backup")
