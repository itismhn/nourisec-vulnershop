import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    # VULN: Sensitive Data Exposure (WSTG-CRYP-04) - hardcoded, weak, guessable secret key
    SECRET_KEY = "supersecret123"

    DATABASE = os.path.join(BASE_DIR, "instance", "vulnershop.db")
    SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

    # VULN: Security Misconfiguration (WSTG-CONF-06) - debug mode on in a "production-like" demo
    # shows full Werkzeug stack traces (file paths, source, framework version) on any unhandled error.
    DEBUG = True

    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    # VULN: Insecure File Upload (WSTG-BUSL-09) - allow-list checks extension only, not content
    ALLOWED_UPLOAD_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "svg"}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    BACKUP_DIR = os.path.join(BASE_DIR, "backup")
