"""Hardened authentication building blocks ("secure" auth mode).

Everything here is inert unless VULNERSHOP_AUTH_MODE=secure (see app/config.py);
in the default "vulnerable" mode only the template helpers are registered, as
no-ops, so the lab keeps its intentional flaws. Each section names the OWASP
WSTG v4.2 test (section 4.4 Authentication Testing) it exists to satisfy.
"""
import hashlib
import hmac
import logging
import math
import os
import re
import secrets
import sys
import time

from flask import abort, current_app, flash, redirect, request, session
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db, init_auth_tables
from app.i18n import t

# --- tunables -----------------------------------------------------------------
LOGIN_MAX_FAILURES = 5          # per username, per window  (WSTG-ATHN-03)
LOGIN_MAX_FAILURES_PER_IP = 20  # per source IP, per window (credential stuffing/spraying)
LOGIN_WINDOW = 15 * 60
RESET_MAX_PER_USER = 3          # reset e-mails per username per hour (WSTG-ATHN-09)
RESET_MAX_PER_IP = 5
RESET_WINDOW = 60 * 60
RESET_TOKEN_TTL = 15 * 60
RESET_TOKEN_GUESS_MAX = 10      # bad reset tokens per IP per window
REGISTER_MAX_PER_IP = 10
REGISTER_WINDOW = 60 * 60
PASSWORD_HISTORY = 5
PASSWORD_MIN_LEN = 10           # WSTG-ATHN-07 (NIST SP 800-63B: length over composition)
PASSWORD_MAX_LEN = 128          # bound the hashing work an attacker can force
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")

audit_log = logging.getLogger("vulnershop.auth")
mail_log = logging.getLogger("vulnershop.mail")

# --- audit log & simulated mail -----------------------------------------------


def _clean(value):
    # Strip anything that could forge extra log lines (CWE-117).
    return re.sub(r"[^\x20-\x7e]", "?", str(value))[:80]


def audit(event, **fields):
    parts = [f"event={event}", f"ip={_clean(request.remote_addr)}"]
    parts += [f"{k}={_clean(v)}" for k, v in fields.items()]
    audit_log.info(" ".join(parts))


def send_email(to, subject, body):
    """Stand-in for SMTP: the "mailbox" is the server log (docker compose logs -f).

    There is deliberately no web page that shows it - the vulnerable build's
    /dev/last-reset debug page is exactly the flaw WSTG-ATHN-09 warns about.
    """
    mail_log.info("[SIMULATED EMAIL] to=%s subject=%s\n%s", _clean(to), _clean(subject), body)


# --- password storage (WSTG-ATHN-07, CRYP-04) ----------------------------------

_LEGACY_MD5 = re.compile(r"^[0-9a-f]{32}$")
_dummy_hash = None


def hash_password_secure(password):
    return generate_password_hash(password)  # salted scrypt (werkzeug default)


def verify_password(stored_hash, password):
    """Check a password; transparently accepts pre-migration unsalted MD5 hashes."""
    if _LEGACY_MD5.match(stored_hash or ""):
        candidate = hashlib.md5(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate, stored_hash)
    return check_password_hash(stored_hash, password)


def needs_rehash(stored_hash):
    return bool(_LEGACY_MD5.match(stored_hash or ""))


def burn_password_check(password):
    """Spend the same time as a real check so unknown usernames aren't timing-distinguishable."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = generate_password_hash(secrets.token_hex(8))
    check_password_hash(_dummy_hash, password)


# --- password policy (WSTG-ATHN-07) --------------------------------------------

_COMMON_BASES = {
    "password", "passw0rd", "admin", "administrator", "qwerty", "qwertyuiop", "letmein",
    "welcome", "iloveyou", "monkey", "dragon", "football", "baseball", "master", "shadow",
    "superman", "trustno", "changeme", "secret", "supersecret", "abc", "login", "princess",
    "sunshine", "starwars", "whatever", "freedom", "hello", "root", "toor", "test", "guest",
    "default", "nourisec", "nourishop", "vulnershop", "alice", "bobby", "iranian", "tehran",
    "asdfghjkl", "zxcvbnm", "1q2w3e4r", "q1w2e3r4",
}


def validate_password(password, username="", email=""):
    """Return a list of (i18n_key, kwargs) problems; empty means acceptable."""
    problems = []
    if len(password) < PASSWORD_MIN_LEN:
        problems.append(("auth.pw_too_short", {"min": PASSWORD_MIN_LEN}))
    if len(password) > PASSWORD_MAX_LEN:
        problems.append(("auth.pw_too_long", {"max": PASSWORD_MAX_LEN}))
    lowered = password.lower()
    base = re.sub(r"[\d\W_]+$", "", lowered)  # "Password1!" -> "password"
    if (
        not any(c.isalpha() for c in password)
        or lowered in _COMMON_BASES
        or base in _COMMON_BASES
        or len(set(password)) < 5
    ):
        problems.append(("auth.pw_common", {}))
    for ident in (username, email.split("@")[0] if email else ""):
        if len(ident) >= 3 and ident.lower() in lowered:
            problems.append(("auth.pw_has_username", {}))
            break
    return problems


def flash_password_problems(problems):
    for key, kwargs in problems:
        flash(t(key, **kwargs), "danger")


def password_in_history(user_id, new_password):
    db = get_db()
    rows = db.execute(
        "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?",
        (user_id, PASSWORD_HISTORY),
    ).fetchall()
    current = db.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    hashes = [r["password_hash"] for r in rows] + ([current["password_hash"]] if current else [])
    return any(verify_password(h, new_password) for h in hashes)


def set_password(user_id, new_password):
    """Store a new password and remember the old hash for reuse checks."""
    db = get_db()
    old = db.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    if old:
        db.execute(
            "INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)",
            (user_id, old["password_hash"], time.time()),
        )
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password_secure(new_password), user_id),
    )
    db.commit()


# --- attempt throttling / lockout (WSTG-ATHN-03) -------------------------------


def throttle_remaining(kind, subject, limit, window):
    """Seconds until `subject` may try `kind` again (0 = allowed now)."""
    now = time.time()
    rows = get_db().execute(
        "SELECT created_at FROM auth_attempts WHERE kind = ? AND subject = ? AND created_at > ? "
        "ORDER BY created_at DESC LIMIT ?",
        (kind, subject, now - window, limit),
    ).fetchall()
    if len(rows) < limit:
        return 0
    return max(1, math.ceil(rows[-1]["created_at"] + window - now))


def record_attempt(kind, subject):
    db = get_db()
    now = time.time()
    db.execute("DELETE FROM auth_attempts WHERE created_at < ?", (now - 24 * 3600,))
    db.execute(
        "INSERT INTO auth_attempts (kind, subject, created_at) VALUES (?, ?, ?)", (kind, subject, now)
    )
    db.commit()


def clear_attempts(kind, subject):
    db = get_db()
    db.execute("DELETE FROM auth_attempts WHERE kind = ? AND subject = ?", (kind, subject))
    db.commit()


def user_subject(username):
    return "user:" + username.strip().lower()[:64]


def ip_subject():
    return "ip:" + (request.remote_addr or "?")


def flash_throttled(seconds):
    flash(t("auth.flash_throttled", minutes=max(1, math.ceil(seconds / 60))), "danger")


# --- server-side sessions (WSTG-ATHN-04, SESS-03/06/07) ------------------------


def _hash_sid(sid):
    return hashlib.sha256(sid.encode()).hexdigest()


def _drop_auth_keys():
    for key in ("sid", "user_id", "username", "role"):
        session.pop(key, None)


def start_session(user):
    """Log `user` in under a brand-new session id and CSRF token (anti-fixation)."""
    old_sid = session.get("sid")
    if old_sid:
        get_db().execute("DELETE FROM auth_sessions WHERE sid_hash = ?", (_hash_sid(old_sid),))
    cart = session.get("cart")
    lang = session.get("lang")
    session.clear()
    if cart:
        session["cart"] = cart
    if lang:
        session["lang"] = lang
    sid = secrets.token_urlsafe(32)
    now = time.time()
    db = get_db()
    db.execute(
        "INSERT INTO auth_sessions (sid_hash, user_id, created_at, last_seen, ip, user_agent) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (_hash_sid(sid), user["id"], now, now, request.remote_addr, (request.user_agent.string or "")[:200]),
    )
    db.commit()
    session.permanent = True
    session["sid"] = sid
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]


def end_session():
    sid = session.get("sid")
    if sid:
        db = get_db()
        db.execute("DELETE FROM auth_sessions WHERE sid_hash = ?", (_hash_sid(sid),))
        db.commit()
    session.clear()


def revoke_sessions(user_id, except_sid=None):
    db = get_db()
    if except_sid:
        db.execute(
            "DELETE FROM auth_sessions WHERE user_id = ? AND sid_hash != ?",
            (user_id, _hash_sid(except_sid)),
        )
    else:
        db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
    db.commit()


def _load_session():
    sid = session.get("sid")
    if not sid:
        if "user_id" in session:  # no server-side record: forged or pre-secure-mode cookie
            _drop_auth_keys()
        return
    db = get_db()
    now = time.time()
    row = db.execute("SELECT * FROM auth_sessions WHERE sid_hash = ?", (_hash_sid(sid),)).fetchone()
    cfg = current_app.config
    user = None
    if row and (
        now - row["last_seen"] <= cfg["SESSION_IDLE_TIMEOUT"]
        and now - row["created_at"] <= cfg["SESSION_ABSOLUTE_TIMEOUT"]
    ):
        user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if not user:
        if row:
            db.execute("DELETE FROM auth_sessions WHERE sid_hash = ?", (row["sid_hash"],))
            db.commit()
        _drop_auth_keys()
        flash(t("auth.flash_session_expired"), "warning")
        return
    db.execute("UPDATE auth_sessions SET last_seen = ? WHERE sid_hash = ?", (now, row["sid_hash"]))
    db.commit()
    # Role/username always come from the DB, never trusted from the cookie.
    session["user_id"], session["username"], session["role"] = user["id"], user["username"], user["role"]


# --- CSRF (WSTG-SESS-05; protects login, reset and password-change forms) --------


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def _check_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    if not hmac.compare_digest(sent, session.get("_csrf", "\0")):
        audit("csrf_rejected", path=request.path)
        abort(400, description="Invalid or missing CSRF token.")


# --- wiring ---------------------------------------------------------------------


def _csrf_input():
    return Markup('<input type="hidden" name="csrf_token" value="%s">') % csrf_token()


def init_security(app):
    secure = app.config["AUTH_SECURE"]

    @app.context_processor
    def security_helpers():
        if secure:
            return {"csrf_input": _csrf_input, "AUTH_SECURE": True}
        return {"csrf_input": lambda: "", "AUTH_SECURE": False}

    if not secure:
        return

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(message)s"))
    base_log = logging.getLogger("vulnershop")
    base_log.setLevel(logging.INFO)
    if not base_log.handlers:
        base_log.addHandler(handler)
    base_log.propagate = False

    with app.app_context():
        init_auth_tables()  # upgrade a database that predates secure mode

    if os.environ.get("TRUST_PROXY") == "1":  # behind a TLS-terminating reverse proxy
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def _secure_before_request():
        if request.endpoint == "static":
            return
        # WSTG-ATHN-01: never serve credential forms over plain HTTP when HTTPS is enforced.
        if app.config["FORCE_HTTPS"] and not request.is_secure:
            return redirect(request.url.replace("http://", "https://", 1), code=301)
        _load_session()
        _check_csrf()

    @app.after_request
    def _secure_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"  # login-page clickjacking
        resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        # Keeps reset tokens in URLs out of Referer headers sent to other sites.
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            # WSTG-ATHN-06: authenticated and credential pages must not be cached, so the
            # Back button after logout cannot replay them.
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
        return resp
