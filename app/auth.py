import hashlib
import secrets
import time

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from app import security as sec
from app.db import get_db
from app.i18n import t
from app.models import create_user, get_user_by_id, get_user_by_username, hash_password

auth_bp = Blueprint("auth", __name__)

# In-memory "last reset link" store, simulating a debug leftover page.
# VULN: Broken Authentication (WSTG-ATHN-04) - see /dev/last-reset in app/__init__.py
LAST_RESET = {"link": None, "username": None}


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_app.config["AUTH_SECURE"]:
        return _register_secure()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # VULN: Broken Authentication - no password complexity/length policy (WSTG-ATHN-07)
        if not username or not password:
            flash(t("auth.flash_username_password_required"), "danger")
            return render_template("register.html")

        if get_user_by_username(username):
            flash(t("auth.flash_username_taken"), "danger")
            return render_template("register.html")

        create_user(username, email, password)
        flash(t("auth.flash_account_created"), "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_app.config["AUTH_SECURE"]:
        return _login_secure()
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = hash_password(password)

        db = get_db()

        # VULN: SQL Injection (WSTG-INPV-05) - string concatenation instead of a
        # parameterized query. Classic bypass: username = ' OR '1'='1' --
        # No rate limiting / lockout either (WSTG-ATHN-03).
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password_hash = '"
            + password_hash
            + "'"
        )
        try:
            user = db.execute(query).fetchone()
        except Exception:
            user = None

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(t("auth.flash_welcome", username=user["username"]), "success")
            return redirect(url_for("shop.index"))

        flash(t("auth.flash_invalid_login"), "danger")
        return render_template("login.html")

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    if current_app.config["AUTH_SECURE"]:
        sec.end_session()  # revokes the server-side session record, not just the cookie
    session.clear()
    flash(t("auth.flash_logged_out"), "info")
    return redirect(url_for("shop.index"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_app.config["AUTH_SECURE"]:
        return _forgot_password_secure()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_user_by_username(username)
        if user:
            # VULN: Broken Authentication - predictable, non-expiring reset token
            # derived only from the username, not a random signed value (WSTG-ATHN-04).
            token = hashlib.md5(f"reset-{username}".encode()).hexdigest()
            db = get_db()
            db.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, user["id"]))
            db.commit()

            reset_link = url_for("auth.reset_password", token=token, _external=True)
            # Simulated "email": in a real deployment this would be emailed. Here it's
            # just stored so the /dev/last-reset debug page can leak it (see above).
            LAST_RESET["link"] = reset_link
            LAST_RESET["username"] = username

        flash(t("auth.flash_reset_link_sent"), "info")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_app.config["AUTH_SECURE"]:
        return _reset_password_secure(token)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()
    if not user:
        flash(t("auth.flash_reset_invalid"), "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        db.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?",
            (hash_password(new_password), user["id"]),
        )
        db.commit()
        flash(t("auth.flash_password_changed"), "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)


# ---------------------------------------------------------------------------
# Hardened implementations (VULNERSHOP_AUTH_MODE=secure). Helpers live in
# app/security.py; the WSTG test each control answers is noted inline.
# ---------------------------------------------------------------------------


def _register_secure():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    wait = sec.throttle_remaining("register", sec.ip_subject(), sec.REGISTER_MAX_PER_IP, sec.REGISTER_WINDOW)
    if wait:
        sec.flash_throttled(wait)
        return render_template("register.html"), 429
    sec.record_attempt("register", sec.ip_subject())

    errors = False
    if not sec.USERNAME_RE.match(username):
        flash(t("auth.flash_username_invalid"), "danger")
        errors = True
    if not sec.EMAIL_RE.match(email) or len(email) > 254:
        flash(t("auth.flash_email_invalid"), "danger")
        errors = True
    problems = sec.validate_password(password, username, email)  # WSTG-ATHN-07
    if problems:
        sec.flash_password_problems(problems)
        errors = True
    if errors:
        return render_template("register.html"), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)).fetchone():
        flash(t("auth.flash_username_taken"), "danger")
        return render_template("register.html"), 409

    create_user(username, email, password)  # role is always "customer"
    sec.audit("register", user=username)
    flash(t("auth.flash_account_created"), "success")
    return redirect(url_for("auth.login"))


def _login_secure():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")[: sec.PASSWORD_MAX_LEN + 1]
    user_key, ip_key = sec.user_subject(username), sec.ip_subject()

    # WSTG-ATHN-03: temporary lockout per account name AND per source IP. Applies to
    # names that do not exist too, so it cannot be used to enumerate accounts. Attempts
    # made while locked are not recorded, so an attacker cannot extend a victim's lockout.
    wait = max(
        sec.throttle_remaining("login", user_key, sec.LOGIN_MAX_FAILURES, sec.LOGIN_WINDOW),
        sec.throttle_remaining("login", ip_key, sec.LOGIN_MAX_FAILURES_PER_IP, sec.LOGIN_WINDOW),
    )
    if wait:
        sec.audit("login_blocked", user=username, retry_after=wait)
        sec.flash_throttled(wait)
        return render_template("login.html"), 429

    # WSTG-ATHN-04: parameterised lookup (no SQL injection auth bypass).
    user = get_user_by_username(username)
    ok = False
    if user:
        ok = sec.verify_password(user["password_hash"], password)
    else:
        sec.burn_password_check(password)  # equalise timing with the "user exists" path

    if not ok:
        sec.record_attempt("login", user_key)
        sec.record_attempt("login", ip_key)
        sec.audit("login_failed", user=username)
        # Same message and status whether the name exists, the password is wrong, or both.
        flash(t("auth.flash_invalid_login"), "danger")
        return render_template("login.html"), 401

    if sec.needs_rehash(user["password_hash"]):  # upgrade legacy unsalted MD5 on first login
        get_db().execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (sec.hash_password_secure(password), user["id"]),
        )
        get_db().commit()
    sec.clear_attempts("login", user_key)
    sec.start_session(user)  # WSTG-ATHN-04: fresh session id + CSRF token on privilege change
    sec.audit("login_ok", user=username)
    flash(t("auth.flash_welcome", username=user["username"]), "success")
    return redirect(url_for("shop.index"))


def _forgot_password_secure():
    if request.method == "GET":
        return render_template("forgot_password.html")

    username = request.form.get("username", "").strip()
    user_key, ip_key = sec.user_subject(username), sec.ip_subject()
    wait = max(
        sec.throttle_remaining("reset", user_key, sec.RESET_MAX_PER_USER, sec.RESET_WINDOW),
        sec.throttle_remaining("reset", ip_key, sec.RESET_MAX_PER_IP, sec.RESET_WINDOW),
    )
    if wait:
        sec.flash_throttled(wait)
        return render_template("forgot_password.html"), 429
    sec.record_attempt("reset", user_key)
    sec.record_attempt("reset", ip_key)

    user = get_user_by_username(username)
    if user:
        db = get_db()
        # WSTG-ATHN-09: a new request invalidates any older outstanding link.
        db.execute("DELETE FROM password_resets WHERE user_id = ?", (user["id"],))
        token = secrets.token_urlsafe(32)  # 256 bits from the OS CSPRNG, unrelated to the username
        db.execute(
            "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hashlib.sha256(token.encode()).hexdigest(), user["id"], time.time() + sec.RESET_TOKEN_TTL),
        )
        db.commit()
        link = url_for("auth.reset_password", token=token, _external=True)
        sec.send_email(
            user["email"],
            "Password reset",
            f"Use this link within {sec.RESET_TOKEN_TTL // 60} minutes (single use):\n{link}",
        )
    sec.audit("reset_requested", user=username, known=bool(user))
    # Identical response whether or not the account exists (no user enumeration).
    flash(t("auth.flash_reset_link_sent"), "info")
    return redirect(url_for("auth.login"))


def _valid_reset_row(token):
    return get_db().execute(
        "SELECT * FROM password_resets WHERE token_hash = ? AND used = 0 AND expires_at > ?",
        (hashlib.sha256(token.encode()).hexdigest(), time.time()),
    ).fetchone()


def _reset_password_secure(token):
    ip_key = sec.ip_subject()
    if sec.throttle_remaining("reset_token", ip_key, sec.RESET_TOKEN_GUESS_MAX, sec.LOGIN_WINDOW):
        return render_template("login.html"), 429  # stop token guessing
    row = _valid_reset_row(token)
    if not row:
        sec.record_attempt("reset_token", ip_key)
        flash(t("auth.flash_reset_invalid"), "danger")
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template("reset_password.html", token=token)

    db = get_db()
    user = get_user_by_id(row["user_id"])
    new_password = request.form.get("password", "")
    problems = sec.validate_password(new_password, user["username"], user["email"])
    if problems:
        sec.flash_password_problems(problems)
        return render_template("reset_password.html", token=token), 400
    if sec.password_in_history(user["id"], new_password):
        flash(t("auth.pw_reused", count=sec.PASSWORD_HISTORY), "danger")
        return render_template("reset_password.html", token=token), 400

    sec.set_password(user["id"], new_password)
    db.execute("UPDATE password_resets SET used = 1 WHERE token_hash = ?", (row["token_hash"],))
    db.commit()
    sec.revoke_sessions(user["id"])  # whoever held the old password is logged out everywhere
    sec.clear_attempts("login", sec.user_subject(user["username"]))
    sec.audit("password_reset", user=user["username"])
    sec.send_email(user["email"], "Your password was changed", "If this wasn't you, contact support immediately.")
    flash(t("auth.flash_password_changed"), "success")
    return redirect(url_for("auth.login"))
