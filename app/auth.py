import hashlib

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.db import get_db
from app.i18n import t
from app.models import create_user, get_user_by_id, get_user_by_username, hash_password

auth_bp = Blueprint("auth", __name__)

# In-memory "last reset link" store, simulating a debug leftover page.
# VULN: Broken Authentication (WSTG-ATHN-04) - see /dev/last-reset in app/__init__.py
LAST_RESET = {"link": None, "username": None}


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
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
    session.clear()
    flash(t("auth.flash_logged_out"), "info")
    return redirect(url_for("shop.index"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
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
