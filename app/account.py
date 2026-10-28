from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for

from app import security as sec
from app.db import get_db
from app.i18n import t
from app.models import get_order, get_order_items, get_orders_for_user, get_user_by_id, hash_password

account_bp = Blueprint("account", __name__)


def _require_login():
    return "user_id" in session


def _reauthenticate(user):
    """Secure mode: require the current password before a sensitive change (WSTG-ATHN-09).

    Returns True when allowed. Failed guesses count toward a lockout, so a hijacked
    session cannot be used to brute-force the password through this form.
    """
    key = f"pwcheck:{user['id']}"
    wait = sec.throttle_remaining("reauth", key, sec.LOGIN_MAX_FAILURES, sec.LOGIN_WINDOW)
    if wait:
        sec.flash_throttled(wait)
        return False
    if not sec.verify_password(user["password_hash"], request.form.get("current_password", "")):
        sec.record_attempt("reauth", key)
        sec.audit("reauth_failed", user=user["username"])
        flash(t("auth.flash_current_password_wrong"), "danger")
        return False
    sec.clear_attempts("reauth", key)
    return True


def _require_owner_or_admin(owner_id):
    """Secure mode (WSTG-ATHZ-04): only the owner or an admin may touch an object.

    Anyone else gets the same 404 as for a non-existent id, so object ids can't be
    enumerated either. The decision uses the DB-backed session, never request input.
    """
    if session.get("role") == "admin" and owner_id is not None:
        return
    if owner_id is not None and session.get("user_id") == owner_id:
        return
    sec.audit("authz_denied", user=session.get("username"), path=request.path)
    abort(404)


@account_bp.route("/profile")
def profile_self():
    if not _require_login():
        return redirect(url_for("auth.login"))
    return redirect(url_for("account.profile", user_id=session["user_id"]))


@account_bp.route("/profile/<int:user_id>")
def profile(user_id):
    if not _require_login():
        return redirect(url_for("auth.login"))

    # VULN: Broken Access Control / IDOR (WSTG-ATHZ-01) - fetches by ID with no
    # check that user_id == session["user_id"]. Any logged-in user can view any
    # other user's profile by changing the number in the URL.
    if current_app.config["AUTH_SECURE"]:
        _require_owner_or_admin(user_id)  # WSTG-ATHZ-04
    user = get_user_by_id(user_id)
    if not user:
        flash(t("account.flash_user_not_found"), "warning")
        return redirect(url_for("shop.index"))

    orders = get_orders_for_user(user_id)
    return render_template("profile.html", profile_user=user, orders=orders)


@account_bp.route("/orders")
def orders():
    if not _require_login():
        return redirect(url_for("auth.login"))
    user_orders = get_orders_for_user(session["user_id"])
    return render_template("orders.html", orders=user_orders)


@account_bp.route("/orders/<int:order_id>")
def order_detail(order_id):
    if not _require_login():
        return redirect(url_for("auth.login"))

    # VULN: Broken Access Control / IDOR (WSTG-ATHZ-01) - no ownership check against
    # session["user_id"]. Incrementing the ID in the URL reveals other customers' orders.
    order = get_order(order_id)
    if current_app.config["AUTH_SECURE"]:
        # WSTG-ATHZ-04: a missing order and someone else's order look identical (404).
        _require_owner_or_admin(order["user_id"] if order else None)
    if not order:
        flash(t("account.flash_order_not_found"), "warning")
        return redirect(url_for("account.orders"))

    items = get_order_items(order_id)
    return render_template("order_detail.html", order=order, items=items)


@account_bp.route("/account/change-email", methods=["POST"])
def change_email():
    if not _require_login():
        return redirect(url_for("auth.login"))

    # VULN: CSRF (WSTG-SESS-05) - state-changing action with no CSRF token, and it
    # accepts a plain form POST from anywhere (no Origin/Referer check either).
    # See app/static/csrf_poc_change_email.html for a demo auto-submitting form.
    new_email = request.form.get("email", "").strip()
    db = get_db()
    if current_app.config["AUTH_SECURE"]:
        user = get_user_by_id(session["user_id"])
        if not sec.EMAIL_RE.match(new_email) or len(new_email) > 254:
            flash(t("auth.flash_email_invalid"), "danger")
            return redirect(url_for("account.profile", user_id=session["user_id"]))
        if not _reauthenticate(user):
            return redirect(url_for("account.profile", user_id=session["user_id"]))
        # The recovery address changed: tell the OLD one so a takeover is noticed.
        sec.send_email(user["email"], "Your e-mail address was changed", f"New address: {new_email}")
        sec.audit("email_changed", user=user["username"])
    db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, session["user_id"]))
    db.commit()
    flash(t("account.flash_email_updated"), "success")
    return redirect(url_for("account.profile", user_id=session["user_id"]))


@account_bp.route("/account/change-password", methods=["POST"])
def change_password():
    if not _require_login():
        return redirect(url_for("auth.login"))

    # VULN: CSRF (WSTG-SESS-05) - no CSRF token; also no "current password" check,
    # making the CSRF impact a full account takeover rather than a nuisance change.
    new_password = request.form.get("password", "")
    db = get_db()
    if current_app.config["AUTH_SECURE"]:
        return _change_password_secure(new_password)
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(new_password), session["user_id"]),
    )
    db.commit()
    flash(t("account.flash_password_updated"), "success")
    return redirect(url_for("account.profile", user_id=session["user_id"]))


def _change_password_secure(new_password):
    profile_url = url_for("account.profile", user_id=session["user_id"])
    user = get_user_by_id(session["user_id"])
    if not _reauthenticate(user):
        return redirect(profile_url)
    problems = sec.validate_password(new_password, user["username"], user["email"])
    if problems:
        sec.flash_password_problems(problems)
        return redirect(profile_url)
    if sec.password_in_history(user["id"], new_password):
        flash(t("auth.pw_reused", count=sec.PASSWORD_HISTORY), "danger")
        return redirect(profile_url)

    sec.set_password(user["id"], new_password)
    # Kill every other session and re-issue this one, so a stolen cookie dies with the old password.
    sec.revoke_sessions(user["id"])
    sec.start_session(get_user_by_id(user["id"]))
    sec.audit("password_changed", user=user["username"])
    sec.send_email(user["email"], "Your password was changed", "If this wasn't you, contact support immediately.")
    flash(t("account.flash_password_updated"), "success")
    return redirect(profile_url)
