from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.db import get_db
from app.i18n import t
from app.models import get_order, get_order_items, get_orders_for_user, get_user_by_id, hash_password

account_bp = Blueprint("account", __name__)


def _require_login():
    return "user_id" in session


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
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(new_password), session["user_id"]),
    )
    db.commit()
    flash(t("account.flash_password_updated"), "success")
    return redirect(url_for("account.profile", user_id=session["user_id"]))
