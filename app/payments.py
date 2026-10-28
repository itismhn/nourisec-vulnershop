"""Order payment, cancellation and refund workflow (WSTG-BUSL-02/04/05/06/07).

Happy path: checkout creates an order as `pending_payment`; paying it moves it to `paid`;
a paid order can be refunded once within the return window. The vulnerable build lets a
customer skip or repeat steps; secure mode makes the server the only authority on state.
"""
import re

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for

from app import commerce
from app import security as sec
from app.db import get_db
from app.i18n import t
from app.models import get_order, get_order_items

payments_bp = Blueprint("payments", __name__)

DECLINED_TEST_CARD = "4000000000000002"


def _luhn_ok(number):
    digits = [int(c) for c in number][::-1]
    if not 13 <= len(digits) <= 19:
        return False
    total = sum(digits[0::2]) + sum(sum(divmod(d * 2, 10)) for d in digits[1::2])
    return total % 10 == 0


def _my_order(order_id):
    """Owner-only for every order *action* in both builds, so BUSL tests never depend on IDOR."""
    order = get_order(order_id)
    if not order or order["user_id"] != session.get("user_id"):
        abort(404)
    return order


def _restock(order_id):
    db = get_db()
    for item in get_order_items(order_id):
        db.execute("UPDATE products SET stock = stock + ? WHERE id = ?", (item["quantity"], item["product_id"]))


def _expire_if_stale(order):
    """Secure mode (WSTG-BUSL-04): an unpaid order only holds its stock for ORDER_PAY_WINDOW."""
    age = (commerce.utcnow() - commerce.parse_ts(order["created_at"])).total_seconds()
    if order["status"] == "pending_payment" and age > current_app.config["ORDER_PAY_WINDOW"]:
        db = get_db()
        if db.execute(
            "UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending_payment'", (order["id"],)
        ).rowcount:
            _restock(order["id"])
        db.commit()
        sec.audit("order_expired", order=order["id"])
        return True
    return False


@payments_bp.route("/orders/<int:order_id>/pay", methods=["GET", "POST"])
def pay(order_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    order = _my_order(order_id)
    secure = current_app.config["AUTH_SECURE"]
    detail = url_for("account.order_detail", order_id=order_id)

    if secure:
        if _expire_if_stale(order):
            flash(t("pay.flash_expired"), "warning")
            return redirect(detail)
        if order["status"] != "pending_payment":
            flash(t("pay.flash_not_payable"), "warning")
            return redirect(detail)
    # VULN: Circumvention of Work Flows (WSTG-BUSL-06) - the vulnerable build never checks the
    # order's current state here, so cancelled, refunded and already-paid orders can be "paid".
    if request.method == "GET":
        return render_template("pay.html", order=order)

    subject = f"user:{session['user_id']}"
    if secure:
        # WSTG-BUSL-07: card-testing defence - repeated declines lock payment for a while.
        if sec.throttle_remaining("card", subject, commerce.CARD_MAX_DECLINES, commerce.CARD_WINDOW):
            sec.audit("card_throttled", user=session.get("username"))
            abort(429)
    card = re.sub(r"[\s-]", "", request.form.get("card_number", ""))
    if not (card.isdigit() and _luhn_ok(card)) or card == DECLINED_TEST_CARD:
        if secure:
            sec.record_attempt("card", subject)
            sec.audit("card_declined", user=session.get("username"), order=order_id)
        # VULN (BUSL-07): unlimited declines, so the endpoint doubles as a free card-validity oracle.
        flash(t("pay.declined"), "danger")
        return render_template("pay.html", order=order), 402

    if secure:
        # The server marks the order paid itself, atomically, only from `pending_payment`.
        cur = get_db().execute(
            "UPDATE orders SET status = 'paid' WHERE id = ? AND status = 'pending_payment'", (order_id,)
        )
        get_db().commit()
        if cur.rowcount:
            sec.audit("order_paid", user=session.get("username"), order=order_id)
        flash(t("shop.flash_order_success"), "success")
        return redirect(detail)
    # VULN: Ability to Forge Requests (WSTG-BUSL-02) - the "gateway" reports back by redirecting
    # the browser to /payment/callback with the result in the query string.
    return redirect(url_for("payments.callback", order_id=order_id, status="success"))


@payments_bp.route("/payment/callback")
def callback():
    if current_app.config["AUTH_SECURE"]:
        abort(404)  # secure mode has no browser-reachable payment callback at all
    # VULN: Ability to Forge Requests / Circumvention of Work Flows (WSTG-BUSL-02/06) - anyone
    # can call this URL with any order id and status=success. No signature, no login, no check
    # that a payment happened, that the order is pending, or that the amount matches.
    order_id = request.args.get("order_id", type=int)
    status = "paid" if request.args.get("status") == "success" else "payment_failed"
    db = get_db()
    db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    db.commit()
    flash(t("pay.flash_paid" if status == "paid" else "pay.flash_failed"), "info")
    return redirect(url_for("account.order_detail", order_id=order_id or 0))


@payments_bp.route("/orders/<int:order_id>/cancel", methods=["POST"])
def cancel(order_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    order = _my_order(order_id)
    db = get_db()
    detail = url_for("account.order_detail", order_id=order_id)
    if current_app.config["AUTH_SECURE"]:
        # Only an unpaid order can be cancelled, once; stock goes back exactly once.
        cur = db.execute("UPDATE orders SET status = 'cancelled' WHERE id = ? AND status = 'pending_payment'", (order_id,))
        if not cur.rowcount:
            flash(t("orders.flash_cannot_cancel"), "danger")
            return redirect(detail)
        _restock(order_id)
        sec.audit("order_cancelled", user=session.get("username"), order=order_id)
    else:
        # VULN (BUSL-05/06): any state, any number of times - and every call restocks again,
        # so repeating it inflates the stock count.
        db.execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order_id,))
        _restock(order_id)
    db.commit()
    flash(t("orders.flash_cancelled"), "info")
    return redirect(detail)


@payments_bp.route("/orders/<int:order_id>/refund", methods=["POST"])
def refund(order_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    order = _my_order(order_id)
    db = get_db()
    detail = url_for("account.order_detail", order_id=order_id)
    if current_app.config["AUTH_SECURE"]:
        age_days = (commerce.utcnow() - commerce.parse_ts(order["created_at"])).days
        if age_days >= current_app.config["REFUND_WINDOW_DAYS"]:
            flash(t("orders.flash_cannot_refund"), "danger")
            return redirect(detail)
        # Paid orders only, and only once: the status flip is the lock.
        cur = db.execute(
            "UPDATE orders SET status = 'refunded', refunded = total "
            "WHERE id = ? AND status IN ('paid', 'completed') AND total > 0",
            (order_id,),
        )
        if not cur.rowcount:
            flash(t("orders.flash_cannot_refund"), "danger")
            return redirect(detail)
        _restock(order_id)
        sec.audit("order_refunded", user=session.get("username"), order=order_id)
    else:
        # VULN (BUSL-05/06): no check that the order was ever paid, is inside the return window,
        # or was already refunded - every call pays out the order total again.
        db.execute("UPDATE orders SET status = 'refunded', refunded = refunded + total WHERE id = ?", (order_id,))
    db.commit()
    flash(t("orders.flash_refunded"), "info")
    return redirect(detail)
