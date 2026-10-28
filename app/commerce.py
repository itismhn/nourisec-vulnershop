"""Shared business-logic helpers for cart, coupons and orders (OWASP WSTG v4.2 section 4.10, BUSL).

The vulnerable build trusts the client at almost every step here; the helpers named
`*_secure` / guarded by `AUTH_SECURE` are the hardened behaviour. Rules enforced in
secure mode live in one place so the tests and AUTH_HARDENING.md can point at them.
"""
import datetime

from flask import current_app, session

from app.db import get_db
from app.models import get_product

# Order lifecycle: pending_payment -> paid -> refunded, or pending_payment -> cancelled.
# Seeded orders use the legacy final state "completed", which counts as paid.
PAID_STATES = ("paid", "completed")
LIVE_STATES = ("pending_payment", "paid", "completed")  # these still count against purchase limits

COUPON_MAX_BAD = 5          # wrong codes per customer per window (WSTG-BUSL-07)
COUPON_WINDOW = 15 * 60
CARD_MAX_DECLINES = 5
CARD_WINDOW = 60 * 60
REVIEW_MAX_PER_HOUR = 3
CONTACT_MAX_PER_HOUR = 5
UPLOAD_MAX_PER_HOUR = 5


def is_secure():
    return current_app.config["AUTH_SECURE"]


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def parse_ts(text):
    return datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


# --- cart --------------------------------------------------------------------


def cart_lines(cart):
    """Resolve a session cart into [{product, qty, subtotal}], skipping unknown products."""
    lines = []
    for product_id, qty in cart.items():
        product = get_product(int(product_id))
        if product:
            lines.append({"product": product, "qty": qty, "subtotal": product["price"] * qty})
    return lines


def purchased_qty(user_id, product_id):
    """Units of a product this customer already has on live (unpaid or paid) orders."""
    row = get_db().execute(
        "SELECT COALESCE(SUM(oi.quantity), 0) AS n FROM order_items oi "
        "JOIN orders o ON o.id = oi.order_id "
        "WHERE o.user_id = ? AND oi.product_id = ? AND o.status IN (?, ?, ?)",
        (user_id, product_id, *LIVE_STATES),
    ).fetchone()
    return row["n"]


def cart_problem(cart, user_id):
    """Secure mode: return an i18n key if the cart breaks a business rule, else None."""
    cfg = current_app.config
    if len(cart) > cfg["MAX_CART_LINES"]:
        return "shop.flash_cart_invalid"
    for product_id, qty in cart.items():
        product = get_product(int(product_id))
        if not product or not isinstance(qty, int) or isinstance(qty, bool):
            return "shop.flash_cart_invalid"
        if not 1 <= qty <= cfg["MAX_QTY_PER_LINE"]:
            return "shop.flash_cart_invalid"
        if qty > product["stock"]:
            return "shop.flash_out_of_stock"
        limit = product["purchase_limit"]
        if limit and qty + (purchased_qty(user_id, product["id"]) if user_id else 0) > limit:
            return "shop.flash_limit_reached"
    return None


# --- coupons -----------------------------------------------------------------


def get_coupon(code):
    return get_db().execute("SELECT * FROM coupons WHERE code = ?", (code,)).fetchone()


def coupon_redeemable(coupon, user_id):
    """Secure mode: exists, not expired, and (if single-use) not yet redeemed by this customer."""
    if not coupon:
        return False
    if coupon["expires_at"] < utcnow().strftime("%Y-%m-%d"):
        return False
    if coupon["single_use"] and user_id:
        used = get_db().execute(
            "SELECT 1 FROM coupon_redemptions WHERE code = ? AND user_id = ?", (coupon["code"], user_id)
        ).fetchone()
        if used:
            return False
    return True


def active_coupon_codes():
    """Codes the session currently holds. Vulnerable: a list that can grow without limit."""
    if is_secure():
        code = session.get("coupon")
        return [code] if code else []
    return list(session.get("coupons", []))


def cart_totals(cart):
    """-> (lines, subtotal, discount, total, codes_applied)."""
    lines = cart_lines(cart)
    subtotal = sum(line["subtotal"] for line in lines)
    percent = 0
    applied = []
    for code in active_coupon_codes():
        coupon = get_coupon(code)
        if coupon and (not is_secure() or coupon_redeemable(coupon, session.get("user_id"))):
            percent += coupon["percent"]
            applied.append(coupon["code"])
    if is_secure():
        percent = min(percent, 100)
    # VULN (BUSL-01/05): percentages from stacked codes are added with no ceiling, so enough
    # applications push the total below zero.
    discount = subtotal * percent / 100
    return lines, subtotal, discount, subtotal - discount, applied
