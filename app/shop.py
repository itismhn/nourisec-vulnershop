import sqlite3
import time

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for

from app import commerce
from app import security as sec
from app import validation
from app.db import get_db
from app.i18n import t
from app.models import (
    get_product,
    get_product_sold_count,
    get_reviews,
    list_products,
    list_related_products,
)

shop_bp = Blueprint("shop", __name__)

CATEGORIES = [
    "موبایل و دیجیتال",
    "خواربار ایرانی",
    "مد و پوشاک",
    "زیبایی و سلامت",
    "صنایع‌دستی",
]


@shop_bp.route("/")
def index():
    category = request.args.get("category")
    products = list_products(category)
    return render_template(
        "index.html", products=products, categories=CATEGORIES, active_category=category
    )


@shop_bp.route("/product/<product_id>")
def product_detail(product_id):
    # VULN: Security Misconfiguration - no input validation before int() conversion,
    # combined with DEBUG=True, surfaces a full Werkzeug stack trace for non-numeric
    # IDs (WSTG-ERRH-01). Try /product/abc.
    if current_app.config["AUTH_SECURE"] and not (product_id.isascii() and product_id.isdigit() and len(product_id) < 10):
        abort(404)  # secure mode: validate the id before using it, so no stack trace
    product = get_product(int(product_id))
    if not product:
        flash(t("shop.flash_product_not_found"), "warning")
        return redirect(url_for("shop.index"))
    reviews = get_reviews(product["id"])
    sold_count = get_product_sold_count(product["id"])
    related = list_related_products(product["category"], product["id"])
    return render_template(
        "product.html", product=product, reviews=reviews, sold_count=sold_count, related=related
    )


@shop_bp.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()

    if current_app.config["AUTH_SECURE"]:
        # WSTG-INPV-05: parameterised query, LIKE wildcards escaped, no database error text shown.
        like = validation.like_pattern(q[: validation.SEARCH_MAX_LEN])
        results = db.execute(
            "SELECT id, name, description, price, image FROM products "
            "WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'",
            (like, like),
        ).fetchall()
        return render_template("search.html", query=q, results=results, error=None)

    # VULN: SQL Injection (WSTG-INPV-05) - string concatenation into a LIKE clause.
    # Column count (5) is chosen to line up with the users table for a teachable
    # UNION-based extraction: ' UNION SELECT id, username, password_hash, email, avatar FROM users --
    query = (
        "SELECT id, name, description, price, image FROM products "
        "WHERE name LIKE '%" + q + "%' OR description LIKE '%" + q + "%'"
    )
    try:
        results = db.execute(query).fetchall()
        error = None
    except Exception as e:
        results = []
        error = str(e)

    # VULN: Reflected XSS (WSTG-INPV-01) - the raw query is rendered back with |safe
    # in search.html instead of being auto-escaped.
    return render_template("search.html", query=q, results=results, error=error)


@shop_bp.route("/cart")
def cart():
    lines, subtotal, discount, total, codes = commerce.cart_totals(session.get("cart", {}))
    return render_template(
        "cart.html", items=lines, subtotal=subtotal, discount=discount, total=total, codes=codes
    )


@shop_bp.route("/cart/add/<int:product_id>", methods=["POST"])
def cart_add(product_id):
    cart_items = session.get("cart", {})
    key = str(product_id)
    if not current_app.config["AUTH_SECURE"]:
        # VULN: Business Logic Data Validation (WSTG-BUSL-01) - any integer is accepted:
        # zero, negative (a "refund" line that cancels out other items), or absurdly large.
        # The purchase limit and stock shown on the product page are never enforced here (BUSL-05).
        cart_items[key] = cart_items.get(key, 0) + int(request.form.get("qty", 1))
    else:
        cfg = current_app.config
        # WSTG-INPV-04/05 + BUSL-01: exactly one integer in 1..MAX_QTY_PER_LINE (a repeated qty
        # field is rejected, not resolved first-wins or last-wins), capped per cart line.
        qty = validation.form_int("qty", 1, cfg["MAX_QTY_PER_LINE"]) if "qty" in request.form else 1
        if not get_product(product_id):
            abort(404)
        new_qty = cart_items.get(key, 0) + (qty or 0)
        if qty is None or new_qty > cfg["MAX_QTY_PER_LINE"]:
            flash(t("shop.flash_qty_invalid", max=cfg["MAX_QTY_PER_LINE"]), "danger")
            return redirect(request.referrer or url_for("shop.index"))
        if key not in cart_items and len(cart_items) >= cfg["MAX_CART_LINES"]:
            flash(t("shop.flash_cart_invalid"), "danger")
            return redirect(request.referrer or url_for("shop.index"))
        problem = commerce.cart_problem({key: new_qty}, session.get("user_id"))
        if problem:  # per-customer purchase limit and stock, checked on the add itself
            flash(t(problem), "danger")
            return redirect(request.referrer or url_for("shop.index"))
        cart_items = dict(cart_items, **{key: new_qty})
    session["cart"] = cart_items
    flash(t("shop.flash_added_to_cart"), "success")
    return redirect(request.referrer or url_for("shop.index"))


@shop_bp.route("/cart/remove/<int:product_id>", methods=["POST"])
def cart_remove(product_id):
    cart_items = session.get("cart", {})
    cart_items.pop(str(product_id), None)
    session["cart"] = cart_items
    return redirect(url_for("shop.cart"))


@shop_bp.route("/cart/coupon", methods=["POST"])
def cart_coupon():
    code = request.form.get("code", "").strip()
    secure = current_app.config["AUTH_SECURE"]
    if not secure:
        # VULN: Number of Times a Function Can Be Used (WSTG-BUSL-05) - the code is looked up
        # but never checked for expiry or earlier use, and every application is appended to a
        # list, so one code can be stacked as often as you like. Wrong guesses are free
        # (WSTG-BUSL-07: no throttling, no logging).
        coupon = commerce.get_coupon(code)
        if not coupon:
            flash(t("shop.flash_coupon_invalid"), "danger")
        else:
            session["coupons"] = session.get("coupons", []) + [coupon["code"]]
            flash(t("shop.flash_coupon_applied"), "success")
        return redirect(url_for("shop.cart"))

    user_id = session.get("user_id")
    if not user_id:
        flash(t("shop.flash_login_to_coupon"), "warning")
        return redirect(url_for("auth.login"))
    subject = f"user:{user_id}"
    wait = sec.throttle_remaining("coupon", subject, commerce.COUPON_MAX_BAD, commerce.COUPON_WINDOW)
    if wait:
        sec.audit("coupon_throttled", user=session.get("username"))
        abort(429)
    coupon = commerce.get_coupon(code[:32])
    if not commerce.coupon_redeemable(coupon, user_id):
        # One message for unknown, expired and already-used codes: no oracle for guessing.
        sec.record_attempt("coupon", subject)
        sec.audit("coupon_rejected", user=session.get("username"))
        flash(t("shop.flash_coupon_invalid"), "danger")
    else:
        session["coupon"] = coupon["code"]  # one code per cart; applying again replaces it
        flash(t("shop.flash_coupon_applied"), "success")
    return redirect(url_for("shop.cart"))


@shop_bp.route("/checkout", methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        flash(t("shop.flash_login_to_checkout"), "warning")
        return redirect(url_for("auth.login"))

    cart_items = session.get("cart", {})
    if not cart_items:
        flash(t("shop.flash_cart_empty"), "info")
        return redirect(url_for("shop.cart"))

    lines, subtotal, discount, total, codes = commerce.cart_totals(cart_items)
    if request.method == "GET":
        return render_template(
            "checkout.html", items=lines, subtotal=subtotal, discount=discount, total=total
        )

    if current_app.config["AUTH_SECURE"]:
        return _checkout_secure(cart_items)

    # VULN: Integrity Checks (WSTG-BUSL-03) - the amount to charge is read back from a hidden
    # form field instead of being recomputed from server-side prices. Edit it in the browser
    # dev tools or in Burp.
    posted = request.form.get("total", "")
    if posted:
        total = float(posted)
    db = get_db()
    # VULN: Process Timing (WSTG-BUSL-04) - stock is checked, then (after the simulated payment
    # gateway latency) decremented in a separate step. Two parallel checkouts both pass the
    # check and oversell the item. Negative quantities even *add* stock.
    for line in lines:
        if line["qty"] > 0 and line["product"]["stock"] < line["qty"]:
            flash(t("shop.flash_out_of_stock"), "danger")
            return redirect(url_for("shop.cart"))
    time.sleep(current_app.config["CHECKOUT_LATENCY"])
    for line in lines:
        db.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (line["qty"], line["product"]["id"]))
    order_id = _create_order(db, session["user_id"], lines, subtotal, discount, total, codes[-1] if codes else None)
    db.commit()
    session["cart"] = {}
    session.pop("coupons", None)
    return redirect(url_for("payments.pay", order_id=order_id))


class _CheckoutRefused(Exception):
    def __init__(self, key):
        self.key = key


def _checkout_secure(cart_items):
    """Server-side checkout: nothing the browser sends decides the price, stock or discount."""
    user_id = session["user_id"]
    problem = commerce.cart_problem(cart_items, user_id)
    if problem:
        flash(t(problem), "danger")
        return redirect(url_for("shop.cart"))
    db = get_db()
    try:
        time.sleep(current_app.config["CHECKOUT_LATENCY"])
        # WSTG-BUSL-04: reserve stock with a guarded UPDATE. The first one takes SQLite's write
        # lock, so every check below sees committed state, and a parallel checkout cannot slip
        # between "is there stock?" and "take it".
        for product_id, qty in cart_items.items():
            cur = db.execute(
                "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?", (qty, int(product_id), qty)
            )
            if cur.rowcount != 1:
                raise _CheckoutRefused("shop.flash_out_of_stock")
        # Purchase limits are re-checked under the lock too (two tabs, one customer).
        for product_id, qty in cart_items.items():
            product = get_product(int(product_id))
            limit = product["purchase_limit"]
            if limit and qty + commerce.purchased_qty(user_id, product["id"]) > limit:
                raise _CheckoutRefused("shop.flash_limit_reached")
        # Totals come from the database, and the coupon is validated again *now* (it may have
        # expired, or been used in another tab, since it was applied to the cart).
        lines, subtotal, discount, total, codes = commerce.cart_totals(cart_items)
        code = codes[0] if codes else None
        order_id = _create_order(db, user_id, lines, subtotal, discount, total, code)
        if code:
            db.execute(
                "INSERT INTO coupon_redemptions (code, user_id, order_id) VALUES (?, ?, ?)", (code, user_id, order_id)
            )
        db.commit()
    except _CheckoutRefused as refusal:
        db.rollback()
        flash(t(refusal.key), "danger")
        return redirect(url_for("shop.cart"))
    except sqlite3.IntegrityError:  # coupon redeemed by a parallel request
        db.rollback()
        flash(t("shop.flash_coupon_invalid"), "danger")
        return redirect(url_for("shop.cart"))
    session["cart"] = {}
    session.pop("coupon", None)
    sec.audit("order_created", user=session.get("username"), order=order_id)
    return redirect(url_for("payments.pay", order_id=order_id))


def _create_order(db, user_id, lines, subtotal, discount, total, coupon_code):
    cur = db.execute(
        "INSERT INTO orders (user_id, total, subtotal, discount, coupon_code, status) "
        "VALUES (?, ?, ?, ?, ?, 'pending_payment')",
        (user_id, total, subtotal, discount, coupon_code),
    )
    order_id = cur.lastrowid
    for line in lines:
        db.execute(
            "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
            (order_id, line["product"]["id"], line["qty"], line["product"]["price"]),
        )
    return order_id
