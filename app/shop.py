from flask import Blueprint, flash, redirect, render_template, request, session, url_for

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
    cart_items = session.get("cart", {})
    products = []
    total = 0.0
    for product_id, qty in cart_items.items():
        product = get_product(int(product_id))
        if product:
            subtotal = product["price"] * qty
            total += subtotal
            products.append({"product": product, "qty": qty, "subtotal": subtotal})
    return render_template("cart.html", items=products, total=total)


@shop_bp.route("/cart/add/<int:product_id>", methods=["POST"])
def cart_add(product_id):
    cart_items = session.get("cart", {})
    key = str(product_id)
    cart_items[key] = cart_items.get(key, 0) + int(request.form.get("qty", 1))
    session["cart"] = cart_items
    flash(t("shop.flash_added_to_cart"), "success")
    return redirect(request.referrer or url_for("shop.index"))


@shop_bp.route("/cart/remove/<int:product_id>", methods=["POST"])
def cart_remove(product_id):
    cart_items = session.get("cart", {})
    cart_items.pop(str(product_id), None)
    session["cart"] = cart_items
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

    if request.method == "POST":
        # Fake payment step only - no real gateway, no card data persisted.
        db = get_db()
        total = 0.0
        line_items = []
        for product_id, qty in cart_items.items():
            product = get_product(int(product_id))
            if product:
                total += product["price"] * qty
                line_items.append((product["id"], qty, product["price"]))

        cur = db.execute(
            "INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'completed')",
            (session["user_id"], total),
        )
        order_id = cur.lastrowid
        for product_id, qty, price in line_items:
            db.execute(
                "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                (order_id, product_id, qty, price),
            )
        db.commit()
        session["cart"] = {}
        flash(t("shop.flash_order_success"), "success")
        return redirect(url_for("account.order_detail", order_id=order_id))

    return render_template("checkout.html")
