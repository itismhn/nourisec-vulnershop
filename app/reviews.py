from flask import Blueprint, abort, current_app, flash, redirect, request, session, url_for

from app import validation
from app.db import get_db
from app.i18n import t
from app.models import get_product

reviews_bp = Blueprint("reviews", __name__)


@reviews_bp.route("/product/<int:product_id>/review", methods=["POST"])
def add_review(product_id):
    if "user_id" not in session:
        flash(t("reviews.flash_login_to_review"), "warning")
        return redirect(url_for("auth.login"))

    if current_app.config["AUTH_SECURE"]:
        # WSTG-INPV-02: bounded text + 1..5 rating for a product that exists. The body is
        # stored as typed and HTML-encoded on output (product.html), not "sanitised" here.
        if not get_product(product_id):
            abort(404)
        body = request.form.get("body", "").strip()
        rating = validation.form_int("rating", 1, 5) if "rating" in request.form else 5
        if not body or len(body) > validation.REVIEW_MAX_LEN or rating is None:
            flash(t("input.flash_invalid"), "danger")
            return redirect(url_for("shop.product_detail", product_id=product_id))
    else:
        body = request.form.get("body", "")
        rating = int(request.form.get("rating", 5) or 5)

    # VULN: Stored XSS (WSTG-INPV-02) - the review body is stored raw and rendered
    # with |safe in product.html, so a payload like <script>alert(document.cookie)</script>
    # executes for every visitor who views the product page afterwards.
    db = get_db()
    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body, rating) VALUES (?, ?, ?, ?, ?)",
        (product_id, session["user_id"], session["username"], body, rating),
    )
    db.commit()
    flash(t("reviews.flash_review_submitted"), "success")
    return redirect(url_for("shop.product_detail", product_id=product_id))
