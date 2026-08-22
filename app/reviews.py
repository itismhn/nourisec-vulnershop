from flask import Blueprint, flash, redirect, request, session, url_for

from app.db import get_db

reviews_bp = Blueprint("reviews", __name__)


@reviews_bp.route("/product/<int:product_id>/review", methods=["POST"])
def add_review(product_id):
    if "user_id" not in session:
        flash("Please log in to leave a review.", "warning")
        return redirect(url_for("auth.login"))

    body = request.form.get("body", "")

    # VULN: Stored XSS (WSTG-INPV-02) - the review body is stored raw and rendered
    # with |safe in product.html, so a payload like <script>alert(document.cookie)</script>
    # executes for every visitor who views the product page afterwards.
    db = get_db()
    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body) VALUES (?, ?, ?, ?)",
        (product_id, session["user_id"], session["username"], body),
    )
    db.commit()
    flash("Review posted.", "success")
    return redirect(url_for("shop.product_detail", product_id=product_id))
