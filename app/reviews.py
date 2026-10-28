from flask import Blueprint, abort, current_app, flash, redirect, request, session, url_for

from app import commerce
from app import security as sec
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

    body = request.form.get("body", "")
    db = get_db()
    back = url_for("shop.product_detail", product_id=product_id)

    if current_app.config["AUTH_SECURE"]:
        user_id = session["user_id"]
        subject = f"user:{user_id}"
        # WSTG-BUSL-07: review flooding is throttled (and logged), not silently dropped.
        if sec.throttle_remaining("review", subject, commerce.REVIEW_MAX_PER_HOUR, 3600):
            sec.audit("review_throttled", user=session.get("username"))
            abort(429)
        sec.record_attempt("review", subject)
        # WSTG-INPV-02 / BUSL-01: bounded text + 1..5 rating for a product that exists. The body is
        # stored as typed and HTML-encoded on output (product.html), not "sanitised" here.
        if not get_product(product_id):
            abort(404)
        body = body.strip()
        rating = validation.form_int("rating", 1, 5) if "rating" in request.form else 5
        if not body or len(body) > validation.REVIEW_MAX_LEN or rating is None:
            flash(t("input.flash_invalid"), "danger")
            return redirect(back)
        # BUSL-06: only customers with a paid order for this product can review it ...
        bought = db.execute(
            "SELECT 1 FROM order_items oi JOIN orders o ON o.id = oi.order_id "
            "WHERE o.user_id = ? AND oi.product_id = ? AND o.status IN ('paid', 'completed')",
            (user_id, product_id),
        ).fetchone()
        if not bought:
            flash(t("reviews.flash_purchase_required"), "danger")
            return redirect(back)
        # ... and BUSL-05: once.
        if db.execute("SELECT 1 FROM reviews WHERE product_id = ? AND user_id = ?", (product_id, user_id)).fetchone():
            flash(t("reviews.flash_already_reviewed"), "danger")
            return redirect(back)
    else:
        # VULN: Business Logic Data Validation (WSTG-BUSL-01) - the rating is any integer, so
        # 9999 or -50 drags the product's average anywhere; no length cap on the body.
        # VULN (BUSL-05/06): no purchase required, no limit on reviews per customer.
        rating = int(request.form.get("rating", 5) or 5)

    # VULN: Stored XSS (WSTG-INPV-02) - the review body is stored raw and rendered
    # with |safe in product.html, so a payload like <script>alert(document.cookie)</script>
    # executes for every visitor who views the product page afterwards.
    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body, rating) VALUES (?, ?, ?, ?, ?)",
        (product_id, session["user_id"], session["username"], body, rating),
    )
    db.commit()
    flash(t("reviews.flash_review_submitted"), "success")
    return redirect(back)
