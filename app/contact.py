from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.db import get_db

contact_bp = Blueprint("contact", __name__)


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        message = request.form.get("message", "")
        db = get_db()
        db.execute(
            "INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)",
            (name, email, message),
        )
        db.commit()
        flash("پیام شما ثبت شد - تیم پشتیبانی (آزمایشی) به‌زودی پاسخ می‌دهد.", "success")
        return redirect(url_for("contact.contact"))
    return render_template("contact.html")
