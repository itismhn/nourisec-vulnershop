from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from app import security as sec
from app import validation
from app.db import get_db
from app.i18n import t

contact_bp = Blueprint("contact", __name__)


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        message = request.form.get("message", "")
        if current_app.config["AUTH_SECURE"]:
            # WSTG-INPV-10: no CR/LF in single-line fields (header/mail/log injection), valid
            # address, bounded lengths. Stored verbatim and encoded on output.
            name, email, message = name.strip(), email.strip(), message.strip()
            if (
                not name
                or len(name) > validation.CONTACT_NAME_MAX
                or validation.has_control_chars(name)
                or not sec.EMAIL_RE.match(email)
                or len(email) > 254
                or validation.has_control_chars(email)
                or not message
                or len(message) > validation.CONTACT_MESSAGE_MAX
            ):
                flash(t("input.flash_invalid"), "danger")
                return render_template("contact.html"), 400
        db = get_db()
        db.execute(
            "INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)",
            (name, email, message),
        )
        db.commit()
        flash(t("contact.flash_message_sent"), "success")
        return redirect(url_for("contact.contact"))
    return render_template("contact.html")
