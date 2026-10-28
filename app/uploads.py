import os
import secrets
import time

from flask import Blueprint, abort, current_app, flash, redirect, request, session, url_for
from werkzeug.utils import secure_filename

from app import commerce
from app import security as sec
from app.db import get_db
from app.i18n import t

uploads_bp = Blueprint("uploads", __name__)

# Secure mode (WSTG-BUSL-08/09): magic bytes decide the real type; the extension must agree.
_MAGIC = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
}
_EXT_FAMILY = {"png": "png", "jpg": "jpg", "jpeg": "jpg", "gif": "gif"}
# Content that has no business inside a profile picture, even behind a valid image header
# (polyglots), plus the EICAR antivirus test string used to check that uploads are scanned.
_BAD_MARKERS = (
    b"<script", b"<?php", b"<html", b"<svg", b"<iframe", b"javascript:", b"onerror=",
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR",
)


def _extension_allowed(filename):
    # VULN: Insecure File Upload (WSTG-BUSL-08/09) - allow-list checks the file
    # extension only. It never inspects file content/magic bytes, and the
    # allow-list itself includes 'svg', which can carry an embedded <script>
    # that executes when the file is opened directly from /uploads/<name>
    # (browsers render SVG as a document, not just an image, on direct navigation).
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    allowed = (
        current_app.config["SECURE_UPLOAD_EXTENSIONS"]
        if current_app.config["AUTH_SECURE"]
        else current_app.config["ALLOWED_UPLOAD_EXTENSIONS"]
    )
    return ext in allowed


def _content_problem(data, ext):
    """Secure mode: return None if `data` really is a clean image of the claimed type."""
    family = _EXT_FAMILY.get(ext)
    if not family or not data.startswith(_MAGIC[family]):
        return "uploads.flash_file_invalid"
    lowered = data.lower()
    if any(marker.lower() in lowered for marker in _BAD_MARKERS):
        return "uploads.flash_file_invalid"
    return None


@uploads_bp.route("/account/avatar", methods=["POST"])
def upload_avatar():
    if "user_id" not in session:
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))

    profile = url_for("account.profile", user_id=session["user_id"])
    file = request.files.get("avatar")
    if not file or file.filename == "":
        flash(t("uploads.flash_no_file"), "warning")
        return redirect(profile)

    if not _extension_allowed(file.filename):
        flash(t("uploads.flash_file_type_not_allowed"), "danger")
        return redirect(profile)

    # basename() only, to keep this sandboxed to the uploads folder - the
    # intentional weakness here is the extension/content check above, not a
    # path-traversal hole.
    safe_name = os.path.basename(file.filename)
    db = get_db()
    if current_app.config["AUTH_SECURE"]:
        safe_name = secure_filename(safe_name)  # WSTG-ATHZ-01: no separators, dots-only or odd names
        if not safe_name or not _extension_allowed(safe_name):
            flash(t("uploads.flash_file_type_not_allowed"), "danger")
            return redirect(profile)
        subject = f"user:{session['user_id']}"
        if sec.throttle_remaining("upload", subject, commerce.UPLOAD_MAX_PER_HOUR, 3600):
            sec.audit("upload_throttled", user=session.get("username"))
            abort(429)
        sec.record_attempt("upload", subject)
        limit = current_app.config["AVATAR_MAX_BYTES"]
        data = file.stream.read(limit + 1)
        if len(data) > limit:
            flash(t("uploads.flash_too_large"), "danger")
            return redirect(profile)
        ext = safe_name.rsplit(".", 1)[1].lower()
        problem = _content_problem(data, ext)
        if problem:
            sec.audit("upload_rejected", user=session.get("username"), ext=ext)
            flash(t(problem), "danger")
            return redirect(profile)
        # The stored name is chosen by the server; nothing from the client survives but the type.
        stored_name = f"user{session['user_id']}_{secrets.token_hex(8)}.{_EXT_FAMILY[ext]}"
        old = db.execute("SELECT avatar FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        with open(os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name), "wb") as out:
            out.write(data)
        if old and old["avatar"]:  # one avatar per user: do not let uploads pile up on disk
            try:
                os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], os.path.basename(old["avatar"])))
            except OSError:
                pass
    else:
        stored_name = f"user{session['user_id']}_{int(time.time())}_{safe_name}"
        file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name))

    db.execute("UPDATE users SET avatar = ? WHERE id = ?", (stored_name, session["user_id"]))
    db.commit()

    flash(t("uploads.flash_avatar_updated"), "success")
    return redirect(profile)
