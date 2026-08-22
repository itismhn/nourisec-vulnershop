import os
import time

from flask import Blueprint, current_app, flash, redirect, request, session, url_for

from app.db import get_db

uploads_bp = Blueprint("uploads", __name__)


def _extension_allowed(filename):
    # VULN: Insecure File Upload (WSTG-BUSL-09) - allow-list checks the file
    # extension only. It never inspects file content/magic bytes, and the
    # allow-list itself includes 'svg', which can carry an embedded <script>
    # that executes when the file is opened directly from /uploads/<name>
    # (browsers render SVG as a document, not just an image, on direct navigation).
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_UPLOAD_EXTENSIONS"]


@uploads_bp.route("/account/avatar", methods=["POST"])
def upload_avatar():
    if "user_id" not in session:
        flash("لطفا ابتدا وارد شوید.", "warning")
        return redirect(url_for("auth.login"))

    file = request.files.get("avatar")
    if not file or file.filename == "":
        flash("فایلی انتخاب نشده است.", "warning")
        return redirect(url_for("account.profile", user_id=session["user_id"]))

    if not _extension_allowed(file.filename):
        flash("این نوع فایل مجاز نیست.", "danger")
        return redirect(url_for("account.profile", user_id=session["user_id"]))

    # basename() only, to keep this sandboxed to the uploads folder - the
    # intentional weakness here is the extension/content check above, not a
    # path-traversal hole.
    safe_name = os.path.basename(file.filename)
    stored_name = f"user{session['user_id']}_{int(time.time())}_{safe_name}"
    file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name))

    db = get_db()
    db.execute("UPDATE users SET avatar = ? WHERE id = ?", (stored_name, session["user_id"]))
    db.commit()

    flash("تصویر پروفایل به‌روزرسانی شد.", "success")
    return redirect(url_for("account.profile", user_id=session["user_id"]))
