import os
import subprocess
import time

import requests
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.db import get_db, init_db
from app.i18n import t

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _admin_required():
    # VULN: Broken Access Control (WSTG-ATHZ-01 / OWASP A01:2021) - this only checks
    # that *someone* is logged in. It never checks session["role"] == "admin", so any
    # registered customer can reach every /admin/* route just by knowing/guessing the
    # URL - there is no link to it anywhere in the customer-facing UI.
    return "user_id" in session


@admin_bp.route("/")
def dashboard():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))
    db = get_db()
    counts = {
        "users": db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "products": db.execute("SELECT COUNT(*) c FROM products").fetchone()["c"],
        "orders": db.execute("SELECT COUNT(*) c FROM orders").fetchone()["c"],
    }
    return render_template("admin/dashboard.html", counts=counts)


@admin_bp.route("/users")
def users():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))
    db = get_db()
    all_users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/orders")
def orders():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))
    db = get_db()
    all_orders = db.execute(
        """SELECT orders.*, users.username FROM orders
           JOIN users ON users.id = orders.user_id
           ORDER BY orders.id DESC"""
    ).fetchall()
    return render_template("admin/orders.html", orders=all_orders)


@admin_bp.route("/products", methods=["GET", "POST"])
def products():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))

    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "")
        description = request.form.get("description", "")
        price = request.form.get("price", "0")
        category = request.form.get("category", "")
        db.execute(
            "INSERT INTO products (name, description, price, category, image) VALUES (?, ?, ?, ?, ?)",
            (name, description, float(price), category, "placeholder.svg"),
        )
        db.commit()
        flash(t("admin.flash_product_added"), "success")
        return redirect(url_for("admin.products"))

    all_products = db.execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("admin/products.html", products=all_products)


@admin_bp.route("/products/<int:product_id>/delete", methods=["POST"])
def delete_product(product_id):
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))
    db = get_db()
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
    flash(t("admin.flash_product_deleted"), "info")
    return redirect(url_for("admin.products"))


@admin_bp.route("/ping", methods=["GET", "POST"])
def ping():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))

    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULN: Command Injection (OWASP A03:2021, WSTG-BUSL / WSTG-INPV-11) -
        # user input concatenated directly into a shell=True command string.
        # e.g. host = "127.0.0.1; id" runs a second command.
        # SAFETY: run this app only inside the provided Docker container on an
        # isolated network (see docker-compose.yml / README) so this can only
        # touch the sandboxed container, never a real external host.
        cmd = "ping -c 1 " + host
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)

    return render_template("admin/ping.html", host=host, output=output)


@admin_bp.route("/fetch-image", methods=["GET", "POST"])
def fetch_image():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))

    fetched_path = None
    url = ""
    error = None
    if request.method == "POST":
        url = request.form.get("url", "")
        # VULN: SSRF (OWASP A10:2021, WSTG-BUSL-11) - server-side fetch of an
        # attacker-supplied URL with no scheme/host allow-list, so it can be
        # pointed at internal-only endpoints (e.g. http://127.0.0.1:5000/admin/users)
        # that are not meant to be reachable from outside the app.
        # SAFETY: run only on the isolated Docker network (see README) so this
        # cannot be used to reach real third-party hosts.
        try:
            resp = requests.get(url, timeout=5)
            filename = f"fetched_{int(time.time())}.img"
            save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
            with open(save_path, "wb") as f:
                f.write(resp.content)
            fetched_path = f"/uploads/{filename}"
        except Exception as e:
            error = str(e)

    return render_template("admin/fetch_image.html", url=url, fetched_path=fetched_path, error=error)


@admin_bp.route("/reset", methods=["POST"])
def reset():
    if not _admin_required():
        flash(t("common.flash_login_required"), "warning")
        return redirect(url_for("auth.login"))

    init_db()
    from scripts.seed import seed

    seed()
    flash(t("admin.flash_db_reset"), "success")
    return redirect(url_for("admin.dashboard"))
