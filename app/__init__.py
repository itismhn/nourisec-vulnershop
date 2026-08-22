import os

from flask import Flask, render_template, send_from_directory, session

from app import db as db_module
from app.config import Config

BANNER_TEXT = (
    "⚠️ EDUCATIONAL / INTENTIONALLY VULNERABLE APPLICATION — NouriSec Training Lab. "
    "This site contains deliberate security flaws for authorized learning only. "
    "Do NOT enter real personal data, real passwords, or real payment details. "
    "Do NOT attack any system you are not explicitly authorized to test."
)


def create_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)

    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db_module.init_app(app)

    @app.context_processor
    def inject_banner():
        cart_count = sum(session.get("cart", {}).values()) if session.get("cart") else 0
        return {"BANNER_TEXT": BANNER_TEXT, "cart_count": cart_count}

    _PERSIAN_DIGITS = "۰۱۲۳۴۵۶۷۸۹"

    @app.template_filter("toman")
    def toman_filter(value):
        # Formats a numeric price as Persian-digit, thousands-separated Toman.
        try:
            whole = int(round(float(value)))
        except (TypeError, ValueError):
            return value
        grouped = f"{whole:,}".replace(",", "٬")
        return "".join(_PERSIAN_DIGITS[int(ch)] if ch.isdigit() else ch for ch in grouped)

    @app.template_filter("fanum")
    def fanum_filter(value):
        # Renders any integer-ish value using Persian digits (ratings, counts, dates).
        return "".join(_PERSIAN_DIGITS[int(ch)] if ch.isdigit() else ch for ch in str(value))

    from app.auth import auth_bp
    from app.shop import shop_bp
    from app.account import account_bp
    from app.admin import admin_bp
    from app.uploads import uploads_bp
    from app.reviews import reviews_bp
    from app.contact import contact_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(shop_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(reviews_bp)
    app.register_blueprint(contact_bp)

    @app.route("/disclaimer")
    def disclaimer():
        return render_template("disclaimer.html")

    @app.route("/robots.txt")
    def robots_txt():
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return send_from_directory(root, "robots.txt")

    # --- Simulated Security Misconfiguration artifacts (WSTG-CONF) ---
    # These routes simulate common deployment mistakes (exposed VCS metadata, an
    # exposed DB backup, directory listing) without requiring the whole training
    # repo itself to be served as a live, web-accessible .git checkout.

    @app.route("/.git/HEAD")
    def fake_git_head():
        # VULN: Security Misconfiguration - exposed VCS metadata (WSTG-CONF-01)
        return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}

    @app.route("/.git/config")
    def fake_git_config():
        # VULN: Security Misconfiguration - exposed VCS metadata (WSTG-CONF-01)
        fake_config = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "[remote \"origin\"]\n"
            "\turl = https://github.com/nourisec-training/vulnershop-internal-DO-NOT-SHIP.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )
        return fake_config, 200, {"Content-Type": "text/plain"}

    @app.route("/backup/<path:filename>")
    def backup_files(filename):
        # VULN: Security Misconfiguration - old backup left in a web-accessible path (WSTG-CONF-02)
        return send_from_directory(app.config["BACKUP_DIR"], filename)

    @app.route("/uploads/")
    def uploads_listing():
        # VULN: Security Misconfiguration - directory listing enabled (WSTG-CONF-03)
        files = os.listdir(app.config["UPLOAD_FOLDER"])
        listing = "<h1>Index of /uploads/</h1><ul>" + "".join(
            f'<li><a href="/uploads/{f}">{f}</a></li>' for f in files
        ) + "</ul>"
        return listing

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    @app.route("/dev/last-reset")
    def dev_last_reset():
        # VULN: Broken Authentication - insecure "forgot password" flow debug leftover (WSTG-ATHN-04)
        # Simulates a dev-only page that was never removed, exposing the last password-reset link
        # generated for ANY user (not scoped to the requester) to anyone who finds this URL.
        from app.auth import LAST_RESET

        return render_template("dev_last_reset.html", link=LAST_RESET.get("link"), username=LAST_RESET.get("username"))

    return app
