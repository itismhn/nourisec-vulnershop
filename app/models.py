import hashlib

from app.db import get_db


def hash_password(password: str) -> str:
    # VULN: Sensitive Data Exposure (WSTG-CRYP-04) - unsalted MD5 instead of a modern
    # slow/salted hash (bcrypt/argon2). Trivially crackable via rainbow tables.
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(username):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def create_user(username, email, password, role="customer"):
    db = get_db()
    db.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
        (username, email, hash_password(password), role),
    )
    db.commit()


def list_products(category=None):
    db = get_db()
    if category:
        return db.execute(
            "SELECT * FROM products WHERE category = ? ORDER BY id", (category,)
        ).fetchall()
    return db.execute("SELECT * FROM products ORDER BY id").fetchall()


def get_product(product_id):
    db = get_db()
    return db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()


def get_reviews(product_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC", (product_id,)
    ).fetchall()


def get_orders_for_user(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (user_id,)
    ).fetchall()


def get_order(order_id):
    db = get_db()
    return db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


def get_order_items(order_id):
    db = get_db()
    return db.execute(
        """SELECT order_items.*, products.name AS product_name
           FROM order_items JOIN products ON products.id = order_items.product_id
           WHERE order_id = ?""",
        (order_id,),
    ).fetchall()
