"""Seed the VulnerShop database with fake products, users, reviews, and orders.

Run standalone with `python scripts/seed.py`, or import `seed()` (used by the
admin "Reset Database" button in app/admin.py).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.db import get_db, init_db
from app.models import hash_password

PRODUCTS = [
    ("Wireless Mouse", "A smooth, reliable wireless mouse for everyday use.", 19.99, "Electronics"),
    ("Mechanical Keyboard", "Clicky mechanical keyboard with RGB backlighting.", 59.99, "Electronics"),
    ("USB-C Hub", "7-in-1 USB-C hub with HDMI and card reader.", 34.50, "Electronics"),
    ("Ceramic Mug", "12oz ceramic mug, dishwasher safe.", 9.99, "Home"),
    ("Standing Desk Mat", "Anti-fatigue mat for standing desks.", 24.99, "Home"),
    ("Scented Candle", "Hand-poured soy candle, lavender scent.", 14.00, "Home"),
    ("Running Shoes", "Lightweight running shoes with breathable mesh.", 74.99, "Apparel"),
    ("Rain Jacket", "Waterproof packable rain jacket.", 45.00, "Apparel"),
    ("Wool Beanie", "Warm wool beanie, one size fits most.", 12.50, "Apparel"),
    ("Notebook Set", "3-pack of dot-grid notebooks.", 15.75, "Office"),
    ("Desk Organizer", "Bamboo desk organizer with multiple compartments.", 22.00, "Office"),
    ("Fountain Pen", "Smooth-writing fountain pen with converter.", 28.00, "Office"),
]

USERS = [
    ("admin", "admin@vulnershop.test", "admin123", "admin"),
    ("alice", "alice@vulnershop.test", "Password1", "customer"),
    ("bob", "bob@vulnershop.test", "Password1", "customer"),
    # Leftover staging service account - its MD5 hash is also leaked via the
    # web-accessible backup/app_backup.sql (WSTG-CONF-02), so it's crackable
    # and still valid on this live DB (VULN chain: misconfig -> weak crypto -> real login).
    ("svc_backup", "svc-backup@vulnershop.test", "password123", "admin"),
]


def seed():
    db = get_db()

    for name, description, price, category in PRODUCTS:
        db.execute(
            "INSERT INTO products (name, description, price, category, image) VALUES (?, ?, ?, ?, ?)",
            (name, description, price, category, "placeholder.svg"),
        )
    db.commit()

    for username, email, password, role in USERS:
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, hash_password(password), role),
        )
    db.commit()

    alice_id = db.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
    bob_id = db.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()["id"]
    mouse_id = db.execute("SELECT id FROM products WHERE name = 'Wireless Mouse'").fetchone()["id"]
    keyboard_id = db.execute("SELECT id FROM products WHERE name = 'Mechanical Keyboard'").fetchone()["id"]

    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body) VALUES (?, ?, ?, ?)",
        (mouse_id, alice_id, "alice", "Works great, very responsive!"),
    )
    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body) VALUES (?, ?, ?, ?)",
        (keyboard_id, bob_id, "bob", "Loud but satisfying to type on."),
    )
    db.commit()

    cur = db.execute(
        "INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'completed')",
        (alice_id, 19.99),
    )
    order1_id = cur.lastrowid
    db.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
        (order1_id, mouse_id, 1, 19.99),
    )

    cur = db.execute(
        "INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'completed')",
        (bob_id, 59.99),
    )
    order2_id = cur.lastrowid
    db.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
        (order2_id, keyboard_id, 1, 59.99),
    )
    db.commit()

    print("Seeded database with:")
    print(f"  {len(PRODUCTS)} products")
    print("  users:")
    for username, _, password, role in USERS:
        print(f"    {username} / {password}  (role={role})")
    print(f"  2 sample orders, 2 sample reviews")


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        init_db()
        seed()
