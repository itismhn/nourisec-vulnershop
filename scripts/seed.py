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

# (name, description, price, original_price, category, image)
PRODUCTS = [
    (
        "زعفران سرگل ممتاز قائنات، ۱ مثقال",
        "زعفران سرگل ممتاز، برداشت پاییز، بسته‌بندی اورجینال و عطر و رنگ‌دهی بالا. مستقیم از قائنات، خراسان جنوبی.",
        285000, 340000, "خواربار ایرانی", "saffron.jpg",
    ),
    (
        "پسته اکبری درجه یک، بسته ۵۰۰ گرمی",
        "پسته اکبری درشت و تازه، برشته‌شده با نمک دریا. محصول رفسنجان.",
        390000, None, "خواربار ایرانی", "pistachio.jpg",
    ),
    (
        "گلاب قمصر کاشان، بطری ۴۰۰ میلی‌لیتری",
        "گلاب دوآتیشه سنتی، عرق‌گیری‌شده از گل محمدی کاشان.",
        85000, None, "خواربار ایرانی", "rosewater.jpg",
    ),
    (
        "خرمای مضافتی درجه یک بم، ۱ کیلوگرم",
        "خرمای مضافتی تازه و آبدار از نخلستان‌های بم، بدون افزودنی.",
        145000, None, "خواربار ایرانی", "dates.jpg",
    ),
    (
        "مغز گردوی دور سفید همدان، ۱ کیلوگرم",
        "مغز گردوی تازه و روغنی، بدون خشک‌کردن صنعتی. محصول همدان.",
        395000, 450000, "خواربار ایرانی", "walnuts.jpg",
    ),
    (
        "چای احمد شکسته ممتاز، ۴۵۰ گرم",
        "چای سیاه ممتاز با طعمی پررنگ و عطر ماندگار، بسته‌بندی خانواده.",
        168000, None, "خواربار ایرانی", "tea.jpg",
    ),
    (
        "هندزفری بی‌سیم JBL مدل T125BT",
        "هندزفری بلوتوثی با باتری ۱۶ ساعته و کیفیت صدای باس‌دار JBL.",
        1290000, 1590000, "موبایل و دیجیتال", "earbuds.jpg",
    ),
    (
        "ساعت هوشمند اولترا، نمایشگر AMOLED",
        "ساعت هوشمند با صفحه‌نمایش AMOLED، ردیاب ضربان قلب و GPS داخلی.",
        29900000, None, "موبایل و دیجیتال", "smartwatch.jpg",
    ),
    (
        "کفش اسپرت مردانه ایرمکس",
        "کفش اسپرت سبک با کفی طبی و تهویه مناسب، مناسب پیاده‌روی روزانه.",
        2450000, None, "مد و پوشاک", "shoes.jpg",
    ),
    (
        "کوله پشتی چرم طبیعی، دست‌دوز تبریز",
        "کوله پشتی چرم طبیعی دست‌دوز، مناسب لپ‌تاپ تا ۱۵ اینچ.",
        3200000, 3850000, "مد و پوشاک", "backpack.jpg",
    ),
    (
        "عطر مردانه امبروکسان ۱۹، حجم ۵۰ میلی‌لیتر",
        "رایحه گرم و چوبی با ماندگاری بالا، مناسب استفاده روزانه.",
        1850000, None, "زیبایی و سلامت", "perfume.jpg",
    ),
    (
        "فرش دستباف قشقایی، طرح سنتی ۶ متری",
        "فرش دستباف اصیل ایلی قشقایی، رنگ‌رزی گیاهی و بافت متراکم.",
        12500000, 15000000, "صنایع‌دستی", "rug.jpg",
    ),
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

    for name, description, price, original_price, category, image in PRODUCTS:
        db.execute(
            "INSERT INTO products (name, description, price, original_price, category, image) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, description, price, original_price, category, image),
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
    saffron_id = db.execute(
        "SELECT id FROM products WHERE name LIKE 'زعفران%'"
    ).fetchone()["id"]
    earbuds_id = db.execute(
        "SELECT id FROM products WHERE name LIKE 'هندزفری%'"
    ).fetchone()["id"]
    watch_id = db.execute(
        "SELECT id FROM products WHERE name LIKE 'ساعت هوشمند%'"
    ).fetchone()["id"]

    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body, rating) VALUES (?, ?, ?, ?, ?)",
        (saffron_id, alice_id, "alice", "کیفیت واقعا عالی بود، عطر زعفران به محض باز کردن بسته کل آشپزخانه رو پر کرد.", 5),
    )
    db.execute(
        "INSERT INTO reviews (product_id, user_id, username, body, rating) VALUES (?, ?, ?, ?, ?)",
        (earbuds_id, bob_id, "bob", "کیفیت صدا نسبت به قیمتش خیلی خوبه، فقط باتری کمی زودتر از حد انتظار تموم می‌شه.", 4),
    )
    db.commit()

    # order 1 -> alice, order 2 -> bob (kept stable: INSTRUCTOR_GUIDE.md / STUDENT_LAB.md
    # reference these exact IDs for the IDOR walkthrough).
    cur = db.execute(
        "INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'completed')",
        (alice_id, 285000),
    )
    order1_id = cur.lastrowid
    db.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
        (order1_id, saffron_id, 1, 285000),
    )

    cur = db.execute(
        "INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'completed')",
        (bob_id, 29900000),
    )
    order2_id = cur.lastrowid
    db.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
        (order2_id, watch_id, 1, 29900000),
    )
    db.commit()

    print("Seeded database with:")
    print(f"  {len(PRODUCTS)} products")
    print("  users:")
    for username, _, password, role in USERS:
        print(f"    {username} / {password}  (role={role})")
    print("  2 sample orders, 2 sample reviews")


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        init_db()
        seed()
