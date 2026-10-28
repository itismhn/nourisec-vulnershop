PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS auth_attempts;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS coupon_redemptions;
DROP TABLE IF EXISTS coupons;
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS contact_messages;

PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    avatar TEXT,
    reset_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    original_price REAL,
    category TEXT,
    image TEXT,
    stock INTEGER NOT NULL DEFAULT 50,
    purchase_limit INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER,
    username TEXT NOT NULL,
    body TEXT NOT NULL,
    rating INTEGER NOT NULL DEFAULT 5,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(product_id) REFERENCES products(id)
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total REAL NOT NULL,
    subtotal REAL,
    discount REAL NOT NULL DEFAULT 0,
    coupon_code TEXT,
    refunded REAL NOT NULL DEFAULT 0,
    status TEXT DEFAULT 'completed',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
);

CREATE TABLE contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- WSTG-BUSL-05: promo codes. `single_use` means "once per customer" (enforced only in secure mode).
CREATE TABLE coupons (
    code TEXT PRIMARY KEY COLLATE NOCASE,
    percent INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    single_use INTEGER NOT NULL DEFAULT 1
);

-- Secure mode records each redemption; the UNIQUE key makes "once per customer" race-proof.
CREATE TABLE coupon_redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL COLLATE NOCASE,
    user_id INTEGER NOT NULL,
    order_id INTEGER NOT NULL,
    UNIQUE(code, user_id)
);
