-- Tables used by the hardened ("secure" auth mode) implementation. Everything is
-- IF NOT EXISTS so it can run both from init_db() and as a startup migration against
-- a database that was seeded before secure mode existed. scripts/reset_db.py wipes
-- them via the DROPs at the top of schema.sql.

-- WSTG-ATHN-03: failed-attempt ledger driving account lockout and per-IP throttling.
-- `subject` is "user:<name>" or "ip:<addr>" and is recorded for names that do not exist
-- too, so lockout behaviour cannot be used to enumerate accounts.
CREATE TABLE IF NOT EXISTS auth_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts ON auth_attempts(kind, subject, created_at);

-- WSTG-ATHN-04 / SESS-06/07: server-side session records. The cookie only carries a
-- random id; the server stores its SHA-256, so logout, password change and timeouts
-- actually revoke the session instead of relying on a client-held signed cookie.
CREATE TABLE IF NOT EXISTS auth_sessions (
    sid_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT,
    user_agent TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- WSTG-ATHN-09: random, hashed-at-rest, expiring, single-use reset tokens.
CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- WSTG-ATHN-07/09: previous password hashes, to block immediate reuse.
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
