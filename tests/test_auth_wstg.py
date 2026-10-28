"""Automated checks for the hardened auth mode, grouped by OWASP WSTG v4.2 test ID.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""
import os
import re
import sys
import tempfile
import time
import unittest

_tmp = tempfile.mkdtemp()
os.environ["VULNERSHOP_AUTH_MODE"] = "secure"
os.environ["VULNERSHOP_DB"] = os.path.join(_tmp, "test.db")
os.environ["SEED_PASSWORD_ADMIN"] = "Adm1n-Correct-Horse-9"
os.environ["SEED_PASSWORD_ALICE"] = "Alice-Battery-Staple-7"
os.environ["SEED_PASSWORD_BOB"] = "Bob-Purple-Tractor-3"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.db import get_db, init_db  # noqa: E402
from scripts.seed import seed  # noqa: E402

ALICE, ALICE_PW = "alice", "Alice-Battery-Staple-7"


def token_of(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


class Base(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = False  # keep real error handling
        with self.app.app_context():
            init_db()
            seed()
        self.c = self.app.test_client()

    def post(self, path, data=None, client=None, page=None):
        client = client or self.c
        tok = token_of(client.get(page or path).get_data(as_text=True))
        return client.post(path, data={**(data or {}), "csrf_token": tok})

    def login(self, user=ALICE, pw=ALICE_PW, client=None):
        return self.post("/login", {"username": user, "password": pw}, client)

    def q(self, sql, *a):
        with self.app.app_context():
            return get_db().execute(sql, a).fetchall()


class TestATHN01Transport(Base):
    def test_credentials_not_accepted_via_get(self):
        r = self.c.get(f"/login?username={ALICE}&password={ALICE_PW}", follow_redirects=True)
        self.assertNotIn("Welcome", r.get_data(as_text=True))

    def test_cookie_flags_and_hsts(self):
        r = self.c.get("/login", base_url="https://localhost")
        self.assertIn("HttpOnly", r.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", r.headers["Set-Cookie"])
        self.assertIn("max-age", r.headers["Strict-Transport-Security"])

    def test_force_https_redirect(self):
        self.app.config["FORCE_HTTPS"] = True
        r = self.c.get("/login")
        self.assertEqual((r.status_code, r.headers["Location"][:8]), (301, "https://"))


class TestATHN02DefaultCredentials(Base):
    def test_known_defaults_rejected(self):
        for u, p in [("admin", "admin123"), ("svc_backup", "password123"), ("alice", "Password1")]:
            self.assertEqual(self.login(u, p).status_code, 401, u)
        self.assertEqual(self.q("SELECT 1 FROM users WHERE username='svc_backup'"), [])


class TestATHN03Lockout(Base):
    def test_lockout_after_failures_even_with_correct_password(self):
        for _ in range(5):
            self.assertEqual(self.login(ALICE, "wrong").status_code, 401)
        r = self.login(ALICE, ALICE_PW)
        self.assertEqual(r.status_code, 429)
        self.assertEqual(self.c.get("/orders").status_code, 302)  # still logged out

    def test_lockout_applies_to_unknown_names_identically(self):
        for _ in range(5):
            self.login("ghost-user", "x")
        self.assertEqual(self.login("ghost-user", "x").status_code, 429)

    def test_lock_expires(self):
        for _ in range(5):
            self.login(ALICE, "wrong")
        with self.app.app_context():
            get_db().execute("UPDATE auth_attempts SET created_at = created_at - 1000")
            get_db().commit()
        self.assertEqual(self.login().status_code, 302)

    def test_ip_throttle(self):
        for i in range(20):
            self.login(f"spray{i}", "x")
        self.assertEqual(self.login(ALICE, ALICE_PW).status_code, 429)


class TestATHN04Bypass(Base):
    def test_sqli_login_bypass_fails(self):
        for payload in ["' OR '1'='1' --", "alice' --", "admin'/*"]:
            self.assertEqual(self.login(payload, "x").status_code, 401)

    def test_direct_page_requests_require_auth(self):
        for path in ["/profile", "/orders", "/admin/", "/admin/users"]:
            self.assertEqual(self.c.get(path).status_code, 302, path)

    def test_generic_error_and_no_enumeration(self):
        a = self.login(ALICE, "wrong").get_data(as_text=True)
        b = self.login("nobody", "wrong").get_data(as_text=True)
        self.assertIn("Incorrect username or password", a)
        self.assertIn("Incorrect username or password", b)

    def test_forged_legacy_cookie_rejected(self):
        with self.c.session_transaction() as s:
            s["user_id"], s["username"], s["role"] = 1, "admin", "admin"
        self.assertEqual(self.c.get("/admin/").status_code, 302)

    def test_session_rotated_on_login_and_revoked_on_logout(self):
        self.login()
        with self.c.session_transaction() as s:
            sid = s["sid"]
        self.assertEqual(self.c.get("/orders").status_code, 200)
        self.c.get("/logout")
        with self.c.session_transaction() as s:  # replay the old cookie
            s["sid"], s["user_id"] = sid, 2
        self.assertEqual(self.c.get("/orders").status_code, 302)

    def test_idle_and_absolute_timeouts(self):
        self.login()
        with self.app.app_context():
            get_db().execute("UPDATE auth_sessions SET last_seen = last_seen - 1300")
            get_db().commit()
        self.assertEqual(self.c.get("/orders").status_code, 302)
        self.login()
        with self.app.app_context():
            get_db().execute("UPDATE auth_sessions SET created_at = created_at - 30000")
            get_db().commit()
        self.assertEqual(self.c.get("/orders").status_code, 302)

    def test_csrf_required_on_login(self):
        r = self.c.post("/login", data={"username": ALICE, "password": ALICE_PW})
        self.assertEqual(r.status_code, 400)

    def test_customer_cannot_reach_admin(self):
        self.login()
        self.assertEqual(self.c.get("/admin/users").status_code, 403)
        admin = self.app.test_client()
        self.login("admin", "Adm1n-Correct-Horse-9", admin)
        self.assertEqual(admin.get("/admin/users").status_code, 200)
        self.assertNotIn(b"scrypt:", admin.get("/admin/users").data)

    def test_legacy_md5_hash_is_upgraded(self):
        import hashlib
        with self.app.app_context():
            get_db().execute("UPDATE users SET password_hash=? WHERE username='bob'",
                             (hashlib.md5(b"Bob-Purple-Tractor-3").hexdigest(),))
            get_db().commit()
        self.assertEqual(self.login("bob", "Bob-Purple-Tractor-3").status_code, 302)
        self.assertTrue(self.q("SELECT password_hash FROM users WHERE username='bob'")[0][0].startswith("scrypt:"))


class TestATHN06Cache(Base):
    def test_no_store_on_dynamic_pages(self):
        self.login()
        for path in ["/login", "/orders", "/profile/2"]:
            cc = self.c.get(path).headers["Cache-Control"]
            self.assertIn("no-store", cc, path)


class TestATHN07PasswordPolicy(Base):
    def reg(self, pw, user="newuser", email="new@example.com"):
        return self.post("/register", {"username": user, "email": email, "password": pw})

    def test_weak_passwords_rejected(self):
        for pw in ["short1", "password123", "Password1!", "newuser12345", "aaaaaaaaaaaa", "1234567890", "x" * 129]:
            self.assertEqual(self.reg(pw).status_code, 400, pw)

    def test_strong_passphrase_accepted_and_stored_salted(self):
        self.assertEqual(self.reg("correct horse battery").status_code, 302)
        self.assertTrue(self.q("SELECT password_hash FROM users WHERE username='newuser'")[0][0].startswith("scrypt:"))

    def test_bad_username_and_duplicate(self):
        self.assertEqual(self.reg("correct horse battery", user="a b").status_code, 400)
        self.assertEqual(self.reg("correct horse battery", user="ALICE").status_code, 409)


class TestATHN09Reset(Base):
    def request_link(self, user=ALICE):
        with self.assertLogs("vulnershop.mail", "INFO") as cm:
            self.post("/forgot-password", {"username": user})
        return re.search(r"http://\S+/reset-password/(\S+)", cm.output[0]).group(1)

    def test_no_debug_leak_page(self):
        self.assertEqual(self.c.get("/dev/last-reset").status_code, 404)

    def test_same_response_for_unknown_user_and_no_mail(self):
        r1 = self.post("/forgot-password", {"username": "ghost"})
        r2 = self.post("/forgot-password", {"username": ALICE})
        self.assertEqual((r1.status_code, r1.headers["Location"]), (r2.status_code, r2.headers["Location"]))

    def test_token_random_hashed_expiring_single_use(self):
        tok = self.request_link()
        self.assertGreaterEqual(len(tok), 40)
        self.assertNotEqual(tok, __import__("hashlib").md5(b"reset-alice").hexdigest())
        self.assertNotIn(tok, self.q("SELECT token_hash FROM password_resets")[0][0])
        page = f"/reset-password/{tok}"
        self.assertEqual(self.post(page, {"password": "short"}).status_code, 400)
        self.assertEqual(self.post(page, {"password": "a brand new passphrase"}).status_code, 302)
        self.assertEqual(self.c.get(page).status_code, 302)  # single use
        self.assertEqual(self.login(ALICE, "a brand new passphrase").status_code, 302)

    def test_token_expires(self):
        tok = self.request_link()
        with self.app.app_context():
            get_db().execute("UPDATE password_resets SET expires_at = ?", (time.time() - 1,))
            get_db().commit()
        self.assertEqual(self.c.get(f"/reset-password/{tok}").status_code, 302)

    def test_new_request_invalidates_old_and_cannot_reuse_old_password(self):
        old = self.request_link()
        new = self.request_link_again()
        self.assertEqual(self.c.get(f"/reset-password/{old}").status_code, 302)
        r = self.post(f"/reset-password/{new}", {"password": ALICE_PW})
        self.assertEqual(r.status_code, 400)

    def request_link_again(self):
        # a second request inside the same window (limit is 3/hour)
        return self.request_link()

    def test_reset_revokes_existing_sessions(self):
        victim = self.app.test_client()
        self.login(client=victim)
        self.assertEqual(victim.get("/orders").status_code, 200)
        tok = self.request_link()
        self.post(f"/reset-password/{tok}", {"password": "a brand new passphrase"})
        self.assertEqual(victim.get("/orders").status_code, 302)

    def test_reset_requests_rate_limited(self):
        codes = [self.post("/forgot-password", {"username": ALICE}).status_code for _ in range(4)]
        self.assertEqual(codes[-1], 429)

    def test_wrong_tokens_throttled(self):
        for i in range(10):
            self.c.get(f"/reset-password/bad{i}")
        self.assertEqual(self.c.get("/reset-password/bad-final").status_code, 429)


class TestATHN09Change(Base):
    def test_change_requires_current_password_csrf_and_policy(self):
        self.login()
        page = "/profile/2"
        r = self.post("/account/change-password", {"password": "a brand new passphrase"}, page=page)
        self.assertEqual(r.status_code, 302)
        c2 = self.app.test_client()  # missing current password => change must not have happened
        self.assertEqual(self.login(ALICE, "a brand new passphrase", c2).status_code, 401)

    def test_wrong_current_password_blocks_change(self):
        self.login()
        self.post("/account/change-password",
                  {"current_password": "nope", "password": "a brand new passphrase"}, page="/profile/2")
        c2 = self.app.test_client()
        self.assertEqual(self.login(ALICE, "a brand new passphrase", c2).status_code, 401)

    def test_change_success_rotates_and_revokes_other_sessions(self):
        other = self.app.test_client()
        self.login(client=other)
        self.login()
        self.post("/account/change-password",
                  {"current_password": ALICE_PW, "password": "a brand new passphrase"}, page="/profile/2")
        self.assertEqual(other.get("/orders").status_code, 302)
        self.assertEqual(self.c.get("/orders").status_code, 200)
        c3 = self.app.test_client()
        self.assertEqual(self.login(ALICE, "a brand new passphrase", c3).status_code, 302)

    def test_history_blocks_reuse(self):
        self.login()
        self.post("/account/change-password",
                  {"current_password": ALICE_PW, "password": "a brand new passphrase"}, page="/profile/2")
        self.post("/account/change-password",
                  {"current_password": "a brand new passphrase", "password": ALICE_PW}, page="/profile/2")
        c2 = self.app.test_client()
        self.assertEqual(self.login(ALICE, ALICE_PW, c2).status_code, 401)

    def test_cross_site_post_without_token_rejected(self):
        self.login()
        r = self.c.post("/account/change-email", data={"email": "evil@x.io", "current_password": ALICE_PW})
        self.assertEqual(r.status_code, 400)

    def test_email_change_needs_password(self):
        self.login()
        self.post("/account/change-email", {"email": "n@example.com", "current_password": "bad"}, page="/profile/2")
        self.assertNotEqual(self.q("SELECT email FROM users WHERE username='alice'")[0][0], "n@example.com")
        self.post("/account/change-email", {"email": "n@example.com", "current_password": ALICE_PW}, page="/profile/2")
        self.assertEqual(self.q("SELECT email FROM users WHERE username='alice'")[0][0], "n@example.com")


if __name__ == "__main__":
    unittest.main()
