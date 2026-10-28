"""Automated checks for the hardened authorization controls, grouped by OWASP WSTG v4.2 test ID
(section 4.5: Authorization Testing).

Run:  .venv/bin/python -m unittest discover -s tests -v
"""
import os
import tempfile
import unittest

from test_auth_wstg import ALICE, ALICE_PW, Base  # noqa: F401  (sets the secure-mode test env)

BOB, BOB_PW = "bob", "Bob-Purple-Tractor-3"
ADMIN, ADMIN_PW = "admin", "Adm1n-Correct-Horse-9"
ADMIN_GETS = ["/admin/", "/admin/users", "/admin/orders", "/admin/products", "/admin/ping", "/admin/fetch-image"]
ADMIN_POSTS = ["/admin/products", "/admin/products/1/delete", "/admin/ping", "/admin/fetch-image", "/admin/reset"]
# alice owns user id 2 and order 1; bob owns user id 3 and order 2 (kept stable by scripts/seed.py).


class AuthzBase(Base):
    def setUp(self):
        super().setUp()
        self.uploads = tempfile.mkdtemp()
        self.app.config["UPLOAD_FOLDER"] = self.uploads

    def exec(self, *statements):
        with self.app.app_context():
            from app.db import get_db
            for sql in statements:
                get_db().execute(sql)
            get_db().commit()

    def as_user(self, user, pw):
        c = self.app.test_client()
        self.assertEqual(self.login(user, pw, c).status_code, 302)
        return c


class TestATHZ01Traversal(AuthzBase):
    PAYLOADS = [
        "/backup/../app/config.py", "/backup/..%2fapp/config.py", "/backup/%2e%2e/app/config.py",
        "/backup/....//app/config.py", "/backup/%252e%252e%252fapp/config.py", "/backup//etc/passwd",
        "/uploads/../config.py", "/uploads/..%2fconfig.py", "/uploads/%2e%2e%2fconfig.py",
        "/uploads/..\\config.py", "/uploads//etc/passwd", "/uploads/%00.png", "/static/../config.py",
        "/static/..%2f__init__.py",
    ]

    def test_dot_dot_payloads_never_return_files(self):
        for path in self.PAYLOADS:
            r = self.c.get(path)
            self.assertIn(r.status_code, (301, 308, 400, 404), path)
            self.assertNotIn(b"SECRET_KEY", r.data, path)
            self.assertNotIn(b"root:", r.data, path)

    def test_leftover_backup_vcs_metadata_and_listings_absent(self):
        for path in ["/backup/", "/backup/app_backup.sql", "/.git/", "/.git/HEAD", "/.git/config", "/uploads/"]:
            self.assertEqual(self.c.get(path).status_code, 404, path)

    def test_avatar_filename_cannot_escape_upload_folder(self):
        c = self.as_user(ALICE, ALICE_PW)
        for name in ["../../evil.png", "..\\..\\evil.png", "/etc/evil.png", "a/b/../../../evil.png", "....//evil.png"]:
            self.post_avatar(c, name)
        parent = os.path.dirname(self.uploads)
        self.assertFalse(os.path.exists(os.path.join(parent, "evil.png")))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(parent), "evil.png")))
        stored = os.listdir(self.uploads)
        self.assertTrue(stored)
        for f in stored:
            self.assertTrue(f.startswith("user2_") and "/" not in f and "\\" not in f and ".." not in f, f)

    def test_avatar_rejects_server_side_script_and_nameless_files(self):
        c = self.as_user(ALICE, ALICE_PW)
        for name in ["shell.php", "x.png.php", "..", ".png", "evil"]:
            self.post_avatar(c, name)
        self.assertEqual(os.listdir(self.uploads), [])

    def post_avatar(self, client, filename):
        import io
        tok = __import__("test_auth_wstg").token_of(client.get("/profile/2").get_data(as_text=True))
        return client.post("/account/avatar", data={"csrf_token": tok, "avatar": (io.BytesIO(b"x"), filename)},
                           content_type="multipart/form-data")


class TestATHZ02BypassSchema(AuthzBase):
    def count(self, table):
        return self.q(f"SELECT COUNT(*) FROM {table}")[0][0]

    def test_anonymous_forced_browsing_redirects_to_login(self):
        for path in ADMIN_GETS + ["/orders", "/orders/1", "/profile", "/profile/2", "/checkout"]:
            r = self.c.get(path)
            self.assertEqual((r.status_code, "/login" in r.headers["Location"]), (302, True), path)

    def test_anonymous_cannot_post_to_protected_actions(self):
        products, reviews = self.count("products"), self.count("reviews")
        for path in ADMIN_POSTS + ["/product/1/review", "/account/change-email", "/account/avatar"]:
            r = self.post(path, {"name": "x", "price": "1", "body": "x", "host": "127.0.0.1"}, page="/login")
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/login", r.headers["Location"], path)
        self.assertEqual((self.count("products"), self.count("reviews")), (products, reviews))

    def test_customer_gets_403_on_every_admin_route_and_verb(self):
        c = self.as_user(ALICE, ALICE_PW)
        for path in ADMIN_GETS:
            self.assertEqual(c.get(path).status_code, 403, path)
            self.assertEqual(c.head(path).status_code, 403, path)
        for path in ADMIN_POSTS:
            self.assertEqual(self.post(path, {"name": "x", "price": "1", "host": "127.0.0.1"}, c, "/profile/2").status_code,
                             403, path)

    def test_customer_admin_actions_have_no_effect(self):
        c = self.as_user(ALICE, ALICE_PW)
        products, users = self.count("products"), self.count("users")
        self.post("/admin/products", {"name": "pwn", "price": "1", "description": "", "category": ""}, c, "/profile/2")
        self.post("/admin/products/1/delete", {}, c, "/profile/2")
        self.post("/admin/reset", {}, c, "/profile/2")
        self.assertEqual((self.count("products"), self.count("users")), (products, users))

    def test_path_tricks_do_not_bypass_admin_check(self):
        c = self.as_user(ALICE, ALICE_PW)
        for path in ["/admin//users", "/admin/users/", "/admin/./users", "/admin/%2e%2e/admin/users",
                     "//admin/users", "/admin/users;.css", "/admin/users%00", "/ADMIN/users", "/admin/users?x=/login"]:
            r = c.get(path, follow_redirects=True)
            self.assertNotEqual(r.status_code, 200, path)
            self.assertNotIn(b"vulnershop.test", r.data, path)

    def test_override_headers_and_methods_do_not_bypass(self):
        c = self.as_user(ALICE, ALICE_PW)
        for hdrs in [{"X-HTTP-Method-Override": "GET"}, {"X-Original-URL": "/"}, {"X-Forwarded-For": "127.0.0.1"},
                     {"X-Real-IP": "127.0.0.1"}, {"X-Forwarded-Host": "localhost"}]:
            self.assertEqual(c.get("/admin/users", headers=hdrs).status_code, 403, hdrs)
        self.assertIn(c.open("/admin/users", method="TRACE").status_code, (400, 403, 405))

    def test_admin_can_use_admin_routes(self):
        c = self.as_user(ADMIN, ADMIN_PW)
        for path in ADMIN_GETS:
            self.assertEqual(c.get(path).status_code, 200, path)
        before = self.count("products")
        self.post("/admin/products", {"name": "ok", "price": "5", "description": "", "category": ""}, c, "/admin/products")
        self.assertEqual(self.count("products"), before + 1)

    def test_revoked_admin_loses_access_on_next_request(self):
        c = self.as_user(ADMIN, ADMIN_PW)
        self.assertEqual(c.get("/admin/users").status_code, 200)
        self.exec("UPDATE users SET role='customer' WHERE username='admin'")
        self.assertEqual(c.get("/admin/users").status_code, 403)

    def test_deleted_account_session_stops_working(self):
        c = self.as_user(ALICE, ALICE_PW)
        self.exec("PRAGMA foreign_keys = OFF", "DELETE FROM users WHERE username='alice'")
        self.assertEqual(c.get("/orders").status_code, 302)


class TestATHZ03PrivilegeEscalation(AuthzBase):
    def role_of(self, user):
        return self.q("SELECT role FROM users WHERE username=?", user)[0][0]

    def test_registration_ignores_role_parameter(self):
        for extra in [{"role": "admin"}, {"is_admin": "1"}, {"role[]": "admin"}]:
            self.post("/register", {"username": "evil", "email": "e@example.com",
                                    "password": "correct horse battery", **extra})
            self.assertEqual(self.role_of("evil"), "customer", extra)
            self.exec("DELETE FROM users WHERE username='evil'")

    def test_profile_updates_ignore_role_and_foreign_ids(self):
        c = self.as_user(ALICE, ALICE_PW)
        self.post("/account/change-email", {"email": "a@example.com", "role": "admin", "user_id": "3",
                                            "id": "3", "current_password": ALICE_PW}, c, "/profile/2")
        self.assertEqual(self.role_of("alice"), "customer")
        self.assertEqual(self.q("SELECT email FROM users WHERE username='bob'")[0][0], "bob@vulnershop.test")
        self.assertEqual(self.q("SELECT email FROM users WHERE username='alice'")[0][0], "a@example.com")

    def test_password_change_cannot_target_another_user(self):
        c = self.as_user(ALICE, ALICE_PW)
        self.post("/account/change-password", {"password": "hacked passphrase 1", "username": "bob", "user_id": "3",
                                               "current_password": ALICE_PW}, c, "/profile/2")
        self.assertEqual(self.login(BOB, BOB_PW, self.app.test_client()).status_code, 302)

    def test_forged_cookie_role_is_overwritten_from_database(self):
        c = self.as_user(ALICE, ALICE_PW)
        with c.session_transaction() as s:
            s["role"] = "admin"
        self.assertEqual(c.get("/admin/users").status_code, 403)

    def test_forged_cookie_user_id_cannot_switch_identity(self):
        c = self.as_user(ALICE, ALICE_PW)
        with c.session_transaction() as s:
            s["user_id"], s["username"], s["role"] = 1, "admin", "admin"
        self.assertEqual(c.get("/admin/users").status_code, 403)
        self.assertEqual(c.get("/profile/1").status_code, 404)

    def test_cookie_without_server_side_session_is_ignored(self):
        with self.c.session_transaction() as s:
            s["user_id"], s["username"], s["role"] = 1, "admin", "admin"
        self.assertEqual(self.c.get("/admin/users").status_code, 302)

    def test_no_role_selector_in_profile_forms(self):
        html = self.as_user(ALICE, ALICE_PW).get("/profile/2").get_data(as_text=True)
        self.assertNotIn('name="role"', html)
        self.assertNotIn('name="user_id"', html)


class TestATHZ04IDOR(AuthzBase):
    def test_owner_can_read_own_profile_and_order(self):
        c = self.as_user(ALICE, ALICE_PW)
        self.assertEqual(c.get("/profile/2").status_code, 200)
        self.assertEqual(c.get("/orders/1").status_code, 200)
        self.assertEqual(c.get("/profile", follow_redirects=True).status_code, 200)

    def test_other_users_profiles_denied(self):
        c = self.as_user(ALICE, ALICE_PW)
        for uid in (1, 3):
            r = c.get(f"/profile/{uid}")
            self.assertEqual(r.status_code, 404, uid)
            self.assertNotIn(b"vulnershop.test", r.data)

    def test_other_users_orders_denied(self):
        c = self.as_user(ALICE, ALICE_PW)
        r = c.get("/orders/2")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("۲۹".encode(), r.data)

    def test_foreign_and_missing_ids_are_indistinguishable(self):
        c = self.as_user(ALICE, ALICE_PW)
        for kind in ("profile", "orders"):
            foreign, missing = c.get(f"/{kind}/3" if kind == "profile" else "/orders/2"), c.get(f"/{kind}/9999")
            self.assertEqual((foreign.status_code, foreign.data), (missing.status_code, missing.data), kind)

    def test_id_enumeration_only_yields_own_objects(self):
        c = self.as_user(ALICE, ALICE_PW)
        self.assertEqual([i for i in range(1, 40) if c.get(f"/orders/{i}").status_code == 200], [1])
        self.assertEqual([i for i in range(1, 40) if c.get(f"/profile/{i}").status_code == 200], [2])

    def test_new_order_is_private_to_its_buyer(self):
        bob = self.as_user(BOB, BOB_PW)
        self.post("/cart/add/1", {"qty": "1"}, bob, "/")
        r = self.post("/checkout", {}, bob, "/checkout")
        self.assertEqual(r.status_code, 302)
        order_url = r.headers["Location"]
        self.assertEqual(bob.get(order_url).status_code, 200)
        self.assertEqual(self.as_user(ALICE, ALICE_PW).get(order_url).status_code, 404)

    def test_only_own_orders_listed(self):
        html = self.as_user(ALICE, ALICE_PW).get("/orders").get_data(as_text=True)
        self.assertIn("/orders/1", html)
        self.assertNotIn("/orders/2", html)

    def test_admin_may_read_any_profile_and_order(self):
        c = self.as_user(ADMIN, ADMIN_PW)
        for path in ("/profile/2", "/profile/3", "/orders/1", "/orders/2"):
            self.assertEqual(c.get(path).status_code, 200, path)
        self.assertEqual(c.get("/orders/9999").status_code, 404)

    def test_denials_are_audited(self):
        c = self.as_user(ALICE, ALICE_PW)
        with self.assertLogs("vulnershop.auth", "INFO") as cm:
            c.get("/orders/2")
            c.get("/admin/users")
        text = "\n".join(cm.output)
        self.assertIn("authz_denied", text)
        self.assertIn("path=/orders/2", text)
        self.assertIn("path=/admin/users", text)


if __name__ == "__main__":
    unittest.main()
