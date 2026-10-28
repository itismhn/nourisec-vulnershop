"""Automated checks for the business-logic lab, grouped by OWASP WSTG v4.2 test ID
(section 4.10: Business Logic Testing, BUSL-01 .. BUSL-09).

Every test class has two halves: the *vulnerable* build must still be exploitable (so the lab
stays teachable) and the *secure* build (VULNERSHOP_AUTH_MODE=secure) must refuse the same attack.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""
import io
import os
import tempfile
import threading
import unittest
from unittest import mock

from test_auth_wstg import ALICE, ALICE_PW, Base, token_of  # sets the secure-mode test env
from test_authz_wstg import ADMIN, ADMIN_PW, BOB, BOB_PW

from app import create_app
from app.config import Config
from app.db import get_db, init_db
from scripts.seed import seed

V_PW = "Password1"  # seeded password of alice and bob in the vulnerable build
PNG = b"\x89PNG\r\n\x1a\n" + bytes(32)
SVG_XSS = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>'
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
GOOD_CARD, DECLINED_CARD = "4242 4242 4242 4242", "4000 0000 0000 0002"
ALICE_ID, BOB_ID = 2, 3  # seeded ids; alice owns order 1 (1x saffron), bob order 2 (1x smartwatch)


class Lab:
    """Helpers shared by both builds. Subclasses provide self.app and self.go()."""

    def sql(self, query, *args):
        with self.app.app_context():
            db = get_db()
            rows = db.execute(query, args).fetchall()
            db.commit()
            return rows

    def pid(self, name_prefix):
        return self.sql("SELECT id FROM products WHERE name LIKE ?", name_prefix + "%")[0][0]

    def stock(self, product_id):
        return self.sql("SELECT stock FROM products WHERE id = ?", product_id)[0][0]

    def last_order(self):
        return self.sql("SELECT * FROM orders ORDER BY id DESC LIMIT 1")[0]

    def set_cart(self, client, cart):
        with client.session_transaction() as s:
            s["cart"] = {str(k): v for k, v in cart.items()}

    def cart_of(self, client):
        with client.session_transaction() as s:
            return dict(s.get("cart", {}))

    def make_pending_order(self, client, product, qty=1):
        self.set_cart(client, {product: qty})
        r = self.go(client, "/checkout", {}, page="/checkout")
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:300])
        return self.last_order()["id"]

    def pay(self, client, order, card=GOOD_CARD):
        """Pay and, in the vulnerable build, follow the gateway's redirect to /payment/callback."""
        r = self.go(client, f"/orders/{order}/pay", {"card_number": card}, page=f"/orders/{order}/pay")
        while r.status_code == 302 and "/payment/callback" in r.headers["Location"]:
            r = client.get(r.headers["Location"])
        return r

    def upload(self, client, name, data, ctype=None):
        fields = (io.BytesIO(data), name) if ctype is None else (io.BytesIO(data), name, ctype)
        return self.go(client, "/account/avatar", {"avatar": fields}, page=f"/profile/{ALICE_ID}", multipart=True)


class VulnLab(Lab, unittest.TestCase):
    """The default, intentionally broken build, created inside the secure-configured test process."""

    def setUp(self):
        with mock.patch.object(Config, "AUTH_SECURE", False), mock.patch.object(Config, "AUTH_MODE", "vulnerable"):
            self.app = create_app()
        self.app.config["TESTING"] = False
        self.app.config["CHECKOUT_LATENCY"] = 0
        self.uploads = tempfile.mkdtemp()
        self.app.config["UPLOAD_FOLDER"] = self.uploads
        with self.app.app_context():
            init_db()
            seed()

    def go(self, client, path, data=None, page=None, multipart=False):
        return client.post(path, data=data or {}, content_type="multipart/form-data" if multipart else None)

    def user(self, name="alice"):
        c = self.app.test_client()
        self.assertEqual(c.post("/login", data={"username": name, "password": V_PW}).status_code, 302)
        return c


class SecureLab(Lab, Base):
    def setUp(self):
        super().setUp()
        self.app.config["CHECKOUT_LATENCY"] = 0
        self.uploads = tempfile.mkdtemp()
        self.app.config["UPLOAD_FOLDER"] = self.uploads

    def go(self, client, path, data=None, page=None, multipart=False):
        tok = token_of(client.get("/contact").get_data(as_text=True))  # per-session token, any form page
        return client.post(path, data={**(data or {}), "csrf_token": tok},
                           content_type="multipart/form-data" if multipart else None)

    def user(self, name=ALICE, pw=ALICE_PW):
        c = self.app.test_client()
        self.assertEqual(self.login(name, pw, c).status_code, 302)
        return c

    def exec_sql(self, sql, *args):
        with self.app.app_context():
            get_db().execute(sql, args)
            get_db().commit()


# --------------------------------------------------------------------------------------------
class TestBUSL01Vulnerable(VulnLab):
    def test_negative_quantity_makes_a_negative_order(self):
        c, saffron = self.user(), self.pid("زعفران")
        c.post(f"/cart/add/{saffron}", data={"qty": "-5"})
        self.assertEqual(self.cart_of(c), {str(saffron): -5})
        self.assertEqual(self.go(c, "/checkout", {}).status_code, 302)
        self.assertLess(self.last_order()["total"], 0)  # the shop owes the customer money

    def test_rating_outside_1_to_5_skews_the_average(self):
        c, pistachio = self.user(), self.pid("پسته")
        c.post(f"/product/{pistachio}/review", data={"body": "x", "rating": "9999"})
        self.assertEqual(self.sql("SELECT rating FROM reviews WHERE product_id = ?", pistachio)[0][0], 9999)

    def test_free_and_negative_prices_and_junk_contact_data_accepted(self):
        admin = self.app.test_client()
        admin.post("/login", data={"username": "admin", "password": "admin123"})
        admin.post("/admin/products", data={"name": "gift", "price": "-100", "category": "x"})
        self.assertEqual(self.sql("SELECT price FROM products WHERE name = 'gift'")[0][0], -100)
        self.go(self.app.test_client(), "/contact", {"name": "x", "email": "not-an-email", "message": "A" * 100000})
        self.assertEqual(len(self.sql("SELECT 1 FROM contact_messages")), 1)


class TestBUSL01Secure(SecureLab):
    def test_quantities_outside_1_to_10_or_non_numeric_are_refused(self):
        c, saffron = self.user(), self.pid("پسته")
        for qty in ["-5", "0", "11", "abc", "1.5", "", "99999999999"]:
            self.go(c, f"/cart/add/{saffron}", {"qty": qty}, page=f"/product/{saffron}")
            self.assertEqual(self.cart_of(c), {}, qty)

    def test_forged_cart_is_revalidated_at_checkout(self):
        c, pistachio = self.user(), self.pid("پسته")
        self.set_cart(c, {pistachio: -5})
        self.go(c, "/checkout", {}, page="/cart")
        self.assertEqual(self.q("SELECT COUNT(*) FROM orders")[0][0], 2)  # only the seeded ones

    def test_rating_review_length_and_price_bounds(self):
        c, saffron = self.user(), self.pid("زعفران")
        for rating in ["0", "6", "-1", "abc", "99"]:
            self.go(c, f"/product/{saffron}/review", {"body": "ok", "rating": rating}, page=f"/product/{saffron}")
        self.go(c, f"/product/{saffron}/review", {"body": "A" * 2001, "rating": "5"}, page=f"/product/{saffron}")
        self.assertEqual(self.q("SELECT COUNT(*) FROM reviews WHERE user_id = 2")[0][0], 1)  # the seeded one
        admin = self.user(ADMIN, ADMIN_PW)
        for price in ["-100", "0", "nan", "inf", "abc", "1e12"]:
            self.go(admin, "/admin/products", {"name": "gift", "price": price, "category": "x"})
        self.assertEqual(self.q("SELECT COUNT(*) FROM products WHERE name = 'gift'")[0][0], 0)

    def test_contact_form_validates_fields(self):
        for data in [{"name": "x", "email": "nope", "message": "hi"}, {"name": "x", "email": "a@b.co", "message": "A" * 2001}]:
            self.go(self.c, "/contact", data)
        self.assertEqual(self.q("SELECT COUNT(*) FROM contact_messages")[0][0], 0)


# --------------------------------------------------------------------------------------------
class TestBUSL02Vulnerable(VulnLab):
    def test_anyone_can_forge_the_payment_callback(self):
        alice = self.user()
        order = self.make_pending_order(alice, self.pid("پسته"))
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get(f"/payment/callback?order_id={order}&status=success").status_code, 302)
        self.assertEqual(self.last_order()["status"], "paid")  # never paid, never logged in

    def test_the_gateway_result_travels_through_the_browser(self):
        alice = self.user()
        order = self.make_pending_order(alice, self.pid("پسته"))
        r = self.go(alice, f"/orders/{order}/pay", {"card_number": GOOD_CARD})
        self.assertIn(f"/payment/callback?order_id={order}&status=success", r.headers["Location"])


class TestBUSL02Secure(SecureLab):
    def test_callback_does_not_exist_and_cannot_mark_an_order_paid(self):
        alice = self.user()
        order = self.make_pending_order(alice, self.pid("پسته"))
        for url in [f"/payment/callback?order_id={order}&status=success", f"/payment/callback?order_id={order}"]:
            self.assertEqual(self.app.test_client().get(url).status_code, 404)
            self.assertEqual(alice.get(url).status_code, 404)
        self.assertEqual(self.last_order()["status"], "pending_payment")

    def test_order_actions_are_owner_only(self):
        alice, bob = self.user(), self.user(BOB, BOB_PW)
        order = self.make_pending_order(alice, self.pid("پسته"))
        for action in ["pay", "cancel", "refund"]:
            self.assertEqual(self.go(bob, f"/orders/{order}/{action}", {"card_number": GOOD_CARD},
                                     page="/orders").status_code, 404, action)
        self.assertEqual(self.last_order()["status"], "pending_payment")


# --------------------------------------------------------------------------------------------
class TestBUSL03Vulnerable(VulnLab):
    def test_client_supplied_total_sets_the_price(self):
        c, watch = self.user(), self.pid("ساعت")
        self.set_cart(c, {watch: 1})
        self.assertIn(b'name="total"', c.get("/checkout").data)  # the price rides in a hidden field
        self.assertEqual(self.go(c, "/checkout", {"total": "1"}).status_code, 302)
        self.assertEqual(self.last_order()["total"], 1.0)


class TestBUSL03Secure(SecureLab):
    def test_posted_total_is_ignored_and_form_has_no_price_field(self):
        c, watch = self.user(), self.pid("ساعت")
        self.set_cart(c, {watch: 1})
        self.assertNotIn(b'name="total"', c.get("/checkout").data)
        self.go(c, "/checkout", {"total": "1", "subtotal": "1", "discount": "99999", "status": "paid"}, page="/checkout")
        order = self.last_order()
        self.assertEqual((order["total"], order["status"], order["discount"]), (29900000, "pending_payment", 0))


# --------------------------------------------------------------------------------------------
def _parallel(*fns):
    threads = [threading.Thread(target=fn) for fn in fns]
    [t.start() for t in threads]
    [t.join() for t in threads]


class TestBUSL04Vulnerable(VulnLab):
    def test_parallel_checkouts_oversell_the_last_items(self):
        self.app.config["CHECKOUT_LATENCY"] = 0.3
        watch = self.pid("ساعت")
        self.assertEqual(self.stock(watch), 3)
        alice, bob = self.user(), self.user("bob")
        for c in (alice, bob):
            self.set_cart(c, {watch: 2})
        _parallel(lambda: self.go(alice, "/checkout"), lambda: self.go(bob, "/checkout"))
        self.assertEqual(self.stock(watch), -1)  # 4 sold, 3 existed

    def test_unpaid_order_never_expires(self):
        alice = self.user()
        order = self.make_pending_order(alice, self.pid("پسته"))
        self.sql("UPDATE orders SET created_at = datetime('now', '-30 days') WHERE id = ?", order)
        self.pay(alice, order)
        self.assertEqual(self.sql("SELECT status FROM orders WHERE id = ?", order)[0][0], "paid")


class TestBUSL04Secure(SecureLab):
    def test_parallel_checkouts_cannot_oversell(self):
        self.app.config["CHECKOUT_LATENCY"] = 0.3
        watch = self.pid("ساعت")
        alice, bob = self.user(), self.user(BOB, BOB_PW)
        for c in (alice, bob):
            self.set_cart(c, {watch: 2})
        tokens = {id(c): token_of(c.get("/checkout").get_data(as_text=True)) for c in (alice, bob)}
        _parallel(*[lambda c=c: c.post("/checkout", data={"csrf_token": tokens[id(c)]}) for c in (alice, bob)])
        self.assertEqual(self.stock(watch), 1)  # exactly one of the two orders went through
        self.assertEqual(self.q("SELECT COUNT(*) FROM orders WHERE status = 'pending_payment'")[0][0], 1)

    def test_unpaid_order_expires_and_returns_its_stock(self):
        alice, watch = self.user(), self.pid("ساعت")
        order = self.make_pending_order(alice, watch, 2)
        self.assertEqual(self.stock(watch), 1)
        self.exec_sql("UPDATE orders SET created_at = datetime('now', '-20 minutes') WHERE id = ?", order)
        r = alice.get(f"/orders/{order}/pay")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.q("SELECT status FROM orders WHERE id = ?", order)[0][0], "cancelled")
        self.assertEqual(self.stock(watch), 3)

    def test_coupon_expiring_between_apply_and_checkout_is_not_honoured(self):
        alice, pistachio = self.user(), self.pid("پسته")
        self.set_cart(alice, {pistachio: 1})
        self.go(alice, "/cart/coupon", {"code": "WELCOME10"}, page="/cart")
        self.exec_sql("UPDATE coupons SET expires_at = '2020-01-01'")
        self.go(alice, "/checkout", {}, page="/checkout")
        order = self.last_order()
        self.assertEqual((order["discount"], order["coupon_code"]), (0, None))


# --------------------------------------------------------------------------------------------
class TestBUSL05Vulnerable(VulnLab):
    def test_coupons_stack_and_never_run_out(self):
        c, pistachio = self.user(), self.pid("پسته")
        self.set_cart(c, {pistachio: 1})
        for _ in range(11):
            c.post("/cart/coupon", data={"code": "welcome10"})
        c.post("/cart/coupon", data={"code": "NOWRUZ25"})  # expired, still accepted
        self.go(c, "/checkout")
        self.assertLess(self.last_order()["total"], 0)

    def test_purchase_limit_is_only_a_hint(self):
        c, saffron = self.user(), self.pid("زعفران")
        for _ in range(3):
            c.post(f"/cart/add/{saffron}", data={"qty": "10"})
        self.assertEqual(self.cart_of(c)[str(saffron)], 30)  # limit 2 per customer, 1 already bought

    def test_a_refund_can_be_collected_again_and_again(self):
        c = self.user()
        for _ in range(3):
            c.post("/orders/1/refund")
        self.assertEqual(self.sql("SELECT refunded FROM orders WHERE id = 1")[0][0], 3 * 285000)

    def test_repeated_cancel_inflates_stock(self):
        c, pistachio = self.user(), self.pid("پسته")
        order = self.make_pending_order(c, pistachio)
        before = self.stock(pistachio)
        for _ in range(3):
            c.post(f"/orders/{order}/cancel")
        self.assertEqual(self.stock(pistachio), before + 3)

    def test_unlimited_reviews_per_customer(self):
        c, saffron = self.user(), self.pid("زعفران")
        for _ in range(5):
            c.post(f"/product/{saffron}/review", data={"body": "great", "rating": "5"})
        self.assertEqual(self.sql("SELECT COUNT(*) FROM reviews WHERE user_id = 2")[0][0], 6)


class TestBUSL05Secure(SecureLab):
    def test_a_coupon_is_single_use_per_customer_and_not_stackable(self):
        alice, pistachio = self.user(), self.pid("پسته")
        self.set_cart(alice, {pistachio: 1})
        for _ in range(3):
            self.go(alice, "/cart/coupon", {"code": "WELCOME10"}, page="/cart")
        self.go(alice, "/checkout", {}, page="/checkout")
        order = self.last_order()
        self.assertEqual(order["discount"], order["subtotal"] * 0.10)  # one application, not three
        self.set_cart(alice, {pistachio: 1})
        self.go(alice, "/cart/coupon", {"code": "WELCOME10"}, page="/cart")
        self.go(alice, "/checkout", {}, page="/checkout")
        self.assertEqual(self.last_order()["discount"], 0)  # already redeemed by alice
        bob = self.user(BOB, BOB_PW)
        self.set_cart(bob, {pistachio: 1})
        self.go(bob, "/cart/coupon", {"code": "WELCOME10"}, page="/cart")
        self.go(bob, "/checkout", {}, page="/checkout")
        self.assertGreater(self.last_order()["discount"], 0)  # a different customer may still use it

    def test_expired_and_unknown_codes_are_refused_identically(self):
        alice = self.user()
        self.set_cart(alice, {self.pid("پسته"): 1})
        for code in ["NOWRUZ25", "nope"]:
            r = self.go(alice, "/cart/coupon", {"code": code}, page="/cart")
            self.assertIn(b"not valid", alice.get("/cart").data)
        with alice.session_transaction() as s:
            self.assertNotIn("coupon", s)

    def test_purchase_limit_counts_earlier_orders(self):
        alice, saffron = self.user(), self.pid("زعفران")
        self.go(alice, f"/cart/add/{saffron}", {"qty": "2"}, page=f"/product/{saffron}")
        self.assertEqual(self.cart_of(alice), {})  # alice already owns 1 of the 2 allowed
        self.go(alice, f"/cart/add/{saffron}", {"qty": "1"}, page=f"/product/{saffron}")
        self.assertEqual(self.cart_of(alice), {str(saffron): 1})
        self.set_cart(alice, {saffron: 2})  # forged past the add handler: checkout enforces it too
        self.go(alice, "/checkout", {}, page="/cart")
        self.assertEqual(self.q("SELECT COUNT(*) FROM orders WHERE user_id = 2")[0][0], 1)

    def test_refund_once_only_and_restocks_once(self):
        alice, pistachio = self.user(), self.pid("پسته")
        order = self.make_pending_order(alice, pistachio)
        self.go(alice, f"/orders/{order}/pay", {"card_number": GOOD_CARD})
        sold = self.stock(pistachio)
        for _ in range(3):
            self.go(alice, f"/orders/{order}/refund", {}, page=f"/orders/{order}")
        row = self.q("SELECT status, refunded, total FROM orders WHERE id = ?", order)[0]
        self.assertEqual((row["status"], row["refunded"]), ("refunded", row["total"]))
        self.assertEqual(self.stock(pistachio), sold + 1)

    def test_cancel_works_once_and_only_on_unpaid_orders(self):
        alice, pistachio = self.user(), self.pid("پسته")
        order = self.make_pending_order(alice, pistachio)
        before = self.stock(pistachio)
        for _ in range(3):
            self.go(alice, f"/orders/{order}/cancel", {}, page=f"/orders/{order}")
        self.assertEqual(self.stock(pistachio), before + 1)
        self.go(alice, "/orders/1/cancel", {}, page="/orders/1")  # paid (seeded) order
        self.assertEqual(self.q("SELECT status FROM orders WHERE id = 1")[0][0], "completed")

    def test_one_review_per_customer_and_only_after_buying(self):
        alice, saffron = self.user(), self.pid("زعفران")
        self.go(alice, f"/product/{saffron}/review", {"body": "again", "rating": "5"}, page=f"/product/{saffron}")
        self.assertEqual(self.q("SELECT COUNT(*) FROM reviews WHERE user_id = 2")[0][0], 1)  # seeded one only
        tea = self.pid("چای")
        self.go(alice, f"/product/{tea}/review", {"body": "never bought", "rating": "1"}, page=f"/product/{tea}")
        self.assertEqual(self.q("SELECT COUNT(*) FROM reviews WHERE product_id = ?", tea)[0][0], 0)


# --------------------------------------------------------------------------------------------
class TestBUSL06Vulnerable(VulnLab):
    def test_payment_can_be_skipped_entirely(self):
        c = self.user()
        order = self.make_pending_order(c, self.pid("پسته"))
        c.get(f"/payment/callback?order_id={order}&status=success")
        self.assertEqual(self.last_order()["status"], "paid")

    def test_unpaid_cancelled_and_failed_orders_can_be_refunded_or_paid(self):
        c = self.user()
        order = self.make_pending_order(c, self.pid("پسته"))
        c.post(f"/orders/{order}/refund")  # never paid
        row = self.sql("SELECT status, refunded, total FROM orders WHERE id = ?", order)[0]
        self.assertEqual((row[0], row[1]), ("refunded", row[2]))
        self.pay(c, order)  # refunded orders are payable again
        self.assertEqual(self.sql("SELECT status FROM orders WHERE id = ?", order)[0][0], "paid")

    def test_refund_outside_the_return_window(self):
        c = self.user()
        self.sql("UPDATE orders SET created_at = datetime('now', '-90 days') WHERE id = 1")
        c.post("/orders/1/refund")
        self.assertEqual(self.sql("SELECT status FROM orders WHERE id = 1")[0][0], "refunded")

    def test_review_without_buying(self):
        c = self.user("bob")
        tea = self.pid("چای")
        c.post(f"/product/{tea}/review", data={"body": "never bought", "rating": "5"})
        self.assertEqual(self.sql("SELECT COUNT(*) FROM reviews WHERE product_id = ?", tea)[0][0], 1)


class TestBUSL06Secure(SecureLab):
    def setUp(self):
        super().setUp()
        self.alice, self.pistachio = self.user(), self.pid("پسته")

    def state(self, order):
        return self.q("SELECT status FROM orders WHERE id = ?", order)[0][0]

    def test_cannot_refund_unpaid_cancelled_or_old_orders(self):
        order = self.make_pending_order(self.alice, self.pistachio)
        self.go(self.alice, f"/orders/{order}/refund", {}, page=f"/orders/{order}")
        self.assertEqual(self.state(order), "pending_payment")
        self.go(self.alice, f"/orders/{order}/cancel", {}, page=f"/orders/{order}")
        self.go(self.alice, f"/orders/{order}/refund", {}, page=f"/orders/{order}")
        self.assertEqual(self.state(order), "cancelled")
        self.exec_sql("UPDATE orders SET created_at = datetime('now', '-8 days') WHERE id = 1")
        self.go(self.alice, "/orders/1/refund", {}, page="/orders/1")
        self.assertEqual(self.state(1), "completed")

    def test_cannot_pay_a_cancelled_paid_or_refunded_order(self):
        order = self.make_pending_order(self.alice, self.pistachio)
        self.go(self.alice, f"/orders/{order}/cancel", {}, page=f"/orders/{order}")
        self.go(self.alice, f"/orders/{order}/pay", {"card_number": GOOD_CARD}, page="/orders")
        self.assertEqual(self.state(order), "cancelled")
        self.assertEqual(self.go(self.alice, "/orders/1/pay", {"card_number": GOOD_CARD}, page="/orders").status_code, 302)
        self.assertEqual(self.state(1), "completed")

    def test_payment_needs_a_valid_card_and_checks_the_card_number(self):
        order = self.make_pending_order(self.alice, self.pistachio)
        for card in ["", "1234", "4242424242424241", DECLINED_CARD]:  # 4 declines: below the lockout
            r = self.go(self.alice, f"/orders/{order}/pay", {"card_number": card}, page=f"/orders/{order}/pay")
            self.assertEqual(r.status_code, 402, card)
            self.assertEqual(self.state(order), "pending_payment")
        r = self.go(self.alice, f"/orders/{order}/pay", {"card_number": GOOD_CARD}, page=f"/orders/{order}/pay")
        self.assertEqual((r.status_code, self.state(order)), (302, "paid"))


# --------------------------------------------------------------------------------------------
class TestBUSL07Vulnerable(VulnLab):
    def test_no_limit_on_coupon_guessing_card_testing_or_spam(self):
        c = self.user()
        codes = {c.post("/cart/coupon", data={"code": f"GUESS{i}"}).status_code for i in range(30)}
        self.assertEqual(codes, {302})
        order = self.make_pending_order(c, self.pid("پسته"))
        declines = [self.go(c, f"/orders/{order}/pay", {"card_number": DECLINED_CARD}).status_code for _ in range(15)]
        self.assertEqual(set(declines), {402})  # never throttled: a free card-validity oracle
        anon = self.app.test_client()
        for i in range(20):
            self.go(anon, "/contact", {"name": "spam", "email": "a@b.co", "message": f"buy now {i}"})
        self.assertEqual(len(self.sql("SELECT 1 FROM contact_messages")), 20)


class TestBUSL07Secure(SecureLab):
    def test_coupon_guessing_is_throttled_even_for_a_correct_code(self):
        alice = self.user()
        for i in range(5):
            self.go(alice, "/cart/coupon", {"code": f"GUESS{i}"}, page="/cart")
        self.assertEqual(self.go(alice, "/cart/coupon", {"code": "WELCOME10"}, page="/cart").status_code, 429)
        with alice.session_transaction() as s:
            self.assertNotIn("coupon", s)

    def test_card_testing_is_throttled_and_a_good_card_is_blocked_while_locked(self):
        alice = self.user()
        order = self.make_pending_order(alice, self.pid("پسته"))
        for _ in range(5):
            self.assertEqual(self.go(alice, f"/orders/{order}/pay", {"card_number": DECLINED_CARD},
                                     page=f"/orders/{order}/pay").status_code, 402)
        self.assertEqual(self.go(alice, f"/orders/{order}/pay", {"card_number": GOOD_CARD},
                                 page=f"/orders/{order}/pay").status_code, 429)

    def test_contact_and_review_floods_are_throttled(self):
        codes = [self.go(self.c, "/contact", {"name": "s", "email": "a@b.co", "message": f"m{i}"}).status_code
                 for i in range(7)]
        self.assertEqual(codes[:5], [302] * 5)
        self.assertEqual(codes[5:], [429, 429])
        self.assertEqual(self.q("SELECT COUNT(*) FROM contact_messages")[0][0], 5)
        alice, saffron = self.user(), self.pid("زعفران")
        status = [self.go(alice, f"/product/{saffron}/review", {"body": "x", "rating": "5"},
                          page=f"/product/{saffron}").status_code for _ in range(4)]
        self.assertEqual(status[-1], 429)

    def test_rejections_leave_an_audit_trail(self):
        alice = self.user()
        with self.assertLogs("vulnershop.auth", level="INFO") as logs:
            self.go(alice, "/cart/coupon", {"code": "NOPE"}, page="/cart")
            order = self.make_pending_order(alice, self.pid("پسته"))
            self.go(alice, f"/orders/{order}/pay", {"card_number": DECLINED_CARD}, page=f"/orders/{order}/pay")
        text = "\n".join(logs.output)
        self.assertIn("event=coupon_rejected", text)
        self.assertIn("event=card_declined", text)


# --------------------------------------------------------------------------------------------
class TestBUSL08Vulnerable(VulnLab):
    def test_only_the_file_name_is_checked_not_the_content(self):
        c = self.user()
        for name, data in [("shell.php.png", b"<?php system($_GET['c']); ?>"), ("doc.png", b"%PDF-1.4 not an image"),
                           ("bomb.gif", b"A" * 3_000_000), ("x.jpeg", b"plain text")]:
            self.assertEqual(self.upload(c, name, data, "image/png").status_code, 302, name)
        self.assertEqual(len(os.listdir(self.uploads)), 4)


class TestBUSL08Secure(SecureLab):
    def test_content_must_match_the_claimed_type_whatever_the_headers_say(self):
        c = self.user()
        for name, data, ctype in [("a.png", b"%PDF-1.4 not an image", "image/png"), ("b.jpg", PNG, "image/jpeg"),
                                  ("c.gif", PNG, "image/gif"), ("d.png", b"plain text", None),
                                  ("e.php", PNG, "image/png"), ("f.png.php", PNG, "image/png"),
                                  ("g.svg", SVG_XSS, "image/png"), ("h.html", b"<html>", "image/png")]:
            self.upload(c, name, data, ctype)
        self.assertEqual(os.listdir(self.uploads), [])
        self.assertIsNone(self.q("SELECT avatar FROM users WHERE id = 2")[0][0])

    def test_valid_image_is_accepted_under_a_server_chosen_name(self):
        c = self.user()
        self.assertEqual(self.upload(c, "../../my photo.PNG", PNG).status_code, 302)
        (stored,) = os.listdir(self.uploads)
        self.assertRegex(stored, r"^user2_[0-9a-f]{16}\.png$")

    def test_size_limit_and_upload_rate_limit(self):
        c = self.user()
        self.upload(c, "big.png", PNG + bytes(1024 * 1024))
        self.assertEqual(os.listdir(self.uploads), [])
        statuses = [self.upload(c, "ok.png", PNG).status_code for _ in range(6)]
        self.assertEqual(statuses[-1], 429)


# --------------------------------------------------------------------------------------------
class TestBUSL09Vulnerable(VulnLab):
    def test_svg_with_script_is_stored_and_served_as_an_executable_document(self):
        c = self.user()
        self.upload(c, "evil.svg", SVG_XSS)
        (stored,) = os.listdir(self.uploads)
        r = c.get(f"/uploads/{stored}")
        self.assertEqual(r.mimetype, "image/svg+xml")
        self.assertIn(b"<script>", r.data)
        self.assertNotIn("Content-Security-Policy", r.headers)

    def test_eicar_and_polyglots_are_accepted(self):
        c = self.user()
        self.upload(c, "eicar.png", EICAR)
        self.upload(c, "poly.gif", b"GIF89a" + b"<script>alert(1)</script>")
        self.assertEqual(len(os.listdir(self.uploads)), 2)


class TestBUSL09Secure(SecureLab):
    def test_svg_and_script_bearing_images_are_rejected(self):
        c = self.user()
        payloads = {"evil.svg": SVG_XSS, "eicar.png": EICAR, "poly.png": PNG + b"<script>alert(1)</script>",
                    "php.png": PNG + b"<?php system($_GET['c']); ?>", "xss.gif": b"GIF89a<img src=x onerror=alert(1)>",
                    "html.jpg": b"\xff\xd8\xff<html><body>hi", "ctype.png": PNG + b"JavaScript:alert(1)"}
        for name, data in payloads.items():
            self.upload(c, name, data)
        self.assertEqual(os.listdir(self.uploads), [])

    def test_uploads_are_served_sandboxed_and_old_avatar_is_replaced(self):
        c = self.user()
        self.upload(c, "a.png", PNG)
        (first,) = os.listdir(self.uploads)
        r = c.get(f"/uploads/{first}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("sandbox", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.upload(c, "b.png", PNG)
        self.assertEqual(len(os.listdir(self.uploads)), 1)
        self.assertNotIn(first, os.listdir(self.uploads))


if __name__ == "__main__":
    unittest.main()
