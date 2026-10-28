# Authentication, authorization & input-validation hardening mode (OWASP WSTG v4.2 §4.4, §4.5 and §4.7)

The lab ships two authentication implementations selected by one switch, so you can demo
*attack → fix → re-attack* on the same app:

| Mode | How | What it is |
|------|-----|-----------|
| `vulnerable` (default) | nothing to set | The original intentionally broken auth used by the course labs |
| `secure` | `VULNERSHOP_AUTH_MODE=secure` | Hardened auth, access control and input handling, covered by `tests/test_auth_wstg.py`, `tests/test_authz_wstg.py` and `tests/test_inpv_wstg.py` |

```bash
VULNERSHOP_AUTH_MODE=secure python scripts/reset_db.py   # reseed: secure mode prints random credentials
VULNERSHOP_AUTH_MODE=secure python run.py
# Docker: VULNERSHOP_AUTH_MODE=secure docker compose up --build
#         docker compose exec vulnershop python scripts/reset_db.py
.venv/bin/python -m unittest discover -s tests -v          # 108 checks, one class per WSTG test
```

Seeded secure-mode accounts get random passwords (printed once; override with
`SEED_PASSWORD_ADMIN`, `SEED_PASSWORD_ALICE`, `SEED_PASSWORD_BOB`). The "mailbox" for reset links
and change notifications is the server log (`vulnershop.mail`); audit events go to
`vulnershop.auth`. Code: [`app/security.py`](app/security.py), secure branches in
[`app/auth.py`](app/auth.py), [`app/account.py`](app/account.py), [`app/admin.py`](app/admin.py), [`app/uploads.py`](app/uploads.py), [`app/shop.py`](app/shop.py), [`app/reviews.py`](app/reviews.py) and [`app/contact.py`](app/contact.py); input helpers in [`app/validation.py`](app/validation.py).

## WSTG coverage

| WSTG | Vulnerable build | Secure mode |
|------|------------------|-------------|
| ATHN-01 Encrypted channel | cookies without flags, no HSTS | `HttpOnly`, `SameSite=Lax`, `Secure` (`SESSION_COOKIE_SECURE=1`), HSTS on HTTPS, optional `FORCE_HTTPS=1` redirect, `TRUST_PROXY=1` behind a TLS proxy, credentials accepted via POST only, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer` |
| ATHN-02 Default credentials | `admin/admin123`, `alice/Password1`, `svc_backup/password123` | random per-seed passwords; leftover `svc_backup` not created; old default creds rejected |
| ATHN-03 Lockout | unlimited guessing | 5 failures/15 min per username → temporary lock (also for non-existent names, so no enumeration; attempts while locked aren't counted, so no lock-extension DoS) plus 20/15 min per IP; reset, register and re-auth forms throttled too |
| ATHN-04 Bypass | SQLi login, `/dev/last-reset`, forged-cookie trust | parameterised lookup, generic error + status, equalised timing for unknown users, new session id on login, **server-side session records** (logout, password change/reset, idle 20 min and absolute 8 h timeouts truly revoke), role re-read from DB each request, random `SECRET_KEY`, debug mode off |
| ATHN-05 Remember password | `autocomplete=off` | no "remember me"; proper `username`/`current-password`/`new-password` hints so password managers work |
| ATHN-06 Browser cache | cacheable | `Cache-Control: no-store` on all dynamic pages |
| ATHN-07 Password policy | none; unsalted MD5 | 10–128 chars, common-password/derived-variant blocklist, no username/email, ≥5 distinct chars, last-5 reuse block; salted scrypt; legacy MD5 hashes upgraded on next login |
| ATHN-08 Security questions | n/a | none exist (deliberately) |
| ATHN-09 Change/reset | `md5("reset-"+user)`, no expiry, global leak page | 256-bit random token, SHA-256 at rest, 15 min expiry, single use, older links invalidated, identical response for unknown users, rate-limited, token-guess throttle, leak page removed (404); password/e-mail change need the **current password**, CSRF token and policy; all other sessions revoked; notification mail to the old address |
| ATHN-10 Alternative channels | any logged-in user can open `/admin/*` | admin routes require `role == admin` (403 otherwise); password hashes hidden in the admin user list |

## Authorization coverage (WSTG v4.2 §4.5)

| WSTG | Vulnerable build | Secure mode |
|------|------------------|-------------|
| ATHZ-01 Directory traversal / file include | `/backup/` dump, fake `/.git/` and `/uploads/` listings are public (`send_from_directory` already blocks `..`, encoded and double-encoded variants) | those paths return 404; avatar names go through `secure_filename` and are re-checked against the extension allow-list, so separators, `..`, nameless and `x.png.php`-style names never reach disk |
| ATHZ-02 Bypassing the authorization schema | any logged-in customer can use every `/admin/*` route and verb | admin routes need `role == admin` (403, audited as `authz_denied`) for GET/HEAD/POST alike; anonymous users are redirected to login; path tricks (`//`, `;`, `%00`, case) and override headers (`X-HTTP-Method-Override`, `X-Original-URL`, `X-Forwarded-For`) do not help; demoting or deleting an account takes effect on the very next request |
| ATHZ-03 Privilege escalation | role is copied into the signed cookie (secret is public, so it can be forged) | role/user id are re-read from the server-side session record on every request, so a forged cookie cannot change them; `role`/`user_id`/`username` form fields are ignored by register, e-mail, password and avatar handlers |
| ATHZ-04 IDOR | `/profile/<id>` and `/orders/<id>` return anyone's data | only the owner or an admin; everyone else gets the same 404 as for a non-existent id (no ID enumeration), and the denial is audited |

CSRF tokens (`csrf_input()` in every POST form) are enforced globally in secure mode, which also
neutralises `app/static/csrf_poc_change_email.html`.

## Input validation coverage (WSTG v4.2 §4.7)

Principle: validate against an allow-list (type, range, length, charset) on the server, use
parameterised APIs and output encoding instead of filtering "bad" characters, and fail with a
generic message. Tests marked *no sink* have no vulnerable code behind them in either mode; they
are "attempted X, got Y" checks that prove the payload stays inert.

| WSTG | Vulnerable build | Secure mode |
|------|------------------|-------------|
| INPV-01 Reflected XSS | search term rendered with `\|safe`; DB error text shown | HTML-encoded on output (autoescape); no error text |
| INPV-02 Stored XSS | review body rendered with `\|safe` | stored as typed, encoded on output; body 1–1000 chars, rating 1–5, product must exist |
| INPV-03 Verb tampering | admin check is verb-agnostic; POST-only routes return 405 | same; tests assert PUT/DELETE/PATCH/TRACE/unknown verbs never succeed or change state, and HEAD/OPTIONS don't bypass the admin check |
| INPV-04 Parameter pollution | `qty` accepts anything (negative, huge, non-numeric → 500); Flask uses the first duplicate | `qty` must be exactly one digit string in 1–10; a repeated field is rejected (not first/last-wins); per-line cap across requests; unknown product → 404 |
| INPV-05 SQL injection | login and search build SQL by concatenation | login already parameterised; search uses bound parameters with `LIKE` wildcards escaped (`ESCAPE '\\'`), length-capped |
| INPV-06/09 LDAP, XPath | *no sink* | tests send filter/XPath metacharacters; they are plain bad credentials |
| INPV-07/08 XML/XXE, SSI | *no sink* | tests store an XXE document and an SSI directive; neither is parsed or executed |
| INPV-10 IMAP/SMTP | *no sink* (contact form only stores; reset mail is simulated) | contact form: valid address, no CR/LF/NUL in name/email, bounded lengths |
| INPV-11 Code injection / LFI | *no sink* (file serving covered by ATHZ-01) | tests send include-style parameters and expression strings; nothing is read or evaluated |
| INPV-12 Command injection | `/admin/ping` concatenates into `shell=True` | hostname/IPv4 allow-list (must start alphanumeric, so it can't be an option), argv list, no shell |
| INPV-13 Format string | *no sink* | tests confirm `%s%n`, `{0}`, `{{config}}` render literally |
| INPV-14 Incubated | stored XSS fires for every later viewer | tests plant payloads as customer and view as customer/admin/anonymous; fetched images restricted to raster types so no SVG can be planted |
| INPV-15 Splitting / smuggling | Werkzeug already rejects CR/LF in header values | tests confirm no injected header/cookie; smuggling needs a front-end proxy and is out of scope for the dev server |
| INPV-17 Host header | reset link built from the request `Host` (poisoned link on `/dev/last-reset`) | `Host` must be in `ALLOWED_HOSTS` (default `localhost,127.0.0.1,[::1]`; set it for real deployments), otherwise 400; forwarding headers are ignored unless `TRUST_PROXY=1` |
| INPV-18 SSTI | *no sink* | tests send `{{…}}`, `${…}`, `<%= %>` in inputs and URL paths; never evaluated |
| INPV-19 SSRF | `/admin/fetch-image` fetches any URL | http(s) only, no credentials in URL, every resolved address must be public (blocks loopback, RFC 1918, link-local/metadata, IPv4-mapped IPv6, decimal/hex spellings), no redirects, 2 MB cap, `image/png|jpeg|gif|webp` only, server-chosen filename; blocked attempts audited (`ssrf_blocked`) |
| ERRH-01 Error handling | `/product/abc` → full stack trace (debug mode) | malformed ids → 404; admin product form validates price/name/category instead of 500 |

INPV-16 (incoming requests) is a methodology step (intercept and replay everything with a proxy),
not a control. Known gaps for this chapter: no Content-Security-Policy beyond `frame-ancestors`
(output encoding is the only XSS defence), the SSRF check resolves before connecting (DNS
rebinding window; pin the resolved IP in production), and the SVG avatar upload is still the
Phase 5 lab.

## Demo script (attack → fix)

1. `vulnerable`: Burp Intruder on `/login`; `' OR '1'='1' --`; `/forgot-password` + `/dev/last-reset`.
2. Switch to `secure` + reseed. Repeat: 429 after 5 tries, SQLi → generic 401, `/dev/last-reset` → 404.
3. Reset flow: request a link, read it in the server log, reuse it (rejected), wait/expire it.
4. Log in on two browsers, change the password in one → the other is logged out.
5. Log out, press Back → nothing cached; replaying the old cookie → rejected.

## Known gaps (intentional or out of scope)

- **No MFA** (not in WSTG 4.2's authentication list; a natural follow-up lesson).
- TLS isn't terminated by Flask: use a reverse proxy and set `SESSION_COOKIE_SECURE=1`, `FORCE_HTTPS=1`, `TRUST_PROXY=1`.
- Registration still says "username already taken" (usernames are public in a shop). Logout is a GET link.
- No password aging (NIST 800-63B advises against forced rotation); no e-mail verification on signup.
- Lockout state is in SQLite; use Redis/WAF rate limiting for multi-instance deployments.
- SVG-upload script execution and the CSRF PoC are covered by the Phase 5 lab. XSS, SQLi, command injection and SSRF are fixed in secure mode as described in the input validation table above.
- Authorization is a per-handler check (`_admin_required`, `_require_owner_or_admin`); there is no central policy layer or per-object ACL, and the admin role is all-or-nothing.
