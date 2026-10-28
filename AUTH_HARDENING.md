# Authentication hardening mode (OWASP WSTG v4.2 §4.4)

The lab ships two authentication implementations selected by one switch, so you can demo
*attack → fix → re-attack* on the same app:

| Mode | How | What it is |
|------|-----|-----------|
| `vulnerable` (default) | nothing to set | The original intentionally broken auth used by the course labs |
| `secure` | `VULNERSHOP_AUTH_MODE=secure` | Hardened auth, covered by `tests/test_auth_wstg.py` |

```bash
VULNERSHOP_AUTH_MODE=secure python scripts/reset_db.py   # reseed: secure mode prints random credentials
VULNERSHOP_AUTH_MODE=secure python run.py
# Docker: VULNERSHOP_AUTH_MODE=secure docker compose up --build
#         docker compose exec vulnershop python scripts/reset_db.py
.venv/bin/python -m unittest discover -s tests -v          # 35 checks, one class per WSTG test
```

Seeded secure-mode accounts get random passwords (printed once; override with
`SEED_PASSWORD_ADMIN`, `SEED_PASSWORD_ALICE`, `SEED_PASSWORD_BOB`). The "mailbox" for reset links
and change notifications is the server log (`vulnershop.mail`); audit events go to
`vulnershop.auth`. Code: [`app/security.py`](app/security.py), secure branches in
[`app/auth.py`](app/auth.py) and [`app/account.py`](app/account.py).

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

CSRF tokens (`csrf_input()` in every POST form) are enforced globally in secure mode, which also
neutralises `app/static/csrf_poc_change_email.html`.

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
- IDOR (`/profile/<id>`, `/orders/<id>`), XSS, SQLi in search, uploads, SSRF, etc. are other labs and stay vulnerable in both modes.
