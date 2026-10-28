# NouriSec VulnerShop

<p align="left">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" />
  <img src="https://img.shields.io/badge/python-3.12-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/flask-3.0-black?style=flat-square&logo=flask&logoColor=white" alt="Flask 3.0" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker ready" />
  <img src="https://img.shields.io/badge/OWASP-WSTG%20%2F%20Top%2010-black?style=flat-square" alt="OWASP WSTG / Top 10" />
</p>

A fake online store (Persian-themed storefront, "نوری‌شاپ") built with **12 intentional
security bug classes**, used as the hands-on lab for the [NouriSec](https://nourisec.com)
pentesting course. Every product, user, and order is fake and seeded by a script —
nothing here is a real store, and nothing here should ever be deployed anywhere but
your own machine.

It's built for people learning web application penetration testing who want a real,
clickable target instead of a slide deck: a full Flask app with a database, sessions,
file uploads, an admin panel, and a checkout flow — all wired with bugs that map to the
[OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
and the OWASP Top 10.

## Contents

- [What's inside](#whats-inside)
- [Run it](#run-it)
- [Test accounts](#test-accounts)
- [How to test it](#how-to-test-it)
- [Docs](#docs)
- [A few things worth knowing](#a-few-things-worth-knowing)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## What's inside

| # | Vulnerability | Class | WSTG ID |
|---|----------------|-------|---------|
| 1 | SQL Injection — login & search | Input Validation | WSTG-INPV-05 |
| 2 | Reflected XSS — search results | Input Validation | WSTG-INPV-01 |
| 3 | Stored XSS — product reviews | Input Validation | WSTG-INPV-02 |
| 4 | Broken Access Control — IDOR (`/profile/<id>`, `/orders/<id>`) | Authorization | WSTG-ATHZ-02/04 |
| 5 | Broken Authentication — no lockout, weak password policy, leaky reset flow | Authentication | WSTG-ATHN-02/03/04/07 |
| 6 | Security Misconfiguration — exposed `.git`, backups, directory listing, debug pages | Config | WSTG-CONF-01/02/03/06 |
| 7 | CSRF — account settings forms | Session Mgmt | WSTG-SESS-05 |
| 8 | Insecure File Upload — extension-only checks, SVG with embedded script, EICAR/polyglots accepted | Business Logic | WSTG-BUSL-08/09 |
| 9 | Sensitive Data Exposure — unsalted hashes, hardcoded API key | Cryptography | WSTG-CRYP-04 |
| 10 | Command Injection — admin "ping" tool | Input Validation | WSTG-INPV-12 |
| 11 | SSRF — admin "fetch image by URL" tool | Input Validation | WSTG-INPV-19 |
| 12 | Business Logic Flaws — negative quantities and ratings, client-trusted total, forgeable payment callback, stock race, reusable coupons and refunds, skippable order workflow, no abuse throttling | Business Logic | WSTG-BUSL-01..07 |

Every one of these is confirmed working end-to-end, with a staged path from "find it"
to "exploit it" to "here's the fix" — see [Docs](#docs) below.

> **Hardening mode:** set `VULNERSHOP_AUTH_MODE=secure` to run the same app with a
> WSTG-4.4/4.5/4.7-aligned authentication, authorization and input-validation and business-logic layer (lockout, safe reset flow, server-side
> sessions, password policy, admin role checks, IDOR ownership checks, output encoding, parameterised queries, SSRF allow-listing, server-side totals, atomic stock, throttling, ...). Default is `vulnerable`. See [AUTH_HARDENING.md](AUTH_HARDENING.md).

## Run it

**Docker (recommended):**

```bash
docker compose up --build
```

Open <http://127.0.0.1:5000>. The database seeds itself automatically on first boot.

<details>
<summary><b>Linux prerequisites</b> (if <code>docker compose</code> doesn't work)</summary>

Distro packages like Ubuntu's `docker.io` often ship without the Compose plugin or
without the daemon running. The quickest fix is Docker's official install script,
which installs Docker Engine and the Compose plugin together:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # then log out and back in
docker compose version          # should print a version
```

Common errors:

- `docker: unknown command: docker compose`: the Compose plugin is missing. Install
  `docker-compose-plugin` (apt/dnf) or use the script above.
- `Cannot connect to the Docker daemon`: the service isn't running. Run
  `sudo systemctl enable --now docker`, or `sudo service docker start` on systems
  without systemd (e.g. WSL).
- `permission denied ... docker.sock`: your user isn't in the `docker` group. Run the
  `usermod` line above and log in again.

</details>

**Or locally, without Docker:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/reset_db.py
python run.py
```

Open <http://127.0.0.1:5000> (or set `PORT=5050` before `python run.py` if 5000 is
already taken, e.g. by macOS AirPlay).

## Test accounts

| Username     | Password      | Role     |
|--------------|---------------|----------|
| `admin`      | `admin123`    | admin    |
| `alice`      | `Password1`   | customer |
| `bob`        | `Password1`   | customer |
| `svc_backup` | `password123` | admin    |

## How to test it

Open [`STUDENT_LAB.md`](STUDENT_LAB.md) — it's a staged checklist of what to try, in
order (recon first, then login, then everything else). No answers, just hints, so you
actually practice finding things.

If you just want to see something work right away, try this in the login form:

```
username: ' OR '1'='1' --
password: (anything)
```

That logs you in as `admin` with no real password — a SQL injection bug in the login
query. From there, `STUDENT_LAB.md` walks through the rest (XSS, IDOR, CSRF, and more).
Stuck on one? [`VULN_TIPS.md`](VULN_TIPS.md) has a short nudge and the exact steps to
trigger each bug, without spoiling the fix.

When you're done (or want a clean slate for someone else), reset everything:

```bash
python scripts/reset_db.py
```

or click **Reset Database** in the admin panel (`/admin`) while logged in. Re-run it after
pulling an update that changes the schema (Phase 5 added stock, coupons and order columns).

## Phase 2: Authentication tips

Phase 2 of the course is the OWASP WSTG v4.2 authentication chapter (§4.4). Run each test
against `vulnerable` first (it should break), then against `secure` (it should hold). Switch
modes with `VULNERSHOP_AUTH_MODE=secure|vulnerable` and re-run `python scripts/reset_db.py` —
secure mode prints random passwords instead of the table above. Full control list and demo
script: [`AUTH_HARDENING.md`](AUTH_HARDENING.md).

| WSTG | Tip | How to achieve | Secure mode result |
|------|-----|----------------|--------------------|
| ATHN-02 | Vendor-style default logins | Try `admin/admin123`, `alice/Password1`, `svc_backup/password123` | 401 — random passwords, `svc_backup` removed |
| ATHN-03 | Nothing stops repeat guesses | Send 6+ wrong passwords for one user (Burp Intruder or a curl loop) | 429 after 5; same for unknown usernames |
| ATHN-04 | The login query trusts your input | `' OR '1'='1' --` as username; also open `/admin/users` as a customer | Generic 401; admin pages return 403 |
| ATHN-04 | A logout that only clears the browser | Copy your session cookie, log out, replay the cookie | Rejected (server-side sessions) |
| ATHN-06 | Pages linger after logout | Log out, press Back | `Cache-Control: no-store`, nothing shown |
| ATHN-07 | No password rules | Register with `a`, `password123`, or your own username | Rejected (length, common list, username) |
| ATHN-09 | The reset flow leaks | Request a reset for `alice`, open `/dev/last-reset`; or open `/reset-password/<md5("reset-alice")>` | 404; random, hashed, 15-minute, single-use tokens |
| ATHN-09 | Changing a password needs no proof | POST `/account/change-password` without the current password, or via `app/static/csrf_poc_change_email.html` | Needs current password + CSRF token; other sessions are logged out |

Secure mode logs reset links and change notices to the server console (`[SIMULATED EMAIL]`)
and audit events as `vulnershop.auth`. Automated checks: `python -m unittest discover -s tests`.

## Phase 3: Authorization tips

Phase 3 is the OWASP WSTG v4.2 authorization chapter (§4.5). Same drill as Phase 2: run each test
against `vulnerable` first (it should break), then against `secure` (it should hold). You need two
customer accounts plus an anonymous session. Controls and rationale: [`AUTH_HARDENING.md`](AUTH_HARDENING.md#authorization-coverage-wstg-v42-45).

| WSTG | Tip | How to achieve | Secure mode result |
|------|-----|----------------|--------------------|
| ATHZ-04 | Numbers in URLs are keys to other people's data | Log in as `bob`, open `/orders/1` and `/profile/1`; then walk the IDs upward | 404 for anything not yours, identical to a missing ID; admins may view all |
| ATHZ-02 | The admin panel only checks "logged in" | As a customer, open `/admin/users`, then POST `/admin/products` or `/admin/reset` | 403 on every admin route and verb; anonymous users go to login |
| ATHZ-03 | Roles should never come from the client | Add `role=admin` to `/register` and `/account/change-email`; edit the `role` inside your session cookie | Fields ignored; role and user id are re-read from the server-side session on every request |
| ATHZ-01 | `../` is blocked, but the leftovers are not | Try `/backup/../app/config.py` and encoded variants (blocked); then fetch `/backup/app_backup.sql`, browse `/backup/`, `/.git/`, `/uploads/` | Those paths return 404; avatar filenames are sanitised and extension-checked |

Denied attempts are logged as `authz_denied` on the `vulnershop.auth` logger. Automated checks:
`python -m unittest discover -s tests` (`tests/test_authz_wstg.py`).

## Phase 4: Input validation tips

Phase 4 is the OWASP WSTG v4.2 input validation chapter (§4.7, INPV-01 to INPV-19). Same drill:
`vulnerable` first, then `secure`. Rows marked *probe* have no vulnerable code behind them, so the
expected result in **both** modes is "payload comes back inert" and that result is your evidence.
Controls and rationale: [`AUTH_HARDENING.md`](AUTH_HARDENING.md#input-validation-coverage-wstg-v42-47).

| WSTG | Tip | How to achieve | Secure mode result |
|------|-----|----------------|--------------------|
| INPV-01 | Search echoes your input unescaped | Search `<script>alert(1)</script>`; also try breaking out of the page title and error box | Rendered as text (HTML-encoded) |
| INPV-02 | Reviews are stored raw | Post a review with a script tag, then view it as another user | Encoded for every viewer; bad length/rating rejected |
| INPV-03 | Verb handling | `curl -i -X OPTIONS/HEAD/PUT/DELETE` on `/admin/*` and `/cart/add/1` | Never 200 for a mutation; customers get 403 on HEAD |
| INPV-04 | Duplicate parameters / unchecked `qty` | `qty=1&qty=-5`; `qty=-5`; `/search?q=a&q=b` | Duplicate or out-of-range `qty` rejected; cart unchanged |
| INPV-05 | Concatenated SQL | `'` in login/search; `UNION SELECT` with 5 columns | Generic 401 / literal search, no error text |
| INPV-06–09, 13, 18 | *probe* — no LDAP, XML, XPath, SSI, format or template sinks | `*)(uid=*`, XML with an entity, `<!--#exec cmd="id"-->`, `%s%n`, `{{7*7}}` in every input and in URL paths | Inert everywhere (that is the finding) |
| INPV-10 | Contact form takes a name and e-mail | CR/LF (`%0d%0a`) in `name` and `email` | 400, nothing stored |
| INPV-11 | Look for include-style parameters | `?page=`, `?file=`, `lang` cookie, traversal in path segments | Nothing read or evaluated |
| INPV-12 | Ping builds a shell string | `127.0.0.1; id` in `/admin/ping` (**Docker only**) | 400; argv list, no shell |
| INPV-14 | Plant now, fire later | Stored payload in review/contact, then view as admin and anonymous | Encoded for all viewers |
| INPV-15 | CR/LF into headers | `%0d%0a` in `/set-language/<x>`, search, redirects | No injected header or cookie |
| INPV-17 | Reset link uses the `Host` header | `curl -H "Host: evil.test" -d username=alice /forgot-password`, then open `/dev/last-reset` | 400 for unknown `Host`; `/dev/last-reset` gone |
| INPV-19 | Fetch tool trusts any URL | `http://127.0.0.1:5000/...` in `/admin/fetch-image` (**Docker only**) | 400; only public http(s) images |

Automated checks: `python -m unittest discover -s tests` (`tests/test_inpv_wstg.py`).

## Phase 5: Business logic tips

Phase 5 is the OWASP WSTG v4.2 business-logic chapter (§4.10). Same drill: break it in `vulnerable`,
then confirm `secure` holds. Buy something first (cart → discount code → checkout → pay → order page);
the test cards are on the payment page (`4242 4242 4242 4242` pays, `4000 0000 0000 0002` is declined).
Codes: `WELCOME10` works; `NOWRUZ25` is a retired campaign. Controls: [`AUTH_HARDENING.md`](AUTH_HARDENING.md#business-logic-coverage-wstg-v42-410).

| WSTG | Tip | How to achieve | Secure mode result |
|------|-----|----------------|--------------------|
| BUSL-01 | Numbers the form never offers | Add a product with `qty=-5`, check out; post a review with `rating=9999` | Quantity 1–10 and rating 1–5 only; bad values leave the cart unchanged |
| BUSL-02 | The gateway "calls back" through the browser | Pay, note the redirect to `/payment/callback?order_id=…&status=success`, then call it for an unpaid order while logged out | Route returns 404; the server marks orders paid itself |
| BUSL-03 | Hidden field named `total` on checkout | Edit it to `1` before submitting | Posted total ignored; recomputed from database prices |
| BUSL-04 | Check-then-act on stock; orders never expire | Two parallel checkouts for the 3-left smartwatch; pay an order after back-dating it | Atomic stock reservation; unpaid orders cancel after 15 minutes and restock |
| BUSL-05 | "Once", "limit 2", "7 days" are only text | Apply `WELCOME10` many times; refund the same order repeatedly; review one product five times | Single-use, non-stackable codes; purchase limits; one refund; one review |
| BUSL-06 | Steps trust that the previous step happened | Refund or cancel an unpaid order; pay a cancelled one; review without buying | Each action is only valid from the right state |
| BUSL-07 | No one is watching | 20 wrong coupon codes, 15 declined cards, 20 contact messages | `429` after 5 (reviews: 3/hour), generic messages, audit log events |
| BUSL-08/09 | Only the file name is checked | Upload `shell.php.png` containing HTML, an SVG with `<script>`, the EICAR string as `.png` | Magic bytes + content scan + 1 MB cap, no SVG, random stored name, sandboxed responses |

Automated checks: `python -m unittest discover -s tests` (`tests/test_busl_wstg.py` runs every attack against both builds).

## Docs

- [`STUDENT_LAB.md`](STUDENT_LAB.md) — what to test, hints only.
- [`VULN_TIPS.md`](VULN_TIPS.md) — stuck on one? A short tip plus the exact steps to
  trigger each bug (still no fixes — those stay in the instructor guide).
- [`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md) — the answer key: exact location, root
  cause, and fix for every bug. Don't peek before you've tried.
- [`REPORT_TEMPLATE.md`](REPORT_TEMPLATE.md) — a template for writing up findings like a
  real pentest report.
- [`/disclaimer`](app/templates/disclaimer.html) — full safety notice and scope, also
  linked in the footer of every page.

## A few things worth knowing

- This is for learning on your own machine, not for exposing on the internet. It's not
  authorized for testing against anything other than itself.
- Two of the bugs (the admin "ping" tool and "fetch image by URL") make the *server*
  run commands / make requests. Docker Compose keeps the container off the real
  internet (`internal: true` network) so these stay contained. If you run it outside
  Docker, they run for real on your machine — only do that on a disposable box.

## Contributing

Contributions are welcome — new vulnerability classes, better hints, translations,
fixes to the app's *non*-intentional bugs (typos, broken links, layout issues). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to get set up and what makes a good PR.

## Security

This app is *intentionally* vulnerable — the bugs listed in [What's inside](#whats-inside)
are the point, not something to report. If you find a way to break out of the intended
scope (e.g. escape the app sandbox, or a bug that isn't one of the documented ones and
could affect people running this outside their own machine), see
[`SECURITY.md`](SECURITY.md) for how to report it responsibly.

## License

MIT — see [`LICENSE`](LICENSE). Use it, fork it, run your own training sessions with it.

---

<p align="center">
  Built by <a href="https://github.com/itismhn">Mohammad Hossein Nouri</a> —
  part of <a href="https://nourisec.com">NouriSec</a>, hands-on penetration testing training.
</p>
