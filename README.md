# NouriSec VulnerShop

<p align="left">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" />
  <img src="https://img.shields.io/badge/python-3.12-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/flask-3.0-black?style=flat-square&logo=flask&logoColor=white" alt="Flask 3.0" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker ready" />
  <img src="https://img.shields.io/badge/OWASP-WSTG%20%2F%20Top%2010-black?style=flat-square" alt="OWASP WSTG / Top 10" />
</p>

A fake online store (Persian-themed storefront, "نوری‌شاپ") built with **11 intentional
security bugs**, used as the hands-on lab for the [NouriSec](https://nourisec.com)
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
| 4 | Broken Access Control — IDOR (`/profile/<id>`, `/orders/<id>`) | Authorization | WSTG-ATHZ-01/04 |
| 5 | Broken Authentication — no lockout, weak password policy, leaky reset flow | Authentication | WSTG-ATHN-02/03/04/07 |
| 6 | Security Misconfiguration — exposed `.git`, backups, directory listing, debug pages | Config | WSTG-CONF-01/02/03/06 |
| 7 | CSRF — account settings forms | Session Mgmt | WSTG-SESS-05 |
| 8 | Insecure File Upload — SVG with embedded script | Business Logic | WSTG-BUSL-09 |
| 9 | Sensitive Data Exposure — unsalted hashes, hardcoded API key | Cryptography | WSTG-CRYP-04 |
| 10 | Command Injection — admin "ping" tool | Advanced | — |
| 11 | SSRF — admin "fetch image by URL" tool | Advanced | — |

Every one of these is confirmed working end-to-end, with a staged path from "find it"
to "exploit it" to "here's the fix" — see [Docs](#docs) below.

## Run it

**Docker (recommended):**

```bash
docker compose up --build
```

Open <http://127.0.0.1:5000>. The database seeds itself automatically on first boot.

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

or click **Reset Database** in the admin panel (`/admin`) while logged in.

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
