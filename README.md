# NouriSec VulnerShop

⚠️ **EDUCATIONAL / INTENTIONALLY VULNERABLE APPLICATION — NouriSec Training Lab.**
This site contains deliberate security flaws for authorized learning only. Do **not** enter
real personal data, real passwords, or real payment details. Do **not** attack any system you
are not explicitly authorized to test.

## What this is

VulnerShop is a realistic-looking (but entirely fake) online store, deliberately built with a
set of OWASP Top 10 (2021) vulnerabilities mapped to OWASP WSTG test IDs. It's the hands-on lab
target for the NouriSec penetration-testing course: students go recon → exploit → remediate →
report against a target they're fully authorized to attack, because it's this one.

Every product, user, order, and review is fake, seeded by a script. Nothing here talks to a
real payment gateway, a real email provider, or the real internet in any meaningful way.

See [`/disclaimer`](app/templates/disclaimer.html) (also linked in the footer of every page) for
the full safety notice, and [`STUDENT_LAB.md`](STUDENT_LAB.md) for the staged challenges.

## Stack

Flask + SQLite + Jinja2 + Bootstrap. Single Python process, no frontend build step, zero
external database service. This keeps the entire attack surface readable top-to-bottom in a
handful of files, which matters more here than performance or scalability ever would.

## ⚠️ Run this in an isolated environment only

This is not a real store and must never be deployed as one. Specifically:

- Run it **only** via the provided Docker Compose setup, on a machine/network you control
  (a local laptop, an isolated VM, or a private VPS behind a firewall with no public exposure).
- The default `docker-compose.yml` publishes the app only to `127.0.0.1:5000` on the host, and
  attaches the container to an `internal: true` Docker network so it **cannot make outbound
  connections to the real internet**. This matters because two of the intentional
  vulnerabilities (command injection in the admin "ping" tool, and SSRF in "fetch image by URL")
  let a user make the *server* issue commands/requests — the network isolation is what keeps
  those contained to this sandbox instead of becoming a launchpad against real third parties.
- Never remove the `internal: true` line, never add other services to `vulnershop_net`, and
  never bridge this network to your real LAN/Wi-Fi.
- If you run it outside Docker (`python run.py` directly on your machine, for convenience while
  developing the lab itself) those two modules are **not sandboxed** — they'll execute real
  shell commands and real outbound HTTP requests on your actual machine. Only do this on a
  disposable machine/VM you don't mind touching.

## One-command run

```bash
docker compose up --build
```

Then open <http://127.0.0.1:5000>. The container seeds the database automatically on first boot.

## Running locally without Docker (dev/testing only)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/reset_db.py   # creates + seeds the database
python run.py                # http://127.0.0.1:5000
```

## Seeded accounts

All fake. All documented here on purpose — some are meant to be found by students, others
are meant to be *guessed or cracked*, per the lab design (see `STUDENT_LAB.md`).

| Username     | Password      | Role     | Notes |
|--------------|---------------|----------|-------|
| `admin`      | `admin123`    | admin    | Default/predictable admin creds (WSTG-ATHN-02) |
| `alice`      | `Password1`   | customer | |
| `bob`        | `Password1`   | customer | |
| `svc_backup` | `password123` | admin    | Leftover service account, also leaked (as an MD5 hash) via `/backup/app_backup.sql` |

## Resetting the lab

Multiple students can practice against a clean state at any time:

```bash
python scripts/reset_db.py
```

or click **Reset Database** on the admin dashboard (`/admin`) while logged in — reachable by any
logged-in account, not just admins, which is itself one of the intentional vulnerabilities.

## Repository layout

```
app/                Flask application (blueprints, templates, static assets)
scripts/seed.py      Populates fake products/users/orders/reviews
scripts/reset_db.py  Wipes + reseeds the database
backup/              Intentionally web-accessible old DB dump (misconfig lesson)
robots.txt           Disallows all crawlers (also lists interesting paths on purpose)
Dockerfile, docker-compose.yml, docker-entrypoint.sh
INSTRUCTOR_GUIDE.md   Full vuln map + exploitation walkthroughs + fixes (instructor-only)
STUDENT_LAB.md        Staged challenges, hints only, no answers
REPORT_TEMPLATE.md    Pentest report template for students to fill in
```

## Documentation map

- **Students:** start with [`STUDENT_LAB.md`](STUDENT_LAB.md) and [`REPORT_TEMPLATE.md`](REPORT_TEMPLATE.md).
- **Instructors:** [`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md) has the answer key — every
  vulnerability's exact location, root cause, PoC, and the correct secure-code fix. Don't share
  it with students before they've had a real attempt.
