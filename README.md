# NouriSec VulnerShop

A fake online store (Persian-themed storefront, "نوری‌شاپ") built with intentional
security bugs, used as the hands-on lab for the NouriSec pentesting course. Every
product, user, and order is fake and seeded by a script — nothing here is a real store.

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

## License

MIT — see [`LICENSE`](LICENSE). Use it, fork it, run your own training sessions with it.
