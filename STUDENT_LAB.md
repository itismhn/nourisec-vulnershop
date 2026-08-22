# STUDENT LAB — NouriSec VulnerShop

⚠️ This is the training lab described in [`README.md`](README.md). Reminder: authorized testing
is scoped to **this application only**, running in your own isolated environment. Never enter
real personal data, passwords, or payment details. Read [`/disclaimer`](app/templates/disclaimer.html)
before you start.

This lab is staged by WSTG phase, matching how a real engagement flows: information gathering
first, then authentication, then authorization, then input validation, then business logic, then
you write it all up. Each item gives you a hint, not the answer — the goal is to practice finding
things, not to copy a payload. When you find something, log it (target, steps, evidence) so you
can carry it straight into `REPORT_TEMPLATE.md` at the end.

Truly stuck on one? [`VULN_TIPS.md`](VULN_TIPS.md) gives a bit more — a concrete nudge
and the exact steps to trigger the bug — without spoiling the fix. Don't skip ahead to
`INSTRUCTOR_GUIDE.md` though — it's the full answer key and will spoil the exercise.

---

## Phase 1 — Information Gathering & Fuzzing (WSTG-INFO)

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-INFO-01 | robots.txt / search engine discovery | Check `/robots.txt`. Sometimes a `Disallow` entry tells you more than it hides. |
| 2 | WSTG-INFO-02 | Fingerprint the server & framework | Look at the HTTP response headers on any request. What's serving this, and what version? |
| 3 | WSTG-INFO-05 | Review page source for info leakage | View source and any linked JS/CSS. Developers leave things in comments they shouldn't. |
| 4 | WSTG-CONF-01 | Infrastructure config / exposed VCS | A common mistake is deploying the `.git` folder with the app. Is it reachable? |
| 5 | WSTG-CONF-02 | Backup & unreferenced files | Try predictable backup names/extensions (`~`, `.bak`, `.old`, `.sql`, `.zip`) against paths you've found. |
| 6 | WSTG-ERRH-01 | Error handling / stack traces | Send malformed input somewhere and see what the app tells you about itself when it breaks. |
| 7 | WSTG-INFO-06/07 | Map entry points & architecture | Enumerate every page, form, and query/path parameter you can find before moving to Phase 2. |
| 8 | WSTG-CONF-04 | Enumerate hidden/admin interfaces | Not every page is linked from the UI. What would you expect an admin panel's URL to look like? |
| 9 | — (fuzzing) | Parameter & directory fuzzing | Run a wordlist against paths, and against parameter names on the search/login/product forms. Note which inputs change response size, status code, or timing — that's your Phase 4 target list. |
| 10 | WSTG-CONF-05 | HTTP method tampering | Try methods other than GET/POST on endpoints you've found. Anything behave differently? |

---

## Phase 2 — Authentication (WSTG-ATHN)

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-ATHN-02 | Default credentials | Every store has an admin. Try the obvious username with a few obvious passwords before anything fancier. |
| 2 | WSTG-ATHN-03 | Lockout / rate limiting | Fail a login several times in a row. Does anything stop you? |
| 3 | WSTG-ATHN-07 | Password policy | What's the weakest password the registration form will accept? |
| 4 | WSTG-ATHN-04 | Forgot-password flow | Trigger it for a username you don't own. Is the token something you could predict without ever seeing it delivered? Also: is there a leftover debug page anywhere that might show you what a real reset "email" would have contained? |

---

## Phase 3 — Authorization / Access Control (WSTG-ATHZ)

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-ATHZ-01 | Horizontal privilege escalation | Log in as a normal customer. Find a URL with a numeric ID in it (profile, order). What happens if you change the number? |
| 2 | WSTG-ATHZ-04 | Vertical privilege escalation | You found an admin-shaped URL in Phase 1. Try reaching it while logged in as a plain customer — no admin account needed. |

---

## Phase 4 — Input Validation (WSTG-INPV)

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-INPV-05 | SQL Injection — login | Classic single-quote-breakout payloads on the login form. What happens to the query when your input contains a `'`? |
| 2 | WSTG-INPV-05 | SQL Injection — search | The search box hits the database too. If you can control what comes back, can you make it return rows from a *different* table? (Hint: column count matters for that technique.) |
| 3 | WSTG-INPV-01 | Reflected XSS | The search page echoes your query back onto the page. Try a payload that would prove JS execution, not just presence of text. |
| 4 | WSTG-INPV-02 | Stored XSS | Product reviews are stored and shown to every future visitor. What happens if a review contains a script tag? |

---

## Phase 5 — Business Logic & Advanced (WSTG-BUSL)

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-SESS-05 | CSRF | Find a state-changing form (account settings) with no visible token. Could you build an external HTML page that submits it on a logged-in victim's behalf? |
| 2 | WSTG-BUSL-09 | Insecure file upload | The avatar/profile-picture upload accepts more file types than you might expect. What happens if the file itself contains a script, and what content type does the server hand it back as? |
| 3 | (advanced) | Command injection | There's an admin "health check" tool that pings a host you supply. What happens if your input isn't just a hostname? *Only attempt this inside the provided Docker sandbox — see README.* |
| 4 | (advanced) | SSRF | There's an admin "fetch image by URL" tool. Where else, besides a real image host, might the server be willing to fetch from — including addresses that only make sense from the server's own point of view? *Docker sandbox only.* |

---

## Phase 6 — Reporting (WSTG methodology close-out)

For every finding you confirmed above, fill in one row of `REPORT_TEMPLATE.md`'s findings table:
title, a CVSS-based severity, the affected asset (route/parameter), clear PoC steps, evidence
(request/response, screenshot), business impact in plain language, and a remediation
recommendation. Write the executive summary *last*, after all findings are in — it should read
as if a non-technical stakeholder is your only audience.
