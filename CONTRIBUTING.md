# Contributing to NouriSec VulnerShop

Thanks for considering a contribution. This is a training lab first and an app second,
so contributions are judged on "does this make the lab better to learn from," not just
"does this work."

## Good contributions

- **New vulnerability classes** not already covered (e.g. XXE, deserialization, JWT
  attacks, GraphQL-specific bugs) — with the same three-layer treatment the existing
  bugs get: a hint in `STUDENT_LAB.md`, a nudge in `VULN_TIPS.md`, and a full writeup
  with fix in `INSTRUCTOR_GUIDE.md`.
- **Fixes to unintentional bugs** — anything that isn't one of the documented
  vulnerabilities (typos, broken links, a layout that breaks at some viewport width,
  a route that 500s in a way that isn't the point).
- **Translations** of the docs or storefront copy.
- **Better hints or clearer writeups** in the existing docs.

## Before you open a PR

1. Fork the repo and run it locally (`docker compose up --build`, or the local venv
   steps in `README.md`).
2. Confirm the bug you're touching still triggers the way the relevant doc describes,
   or update the doc to match.
3. Run through `scripts/reset_db.py` to make sure the seed data still loads cleanly.
4. If you're adding a new intentional vulnerability, add matching entries to all three
   docs (`STUDENT_LAB.md`, `VULN_TIPS.md`, `INSTRUCTOR_GUIDE.md`) — partial coverage
   makes the lab inconsistent.

## What NOT to send

- "Fixes" for the documented vulnerabilities themselves — breaking the bugs breaks the
  lab. If you want to demonstrate a fix, add it to `INSTRUCTOR_GUIDE.md` as a
  remediation note instead of patching the code.
- Anything that makes the app safe to expose on the internet. It's meant to run
  locally or in the provided Docker sandbox only — see the [disclaimer](app/templates/disclaimer.html).

## Reporting a bug vs. a vulnerability

If you found one of the *intended* vulnerabilities, you don't need to report it — it's
already documented. If you found something else — a way to break out of the sandbox,
or a bug that could affect someone running this outside their own machine — see
[`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## Style

- Python: match the existing code style (plain Flask, no framework magic). Keep the
  `# VULN: ...` comments on intentional bugs — they're part of the teaching material.
  keep diffs focused on the endpoints you're touching.
- Templates/CSS: match the existing Persian RTL storefront look and feel.
