## What does this PR do?

<!-- New vulnerability, doc fix, unintentional-bug fix, translation, etc. -->

## Checklist

- [ ] I ran the app locally and confirmed my change works (`docker compose up --build`
      or the local venv steps in `README.md`).
- [ ] `python scripts/reset_db.py` still seeds cleanly after my change.
- [ ] If this adds a new intentional vulnerability, I updated all three docs:
      `STUDENT_LAB.md`, `VULN_TIPS.md`, and `INSTRUCTOR_GUIDE.md`.
- [ ] This does **not** patch or remove any of the existing documented vulnerabilities.
- [ ] This does not make the app safer to expose outside a local/sandboxed environment.

## Related issue

<!-- Closes #... if applicable -->
