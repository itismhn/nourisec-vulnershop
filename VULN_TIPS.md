# Vulnerability Tips — quick nudges + how to trigger each one

A middle ground between `STUDENT_LAB.md` (hints only, no answers) and
`INSTRUCTOR_GUIDE.md` (full answer key with fixes). Use this if you're stuck on
*finding* a bug or *triggering* it, but still want to work out the payload and impact
yourself. The remediation for each one is only in `INSTRUCTOR_GUIDE.md`.

---

### 1. SQL Injection — Easy — WSTG-INPV-05
**Tip:** The login form and the search box both build a database query out of your
input directly, with no escaping.
**How to achieve:** On the login page, put `' OR '1'='1' --` in the username field
(any password) and submit. On the search box, try a single quote (`'`) first and
watch what breaks — then look at the products table's columns (5 of them) and try
pairing a `UNION SELECT` with the same column count against the `users` table.

### 2. Reflected XSS — Easy — WSTG-INPV-01
**Tip:** Whatever you search for gets echoed straight back onto the results page.
**How to achieve:** Search for `<script>alert(1)</script>` (via the search box or
directly in the URL as `?q=`) and see if it runs instead of just appearing as text.

### 3. Stored XSS — Medium — WSTG-INPV-02
**Tip:** Product reviews are saved as-is and shown to every future visitor.
**How to achieve:** Log in, open any product, and post a review containing
`<script>alert(document.cookie)</script>`. Reload the product page (or have someone
else view it) and watch it fire.

### 4. Broken Access Control / IDOR — Medium — WSTG-ATHZ-01/04
**Tip:** Several URLs have a plain number in them (`/profile/2`, `/orders/1`) and an
admin panel that's never linked from the site's navigation.
**How to achieve:** Log in as one customer, then just change the number in
`/profile/<id>` or `/orders/<id>` to someone else's. Separately, while logged in as
*any* account, try navigating straight to `/admin`.

### 5. Broken Authentication — Easy/Medium — WSTG-ATHN-02/03/04/07
**Tip:** Four separate weaknesses live in registration and login: no password rules,
no lockout, guessable admin creds, and a "forgot password" flow that leaks more than
it should.
**How to achieve:** Register with a 1-character password (works). Try a few obvious
admin/admin-style logins in a row (nothing stops you). Then trigger `/forgot-password`
for any username and check `/dev/last-reset` — a debug page that was never removed.

### 6. Security Misconfiguration — Easy — WSTG-CONF-01/02/03/06
**Tip:** Look for things that shouldn't be reachable from the outside at all: version
control metadata, old backups, directory listings, and raw error pages.
**How to achieve:** Visit `/.git/config`, `/backup/app_backup.sql`, and `/uploads/`
directly. Then visit `/product/abc` (a non-numeric ID) and see what the app tells you
about its own internals when it breaks.

### 7. CSRF — Medium — WSTG-SESS-05
**Tip:** The account-settings forms (`/account/change-email`, `/account/change-password`)
accept a plain POST from anywhere — no token, no "current password" check.
**How to achieve:** While logged in, open `app/static/csrf_poc_change_email.html` in a
new tab (same browser) — it's a self-submitting form that changes your email with no
interaction beyond loading the page.

### 8. Insecure File Upload — Medium/Hard — WSTG-BUSL-09
**Tip:** The avatar upload's allow-list is wider than it should be, and nothing checks
what's actually *inside* the file.
**How to achieve:** Upload an `.svg` file containing
`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>` as your
avatar, then open the uploaded file directly from `/uploads/<filename>` in a new tab.

### 9. Sensitive Data Exposure — Easy — WSTG-CRYP-04
**Tip:** Passwords aren't hashed the way you'd hope, and a "secret" key made it into
client-side code.
**How to achieve:** Get any password hash (e.g. via the search-box UNION trick in
tip #1, or `/backup/app_backup.sql`) and run it through a hash-cracking tool or an
online hash lookup. Separately, view the page source of `static/js/main.js`.

### 10. Command Injection — Hard (advanced) — admin "ping" tool
**Tip:** The admin health-check tool builds a shell command out of whatever host you
give it.
**How to achieve:** On `/admin/ping`, enter `127.0.0.1; whoami` (or `` `id` ``) instead
of a plain hostname and see what comes back beyond the ping output. Only try this
inside the provided Docker sandbox (see README) — outside Docker it runs on your real
machine.

### 11. SSRF — Hard (advanced) — admin "fetch image by URL"
**Tip:** The "fetch product image by URL" tool makes the *server* request whatever URL
you give it, with no restriction on where that URL points.
**How to achieve:** On `/admin/fetch-image`, enter an internal address instead of a
real image URL — e.g. `http://127.0.0.1:5000/dev/last-reset` — and check the file it
saves under `/uploads/`. Docker sandbox only, same reasoning as #10.

---

Still stuck after the tip? `INSTRUCTOR_GUIDE.md` has the exact file/route/parameter,
a full walkthrough, and the fix for every one of these.
