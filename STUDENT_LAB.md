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

Covers every test in OWASP WSTG v4.2 §4.4. Work through it on the default build, then repeat the
whole table against the hardened build (see "Retest" below) and note what changed.

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-ATHN-01 | Credentials over an encrypted channel | Watch the login request in your proxy. Is it sent by POST? Does the site push you to HTTPS, and what do the `Set-Cookie` flags and response headers say? (Plain HTTP is expected on localhost — the question is what the app *does* about it.) |
| 2 | WSTG-ATHN-02 | Default credentials | Every store has an admin. Try the obvious username with a few obvious passwords before anything fancier. Also look for accounts nobody remembered to remove. |
| 3 | WSTG-ATHN-03 | Lockout / rate limiting | Fail a login several times in a row. Does anything stop you? If something does: does it also apply to usernames that don't exist, and does it ever unlock? |
| 4 | WSTG-ATHN-04 | Bypassing the authentication schema | Three angles: break the login query, open "logged-in only" pages directly without logging in, and tamper with what the server trusts after login (cookie contents, your role). |
| 5 | WSTG-ATHN-04 | Session handling after login/logout | Copy your session cookie, log out, then replay it. Compare the cookie before and after logging in. Does an idle session ever expire? |
| 6 | WSTG-ATHN-05 | Remember-password behaviour | Does the app store credentials in cookies or local storage? What do the form fields tell the browser about autofill? |
| 7 | WSTG-ATHN-06 | Browser cache | Log in, visit your profile, log out, press Back. What shows? Check the cache-related response headers on authenticated pages. |
| 8 | WSTG-ATHN-07 | Password policy | What's the weakest password the registration form will accept? Try short ones, common ones, your own username, and one reused from a previous change. |
| 9 | WSTG-ATHN-08 | Security questions | Does recovery rely on guessable personal answers anywhere? (Note it as "not applicable" in your report if there isn't any.) |
| 10 | WSTG-ATHN-09 | Forgot-password flow | Trigger it for a username you don't own. Is the token something you could predict without ever seeing it delivered? Does it expire, work twice, or survive a newer request? Do known and unknown users get identical answers? Also: is there a leftover debug page anywhere that might show you what a real reset "email" would have contained? |
| 11 | WSTG-ATHN-09 | Changing password / email | What does the account page ask for before changing a password or email? Could another website trigger it for a logged-in victim? After a change, are your *other* sessions still alive? |
| 12 | WSTG-ATHN-10 | Weaker authentication in alternative channels | The admin area is a different door to the same house. Does it hold its users to the same standard as the public login? Compare what a plain customer can reach. |

**Retest against the hardened build.** Start the app with `VULNERSHOP_AUTH_MODE=secure` and
re-run `python scripts/reset_db.py` (the default accounts no longer exist; the seed script
prints the new ones). Repeat tasks 1–12 and record, per task, *vulnerable → hardened*. For each
control you can't break, write one sentence on how you'd verify it in a real engagement. The
list of controls is in [`AUTH_HARDENING.md`](AUTH_HARDENING.md) — read it **after** your retest.

---

## Phase 3 — Authorization / Access Control (WSTG-ATHZ)

Authentication asked "who are you?"; this phase asks "what are you allowed to do?". It covers
every test in OWASP WSTG v4.2 §4.5. Work it on the default build, then repeat the whole table on
the hardened build (see "Retest" below) and note what changed.

### Help: how to work this phase

**1. Set up your test identities.** Authorization bugs only show up when you compare who can do
what, so you need at least three "people":

| Identity | How | Use it for |
|----------|-----|-----------|
| Customer A | register a new account, then buy something (add to cart → checkout) | the "attacker" |
| Customer B | a second account in a *private/incognito window* (separate cookies), also buys something | the "victim" — owns data A shouldn't see |
| Anonymous | a window with no login | what is reachable with no session at all |

Keep a note of each account's ID and order ID — the numbers in the URLs are your raw material.
A proxy (Burp, ZAP) makes it easy to replay one identity's request with another identity's cookie.

**2. Use the compare-and-replay loop.** For every interesting request:

1. Make it as the owner and note the response (status code, size, what is shown).
2. Replay it as another customer, then as anonymous.
3. Change one thing at a time — an ID, a URL path, the HTTP method, a form field, a cookie value.
4. Compare. Same data for the wrong person = finding. A refusal = note *how* it refused.

**3. Read the status codes.** `200` with someone else's data is a bug. `302` to `/login` means
"not authenticated" (not the same as "not authorized"). `403` means the server knows who you are
and said no. `404` can mean "doesn't exist" *or* "pretending it doesn't exist"; if a made-up ID
and someone else's ID give different answers, that difference leaks information.

**4. Per-test nudges** (no spoilers, just where to point your tools):

- **ATHZ-04** — look for IDs in the URL *and* in forms. Walk the ID up and down; check both what
  you can *read* and what you can *change*.
- **ATHZ-02** — you can't see a menu link to the admin area, so don't rely on the UI: guess the
  URL, then test every verb (`GET`, `POST`, `HEAD`) and every action page, not just the front page.
- **ATHZ-03** — privilege is whatever the server believes about you. Find every place that
  belief could come from: form fields, the cookie, a hidden parameter. Add a field the form
  never asked for and see whether it sticks.
- **ATHZ-01** — try `../`, `..%2f` and `%252e%252e%252f` against the paths that serve files by
  name. A blocked traversal is a valid result; then ask what the *intended* path already gives
  away (listings, leftover files, filenames you control).

**5. What to record for each test** (this feeds `REPORT_TEMPLATE.md`): the URL and method, which
identity you used, the exact request you changed, the response that proves it, and what an
attacker would gain. For tests you could *not* break, write "attempted X, got Y" — that is
evidence too.

**6. Stuck?** [`VULN_TIPS.md`](VULN_TIPS.md) has a concrete nudge in its section 4
("Broken Access Control / IDOR"). Don't open `INSTRUCTOR_GUIDE.md` — it is the answer key.

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-ATHZ-04 | Insecure direct object references (horizontal escalation) | Log in as a normal customer. Find a URL with a numeric ID in it (profile, order). What happens if you change the number? Does a made-up number behave differently from someone else's? |
| 2 | WSTG-ATHZ-02 | Bypass the authorization schema (vertical escalation) | You found an admin-shaped URL in Phase 1. Try reaching it while logged in as a plain customer — no admin account needed. Then try the admin *actions* (POST forms), not just the pages, and other HTTP methods. |
| 3 | WSTG-ATHZ-03 | Privilege escalation | Can you become an admin without knowing the admin password? Look at what you send when you register or edit your profile, and at what the session cookie contains and how it is protected. |
| 4 | WSTG-ATHZ-01 | Directory traversal / file include | Some paths hand back files by name (`/backup/…`, `/uploads/…`) and the avatar upload takes a filename from you. Can you get out of the intended folder with `../` (plain, URL-encoded, double-encoded)? If not, what can you still reach *by name* that you shouldn't? |

**Retest in secure mode.** Once you have logged your findings, restart with
`VULNERSHOP_AUTH_MODE=secure` (see [`AUTH_HARDENING.md`](AUTH_HARDENING.md)), reseed, and repeat
all four tests. Each should now be refused; compare the status codes with what you saw before and
note them in your report as the "after" evidence.

---

## Phase 4 — Input Validation (WSTG-INPV)

Authorization asked "what are you allowed to do?"; this phase asks "what happens when the input
is not what the developer expected?". It covers every test in OWASP WSTG v4.2 §4.7 (INPV-01 to
INPV-19). Work it on the default build, then repeat on the hardened build (see "Retest" below).

Not every test has a bug behind it, and that is the point. A real engagement tests the whole list
and reports *"attempted X, got Y"* for the ones that hold. Rows marked **probe** have no vulnerable
code behind them in this app: send the payloads, prove the output is inert, and write that down as
evidence rather than skipping the row.

### Help: how to work this phase

**1. Build your target list first.** From Phase 1 you have every page, form, query parameter,
cookie and header. List each *input* once (search `q`, login `username`/`password`, review `body` /
`rating`, contact `name`/`email`/`message`, cart `qty`, admin `host` and `url`, the `Host` header,
URL path segments, the `lang` cookie, uploaded file names) and tick it off against every test below.

**2. Use the probe → observe → escalate loop.** For each input:

1. Send a harmless **marker** (`zq7x1`) and find everywhere it comes back: same page, another page,
   an error, a header, the page `<title>`, a JS string, an attribute.
2. Note the **context** it lands in (HTML body, attribute, script, SQL, shell, URL). The context
   decides which characters matter.
3. Send the characters that matter for that context (`' " < > ; | $ { } % \r\n`) one at a time and
   compare response status, size, timing and content with the marker response.
4. Only when something changes, build a payload that *proves* impact (JS execution, extra rows,
   a command's output) — and stop there. Proof, not damage.

**3. Per-test nudges** (where to point your tools, no spoilers):

- **INPV-01/02** — check *every* place text is echoed, including the page title and error text,
  not just the obvious one. For stored input ask "who else will see this, and when?".
- **INPV-04** — send the same parameter twice (`?q=a&q=b`, or a form field repeated in the proxy)
  and note which value the server uses. A bug needs the *check* and the *use* to disagree, so also
  look at what the cart does with quantities at all.
- **INPV-05** — a single quote tells you whether the input reaches a query. Count columns before
  you try to pull rows from another table.
- **INPV-10/15** — carriage-return/line-feed (`%0d%0a`) is the character that matters. Where does
  your input end up in a mail header, a response header or a log line?
- **INPV-12/19** — these tools are admin-only, but remember Phase 3: do you need to be an admin?
  Docker sandbox only (see README).

**4. Record per test**: input, endpoint/method, the payload you sent, the response that proves the
result, and the context. Rows you could not break still get an entry ("attempted `{{7*7}}` in 6
inputs, rendered literally"). This feeds `REPORT_TEMPLATE.md`.

**5. Stuck?** [`VULN_TIPS.md`](VULN_TIPS.md) has tips for SQLi (#1), XSS (#2, #3), command
injection (#10), SSRF (#11) and the probes. `INSTRUCTOR_GUIDE.md` is the answer key — don't open it yet.

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-INPV-01 | Reflected XSS | The search page echoes your query back. Try a payload that proves JS execution, not just presence of text. Then check the other places the same text is reflected (title, error box). |
| 2 | WSTG-INPV-02 | Stored XSS | Product reviews are stored and shown to every future visitor. What happens if a review contains a script tag? Which other inputs are stored — and which are ever displayed back? |
| 3 | WSTG-INPV-03 | HTTP verb tampering | For every admin and state-changing URL, try `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `PATCH` and a made-up verb. Read the `Allow` header. Does any verb skip a check the normal one enforces? (Phase 1 task 10 found the verbs; here you test the *access control* on them.) |
| 4 | WSTG-INPV-04 | HTTP parameter pollution | Send a parameter twice, in the query string and in a POST body (`qty`, `q`, `category`). Which value wins? Then ask what the server checks about a quantity before it goes in the cart — try a negative one and look at the cart total. |
| 5 | WSTG-INPV-05 | SQL Injection — login | Classic single-quote-breakout payloads on the login form. What happens to the query when your input contains a `'`? Try the password field too, and compare the error vs. a plain wrong password. |
| 6 | WSTG-INPV-05 | SQL Injection — search | The search box hits the database too. If you can control what comes back, can you make it return rows from a *different* table? (Hint: column count matters for that technique.) Also: what does the page tell you when the query breaks? |
| 7 | WSTG-INPV-06 | LDAP injection — **probe** | There is no directory service. Send LDAP filter metacharacters (`*`, `(`, `)`, `&`, `|`) into the login and search fields and confirm they only ever behave as ordinary text. |
| 8 | WSTG-INPV-07 | XML injection / XXE — **probe** | Nothing parses XML. Submit a small XML document with an entity declaration in a text field, then re-send a form with `Content-Type: application/xml`. Is it parsed, stored, or refused? |
| 9 | WSTG-INPV-08 | SSI injection — **probe** | Put a server-side-include directive in a review and a search term. Does any page execute it or just show it? What does that tell you about the stack? |
| 10 | WSTG-INPV-09 | XPath injection — **probe** | There is no XML data store. Send quote and boolean XPath fragments to the login and search inputs and confirm they match the SQL behaviour (or nothing) rather than a different query language. |
| 11 | WSTG-INPV-10 | IMAP/SMTP injection | The contact form takes a name and an e-mail address. Put a line break in each. Does anything build a mail header from them? Check what the app stores and which responses/logs echo them. |
| 12 | WSTG-INPV-11 | Code injection / local & remote file inclusion | Look for parameters that choose a file, template or page by name (`page=`, `file=`, `lang`, path segments) and for places where the server evaluates what you send. Combine with what you found in Phase 3 (ATHZ-01). A well-documented "no" is a valid result. |
| 13 | WSTG-INPV-12 | Command injection | There's an admin "health check" tool that pings a host you supply. What happens if your input isn't just a hostname? *Only inside the provided Docker sandbox — see README.* (Also listed under Phase 5's advanced tasks; do it once and reuse the evidence.) |
| 14 | WSTG-INPV-13 | Format string injection — **probe** | Send `%s%s%n`, `%x`, `{0}` and `{{}}` style strings to every text input. Look for crashes, odd output, or values from the server appearing. |
| 15 | WSTG-INPV-14 | Incubated vulnerabilities | Plant a marker payload in every stored input (review, contact message, avatar file name/content, admin product fields). Then log in as *other* roles — customer, anonymous, admin — and look for where and when it fires. Who is the victim in each case? |
| 16 | WSTG-INPV-15 | HTTP splitting / smuggling | Put `%0d%0a` in values that end up in response headers or redirects (`/set-language/<lang>`, search, product path) and look for injected headers or cookies. Smuggling needs a front-end proxy in front of the app; with only the dev server, document why it is not testable. |
| 17 | WSTG-INPV-16 | Testing HTTP incoming requests | Proxy a full browsing session. List every request the page makes on its own (JS, images, fonts, background calls), including headers and cookies you did not set. Replay a few with modified headers (`Referer`, `X-Forwarded-For`, `User-Agent`). |
| 18 | WSTG-INPV-17 | Host header injection | Request the forgot-password page with a different `Host` (and `X-Forwarded-Host`) header and trigger a reset for a user you control. Where is the reset link built from? Is there a leftover page that shows it? |
| 19 | WSTG-INPV-18 | Server-side template injection — **probe** | Send template syntax (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) to every input *and* into URL paths (including a made-up page that 404s). Does `49` ever appear instead of the characters you sent? |
| 20 | WSTG-INPV-19 | Server-side request forgery | There's an admin "fetch image by URL" tool. Where else, besides a real image host, might the server be willing to fetch from — including addresses that only make sense from the server's own point of view? *Docker sandbox only.* (Also listed under Phase 5's advanced tasks.) |

Also run **WSTG-ERRH-01** here: feed malformed values (`abc`, `-1`, a huge number, a unicode digit)
to every numeric parameter (`/product/<id>`, `qty`, `rating`) and note which ones produce a stack
trace and what it reveals.

**Retest in secure mode.** Restart with `VULNERSHOP_AUTH_MODE=secure` (see
[`AUTH_HARDENING.md`](AUTH_HARDENING.md#input-validation-coverage-wstg-v42-47)), reseed, and repeat
all 20 rows plus the ERRH check. Record per row *vulnerable → hardened* with the status codes. For
each control you cannot break, write one sentence on how you would verify it in a real engagement
(e.g. "search term is HTML-encoded in the response; confirmed with `<script>` and an attribute
breakout"). Read the controls list **after** your retest.

---

## Phase 5 — Business Logic & Advanced (WSTG-BUSL)

Business-logic bugs are different from the injection bugs in Phase 4: every request is *valid*,
the app just never asked "should this person be able to do this, now, this many times, in this
order?". A scanner will not find them — you have to understand what the shop is *supposed* to
do, then do something it did not expect. All nine WSTG-4.10 tests have something to find here.

**1. Learn the intended flow first.** Buy something normally and write down each step and what
state the order is in after it: product page → cart → (discount code) → checkout → payment →
order page (pay / cancel / refund). Then ask of every step: what does it assume about the step
before it? About the numbers the browser sends? About how often and how fast it is called?

**2. Use a proxy and two accounts.** Intercept each request in Burp/ZAP. Keep two customers
(for limits and ownership) and one anonymous window. Use the "test cards" shown on the payment
page — never a real card.

**3. Per-test nudges** (where to point your tools, not what to type):

- **BUSL-01** — every number and text field is a candidate: quantity, rating, price, message.
  Try zero, negative, huge, fractional, empty, non-numeric and very long values, then look at
  what the *order total* and the *product rating* become.
- **BUSL-02** — find a request the browser makes that the user was never meant to make by
  hand (look at where the payment page sends you afterwards). Who is allowed to call it?
- **BUSL-03** — price and totals should come from the server. Look at the checkout form's
  hidden fields, and at what the session cookie holds and how it is signed.
- **BUSL-04** — time matters twice: *racing* (two requests at once) and *expiry* (something
  that should not last forever). The smartwatch has almost sold out — send two checkouts at
  the same moment (Burp "send group in parallel", or two scripts).
- **BUSL-05** — find anything with a limit written on it ("once per customer", "limit 2",
  "7-day refund") and push past it by repeating the call, in a different order, or in parallel.
- **BUSL-06** — try each step out of order, skip one, or repeat one: pay without checkout,
  refund something unpaid, pay something cancelled, review something you never bought.
- **BUSL-07** — does the app notice abuse? Fire the same failing request 20 times (a wrong
  discount code, a declined card, the contact form). Note the status codes and whether anything
  ever slows you down or gets logged.
- **BUSL-08 / 09** — the avatar upload. Try a file whose *name* says one thing and whose
  *content* says another; then files whose content is actively hostile. What does the server
  call it when it hands it back, and what would a browser do with it?

| # | WSTG ID | Task | Hint |
|---|---------|------|------|
| 1 | WSTG-BUSL-01 | Business-logic data validation | Put an unexpected quantity in the cart and complete checkout. Then post a review with a rating the form does not offer. What does the shop now think the order total / product average is? |
| 2 | WSTG-BUSL-02 | Ability to forge requests | After a successful payment the browser is sent somewhere with a result in the URL. Could someone who never paid send that request themselves — and would they even need to be logged in? |
| 3 | WSTG-BUSL-03 | Integrity checks | Inspect the checkout form in dev tools. Is there a value there the server should never have trusted? Change it and place the order. |
| 4 | WSTG-BUSL-04 | Process timing | The smartwatch has 3 left. Can two customers both get 2? Separately: what happens to an unpaid order left for a month? |
| 5 | WSTG-BUSL-05 | Number of times a function can be used | The welcome code is "once per customer" and the saffron says "limit 2". Apply the code repeatedly, even after it is spent. Request a refund more than once. How many reviews can one customer leave? |
| 6 | WSTG-BUSL-06 | Circumvention of work flows | Reach "paid" without paying. Refund an order that was never paid, or one from last year. Pay for an order you already cancelled. Review a product you never bought. |
| 7 | WSTG-BUSL-07 | Defenses against application misuse | Brute-force discount codes, "test" stolen cards against the payment form, and flood the contact form. Is there any lockout, throttle or alert? What would an attacker gain from each? |
| 8 | WSTG-BUSL-08 | Upload of unexpected file types | The avatar upload takes pictures. What else will it take if you only change the file name? Does it care what the file contains, or how big it is? |
| 9 | WSTG-BUSL-09 | Upload of malicious files | What happens if the file is an SVG carrying a script, a picture with script hidden after the image header, or the EICAR antivirus test string — and what content type does the server hand it back as? |
| 10 | WSTG-SESS-05 | CSRF | Find a state-changing form (account settings) with no visible token. Could you build an external HTML page that submits it on a logged-in victim's behalf? |
| 11 | WSTG-INPV-12 | Command injection (advanced) | There's an admin "health check" tool that pings a host you supply. What happens if your input isn't just a hostname? *Only attempt this inside the provided Docker sandbox — see README.* |
| 12 | WSTG-INPV-19 | SSRF (advanced) | There's an admin "fetch image by URL" tool. Where else, besides a real image host, might the server be willing to fetch from — including addresses that only make sense from the server's own point of view? *Docker sandbox only.* |

**Record for each test:** the exact request you changed, the state of the order/cart/account
*before and after*, and the business impact in money or trust terms ("a customer can buy a
3,000,000-toman watch for 1 toman"), not just "parameter is unvalidated". Rate impact by what an
attacker repeats at scale.

**Retest in secure mode.** Restart with `VULNERSHOP_AUTH_MODE=secure`, reseed
(`python scripts/reset_db.py`), and repeat tests 1–9. Each should be refused (a `4xx`, a
flash message, or an unchanged order/stock/credit total); note the response next to your
"before" evidence. The controls are listed in [`AUTH_HARDENING.md`](AUTH_HARDENING.md#business-logic-coverage-wstg-v42-410).
Tests 10–12 are checked in secure mode too (CSRF token, no shell for `ping`, public-address allow-list for the image fetcher) — see the Phase 4 notes in the README.

---

## Phase 6 — Reporting (WSTG methodology close-out)

For every finding you confirmed above, fill in one row of `REPORT_TEMPLATE.md`'s findings table:
title, a CVSS-based severity, the affected asset (route/parameter), clear PoC steps, evidence
(request/response, screenshot), business impact in plain language, and a remediation
recommendation. Write the executive summary *last*, after all findings are in — it should read
as if a non-technical stakeholder is your only audience.
