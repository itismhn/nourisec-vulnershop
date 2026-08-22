# Penetration Test Report — NouriSec VulnerShop

**Prepared by:** _[your name]_
**Date:** _[date]_
**Classification:** Confidential — for training use only

---

## 1. Executive Summary

_Write this section last, after every finding below is finalized. Summarize, for a
non-technical stakeholder, what was tested, the overall risk posture, the most critical
findings, and the recommended next steps. 3–6 sentences is usually enough._

> Example opening line: "This assessment identified N vulnerabilities in the VulnerShop
> application, including M critical/high-severity issues that could allow an attacker to
> [impact in plain language]. Immediate remediation is recommended for..."

---

## 2. Scope

| Item | Detail |
|---|---|
| Target | NouriSec VulnerShop (training instance) — `http://<host>:5000` |
| In scope | The VulnerShop web application only, running in the isolated lab environment described in the project README |
| Out of scope | Any other host, service, or third party; denial-of-service testing; social engineering |
| Testing window | _[start date]_ – _[end date]_ |
| Authorization | This is a self-hosted, purpose-built training application — authorization is inherent to the lab, not a real client engagement |

---

## 3. Methodology

_Describe the approach you followed. A typical answer for this lab:_

- Followed the OWASP Web Security Testing Guide (WSTG) methodology, staged as:
  information gathering → authentication testing → authorization testing → input validation →
  business logic testing → reporting.
- Manual testing supplemented with tooling: _[list what you actually used, e.g. Burp Suite,
  ffuf/gobuster, curl, browser devtools]_.
- Findings were verified individually with a reproducible proof-of-concept before being recorded
  below (no automated-scanner output was reported without manual confirmation).

---

## 4. Findings Summary

| # | Title | Severity | CVSS v3.1 | Affected Asset |
|---|---|---|---|---|
| 1 | _e.g. SQL Injection in login form_ | Critical | _9.x_ | `POST /login` (`username`) |
| 2 | | | | |
| 3 | | | | |
| ... | | | | |

_Severity scale: Critical (9.0–10.0) / High (7.0–8.9) / Medium (4.0–6.9) / Low (0.1–3.9) /
Informational. Use the [FIRST CVSS calculator](https://www.first.org/cvss/calculator/3.1) to
derive a score, and include the vector string in each finding's detail section._

---

## 5. Detailed Findings

Copy this block once per finding.

### Finding N: _[Title]_

- **Severity:** _Critical / High / Medium / Low / Informational_
- **CVSS v3.1 Score / Vector:** _[score]_ — `[vector string]`
- **Affected Asset:** _[route, parameter, page]_
- **WSTG Reference:** _[e.g. WSTG-INPV-05]_

**Description**
_What is the vulnerability, in your own words? What's the root cause (not just "SQL injection"
— explain what in the code/request handling allows it)?_

**Proof of Concept**
_Step-by-step reproduction. Include exact requests (method, URL, headers, body) and exact
payloads used._

```
[request/response, curl command, or numbered steps]
```

**Evidence**
_Screenshot, response snippet, or terminal output demonstrating the issue._

**Impact**
_What could a real attacker actually do with this? Be concrete: data exposed, accounts
compromised, actions performed — not just "this is bad."_

**Remediation**
_Specific, actionable fix. Reference secure coding patterns, not just "sanitize input."_

---

_(Repeat the block above for each finding in the summary table.)_

---

## 6. Conclusion

_Wrap up: overall security posture in one paragraph, the highest-priority fixes to do first, and
any chained/combined risks worth calling out (e.g. a low-severity information leak that, combined
with a weak-crypto finding, enables a much higher-impact attack path)._

---

## Appendix: Tools Used

_[List tools/versions, e.g. Burp Suite Community 2024.x, ffuf 2.x, sqlmap 1.x, browser + devtools]_
