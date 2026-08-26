# Security Policy

## This app is *supposed* to be vulnerable

NouriSec VulnerShop is a deliberately vulnerable training application. The 11
vulnerabilities listed in the [README](README.md#whats-inside) and detailed in
[`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md) are intentional teaching material —
**please don't open an issue or a report for any of those**. Finding and exploiting
them is the point of the lab.

## What we do want reported

Report it if you find:

- A way to escape the intended sandbox (e.g. break out of the Docker container's
  network isolation, or reach something on the host beyond what the admin "ping" /
  "fetch image" tools are documented to do).
- A vulnerability that is **not** one of the 11 documented bugs and could affect
  someone running this project as instructed (locally, or via `docker compose up`).
- A supply-chain issue — a malicious or compromised dependency in
  `requirements.txt`.
- Anything in the setup/deployment scripts (`Dockerfile`, `docker-compose.yml`,
  `docker-entrypoint.sh`) that could cause harm beyond the documented, contained scope.

## How to report

Please use [GitHub's private security advisory form](../../security/advisories/new)
for this repository rather than a public issue. If you'd rather email, reach out to
**itismhn@yahoo.com** with a clear description and reproduction steps.

You'll get an acknowledgment within a few days. Since this is a training project run
by one person (not a funded security team), please be patient with turnaround time.

## Scope reminder

This project is for learning on your own, isolated machine — see the
[disclaimer](app/templates/disclaimer.html) and the README's
["a few things worth knowing"](README.md#a-few-things-worth-knowing) section. It is
not authorized for testing against anything other than your own local instance of it.
