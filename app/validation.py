"""Hardened input handling ("secure" mode) for OWASP WSTG v4.2 section 4.7 (Input Validation).

Only called when VULNERSHOP_AUTH_MODE=secure; the default build keeps its intentional flaws.
The principle throughout: validate against an allow-list (type, range, length, charset) on the
server, and use parameterised APIs / output encoding instead of trying to filter "bad" input.
"""
import ipaddress
import re
import socket
from urllib.parse import urlsplit

from flask import request

QTY_MAX = 10                 # units of one product per cart line
SEARCH_MAX_LEN = 100
REVIEW_MAX_LEN = 1000
CONTACT_NAME_MAX = 100
CONTACT_MESSAGE_MAX = 2000
PRODUCT_NAME_MAX = 120
PRODUCT_DESC_MAX = 1000
PRODUCT_PRICE_MAX = 10_000_000_000
FETCH_MAX_BYTES = 2 * 1024 * 1024

# Hostname or IPv4 literal: starts with a letter/digit, so it can never be read as an option flag.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")  # CR/LF/NUL and friends (tab allowed)
_DIGITS_RE = re.compile(r"[0-9]{1,9}")

# Content types the image fetcher accepts, and the extension each is stored under.
IMAGE_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp"}


def form_int(name, lo, hi):
    """The single integer in form field `name`, or None.

    A repeated field (HTTP parameter pollution, WSTG-INPV-04), a sign, whitespace tricks,
    non-ASCII digits or an out-of-range value are all rejected rather than "fixed up".
    """
    values = request.form.getlist(name)
    if len(values) != 1 or not _DIGITS_RE.fullmatch(values[0]):
        return None
    number = int(values[0])
    return number if lo <= number <= hi else None


def has_control_chars(value):
    """True if `value` carries CR/LF/NUL (header / log / mail injection, WSTG-INPV-10/15)."""
    return bool(_CONTROL_RE.search(value))


def like_pattern(term):
    """`%term%` with LIKE wildcards in the user's input escaped (use with ESCAPE '\\')."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def is_public_http_url(url):
    """Allow-list check for server-side fetches (SSRF, WSTG-INPV-19).

    Only http(s) with a host that resolves exclusively to public addresses. Loopback, RFC 1918,
    link-local (cloud metadata), reserved and IPv4-mapped IPv6 forms all fail `is_global`, and
    decimal/octal/hex IP spellings are caught because the check runs on the resolved address.
    Known gap: resolving here and connecting later leaves a DNS-rebinding window; pin the
    resolved IP when connecting in a real deployment.
    """
    try:
        parts = urlsplit(url.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not host or parts.username or parts.password:
        return False
    try:
        infos = socket.getaddrinfo(host, port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return False
    return bool(infos)
