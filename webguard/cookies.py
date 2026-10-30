"""Cookie attribute checks based on raw Set-Cookie header values."""
from typing import List

from .models import Finding

SESSION_HINTS = ("sess", "auth", "token", "jwt", "sid", "login")
REF = "OWASP WSTG-SESS-02"


def parse_set_cookie(raw: str):
    parts = [p.strip() for p in raw.split(";")]
    name, _, _ = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), attrs


def check_cookies(set_cookies: List[str], is_https: bool) -> List[Finding]:
    out = []
    for raw in set_cookies:
        name, a = parse_set_cookie(raw)
        if not name:
            continue
        sessionish = any(h in name.lower() for h in SESSION_HINTS)
        base = "medium" if sessionish else "low"

        if is_https and "secure" not in a:
            out.append(Finding(
                "cookie-secure", "Cookie '%s' lacks Secure" % name, base,
                "The cookie may be sent over plain HTTP, where it can be sniffed.",
                "Add the Secure attribute.", REF, name))
        if "httponly" not in a:
            out.append(Finding(
                "cookie-httponly", "Cookie '%s' lacks HttpOnly" % name, base,
                "JavaScript can read the cookie, so any XSS can steal it.",
                "Add the HttpOnly attribute.", REF, name))
        ss = a.get("samesite", "").lower()
        if not ss:
            out.append(Finding(
                "cookie-samesite", "Cookie '%s' lacks SameSite" % name, "low",
                "Without SameSite the cookie rides on cross-site requests, easing CSRF.",
                "Add SameSite=Lax (or Strict).", REF, name))
        elif ss == "none" and "secure" not in a:
            out.append(Finding(
                "cookie-samesite-none", "Cookie '%s' SameSite=None without Secure" % name, "medium",
                "Browsers reject this combination and it signals a misconfiguration.",
                "Add Secure or use SameSite=Lax.", REF, name))
        if name.startswith("__Host-") and not ("secure" in a and a.get("path") == "/" and "domain" not in a):
            out.append(Finding(
                "cookie-prefix", "Cookie '%s' violates __Host- rules" % name, "low",
                "__Host- requires Secure, Path=/ and no Domain attribute.",
                "Fix the attributes or drop the prefix.", REF, name))
    return out
