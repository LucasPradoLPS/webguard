"""Checks on HTTP response headers. Each check is a function: (ctx) -> list[Finding]."""
import re
from typing import Callable, List, Mapping

from .models import Finding

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


class Ctx:
    """Normalised view of a response: lowercase header names, scheme."""

    def __init__(self, headers: Mapping[str, str], is_https: bool):
        self.h = {k.lower(): v for k, v in headers.items()}
        self.is_https = is_https


def check_https(c: Ctx) -> List[Finding]:
    if c.is_https:
        return []
    return [Finding(
        "transport-http", "Site served over plain HTTP", "high",
        "Traffic can be read or modified by anyone on the path (sniffing, session hijack, content injection).",
        "Serve the site over HTTPS and redirect all HTTP traffic to it.",
        "OWASP WSTG-CRYP-03")]


def check_hsts(c: Ctx) -> List[Finding]:
    if not c.is_https:
        return []
    v = c.h.get("strict-transport-security")
    if v is None:
        return [Finding(
            "hsts-missing", "Strict-Transport-Security missing", "medium",
            "Without HSTS a user can be downgraded to HTTP by a man-in-the-middle (SSL stripping).",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            OWASP_HEADERS)]
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < 15552000:  # 180 days
        return [Finding(
            "hsts-weak", "HSTS max-age too short", "low",
            "A short max-age lets the protection expire between visits, reopening the downgrade window.",
            "Use max-age of at least 31536000 (1 year).", OWASP_HEADERS, v)]
    return []


def check_csp(c: Ctx) -> List[Finding]:
    v = c.h.get("content-security-policy")
    if v is None:
        return [Finding(
            "csp-missing", "Content-Security-Policy missing", "medium",
            "CSP is the main defence-in-depth against XSS: it limits which scripts the browser will run.",
            "Define a restrictive policy, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
            "OWASP WSTG-CONF-12")]
    out = []
    for token in ("'unsafe-inline'", "'unsafe-eval'"):
        if token in v:
            out.append(Finding(
                "csp-" + token.strip("'"), "CSP allows " + token, "medium",
                "%s lets injected inline/eval code execute, defeating the XSS protection CSP provides." % token,
                "Remove %s; use nonces or hashes for scripts." % token,
                "OWASP WSTG-CONF-12", v))
    if re.search(r"(script-src|default-src)[^;]*\s\*(\s|;|$)", v):
        out.append(Finding(
            "csp-wildcard", "CSP script source wildcard", "medium",
            "A '*' source allows scripts from any origin, so an attacker can load their own.",
            "List explicit trusted origins instead of '*'.", "OWASP WSTG-CONF-12", v))
    return out


def check_clickjacking(c: Ctx) -> List[Finding]:
    csp = c.h.get("content-security-policy", "")
    if "frame-ancestors" in csp or "x-frame-options" in c.h:
        return []
    return [Finding(
        "clickjacking", "No clickjacking protection", "medium",
        "The page can be framed by another site, which overlays invisible UI to trick users into clicks.",
        "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors'.", "OWASP WSTG-CLNT-09")]


def check_nosniff(c: Ctx) -> List[Finding]:
    if c.h.get("x-content-type-options", "").lower() == "nosniff":
        return []
    return [Finding(
        "nosniff", "X-Content-Type-Options missing", "low",
        "Browsers may MIME-sniff responses and execute uploaded content as script.",
        "Send 'X-Content-Type-Options: nosniff'.", OWASP_HEADERS)]


def check_referrer(c: Ctx) -> List[Finding]:
    if "referrer-policy" in c.h:
        return []
    return [Finding(
        "referrer-policy", "Referrer-Policy missing", "low",
        "Full URLs (possibly with tokens or IDs) may leak to third parties via the Referer header.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.", OWASP_HEADERS)]


def check_permissions(c: Ctx) -> List[Finding]:
    if "permissions-policy" in c.h or "feature-policy" in c.h:
        return []
    return [Finding(
        "permissions-policy", "Permissions-Policy missing", "info",
        "Powerful browser features (camera, geolocation...) are not explicitly restricted.",
        "Send a Permissions-Policy that disables unused features.", OWASP_HEADERS)]


def check_disclosure(c: Ctx) -> List[Finding]:
    out = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = c.h.get(name)
        if v and re.search(r"\d", v):
            out.append(Finding(
                "disclosure-" + name, "Version disclosed in %s header" % name, "low",
                "Exact software versions let an attacker match the target against known CVEs.",
                "Suppress or genericise the header in the server/framework config.",
                "OWASP WSTG-INFO-02", "%s: %s" % (name, v)))
    return out


def check_cors(c: Ctx) -> List[Finding]:
    origin = c.h.get("access-control-allow-origin")
    creds = c.h.get("access-control-allow-credentials", "").lower() == "true"
    if origin == "*" and creds:
        return [Finding(
            "cors-wildcard-creds", "CORS wildcard origin with credentials", "high",
            "Any site may read authenticated responses, enabling cross-origin data theft.",
            "Reflect only an allow-list of trusted origins; never combine '*' with credentials.",
            "OWASP WSTG-CLNT-07", "ACAO: *, ACAC: true")]
    if origin == "*":
        return [Finding(
            "cors-wildcard", "CORS allows any origin", "info",
            "Acceptable for public data, but dangerous if the endpoint ever returns user-specific content.",
            "Restrict to known origins if the API is not fully public.", "OWASP WSTG-CLNT-07", "ACAO: *")]
    return []


HEADER_CHECKS: List[Callable[[Ctx], List[Finding]]] = [
    check_https, check_hsts, check_csp, check_clickjacking, check_nosniff,
    check_referrer, check_permissions, check_disclosure, check_cors,
]
