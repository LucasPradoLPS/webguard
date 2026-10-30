"""Orchestrates one scan: a single GET plus (for HTTPS) one TLS handshake."""
import random
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from typing import Optional
from urllib.parse import urlsplit

from . import __version__
from .cookies import check_cookies
from .headers import HEADER_CHECKS, Ctx
from .models import ScanResult
from .tls import check_tls

HONEST_UA = "WebGuard/%s (+authorized-security-scan)" % __version__
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


@dataclass
class Options:
    timeout: float = 10.0
    insecure: bool = False       # accept self-signed certificates (labs)
    user_agent: str = HONEST_UA
    delay: float = 0.0           # seconds between requests
    jitter: float = 0.0          # extra random 0..jitter seconds on top of delay
    no_tls: bool = False


class Pacer:
    """Spaces out network touches so request rate is a conscious choice."""

    def __init__(self, delay: float, jitter: float):
        self.delay, self.jitter, self._first = delay, jitter, True

    def wait(self):
        if not self._first and (self.delay or self.jitter):
            time.sleep(self.delay + random.uniform(0, self.jitter))
        self._first = False


def normalise(target: str) -> str:
    return target if "://" in target else "https://" + target


def fetch(url: str, opts: Options):
    ctx = ssl.create_default_context()
    if opts.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": opts.user_agent, "Accept": "*/*"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        r = opener.open(req, timeout=opts.timeout)
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry useful headers
        r = e
    try:
        r.read(65536)  # drain a little; we never need the body
    except OSError:
        pass
    finally:
        r.close()
    return r.geturl(), r.code, r.headers


def scan(target: str, opts: Optional[Options] = None, pacer: Optional[Pacer] = None) -> ScanResult:
    opts = opts or Options()
    pacer = pacer or Pacer(opts.delay, opts.jitter)
    url = normalise(target)
    res = ScanResult(target=target)
    start = time.time()
    try:
        pacer.wait()
        try:
            final_url, status, headers = fetch(url, opts)
        except urllib.error.URLError as e:
            if not isinstance(e.reason, ssl.SSLCertVerificationError):
                raise
            # Invalid cert: still inspect headers; the TLS check reports the cert problem.
            final_url, status, headers = fetch(url, replace(opts, insecure=True))
            res.requests_made += 1
        res.requests_made += 1
        res.final_url, res.status = final_url, status
        parts = urlsplit(final_url)
        is_https = parts.scheme == "https"

        ctx = Ctx(dict(headers.items()), is_https)
        for check in HEADER_CHECKS:
            res.findings.extend(check(ctx))
        res.findings.extend(check_cookies(headers.get_all("Set-Cookie") or [], is_https))

        if is_https and not opts.no_tls:
            pacer.wait()
            res.requests_made += 1
            res.findings.extend(check_tls(parts.hostname, parts.port or 443, opts.timeout, opts.insecure))
    except (urllib.error.URLError, OSError, ValueError) as e:
        res.error = str(getattr(e, "reason", e))
    res.duration = round(time.time() - start, 2)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    res.findings.sort(key=lambda f: order[f.severity])
    return res
