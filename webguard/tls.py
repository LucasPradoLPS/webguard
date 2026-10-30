"""TLS check: one handshake. Verifies the certificate first; if that fails,
reconnects unverified so protocol and cipher can still be reported."""
import socket
import ssl
import time
from typing import List, Tuple

from .models import Finding

WEAK_PROTOCOLS = ("SSLv3", "TLSv1", "TLSv1.1")
WEAK_CIPHER_PARTS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")
REF = "OWASP WSTG-CRYP-01"


def _handshake(host: str, port: int, timeout: float, verify: bool) -> Tuple[str, tuple, dict]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.version() or "", s.cipher() or ("", "", 0), s.getpeercert() or {}


def check_tls(host: str, port: int, timeout: float = 10.0, insecure: bool = False) -> List[Finding]:
    out = []
    cert = {}
    try:
        version, cipher, cert = _handshake(host, port, timeout, verify=not insecure)
    except ssl.SSLCertVerificationError as e:
        out.append(Finding(
            "tls-cert-invalid", "Certificate failed validation", "high",
            "Clients cannot verify the server identity; users get trained to click through warnings, enabling MITM.",
            "Install a valid certificate from a trusted CA that matches the hostname.",
            REF, e.verify_message or str(e)))
        try:
            version, cipher, _ = _handshake(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError):
            return out
    except (OSError, ssl.SSLError) as e:
        return [Finding(
            "tls-error", "TLS handshake failed", "high",
            "The HTTPS endpoint could not negotiate a secure session.",
            "Check the TLS configuration of the server.", REF, str(e))]

    if version in WEAK_PROTOCOLS:
        out.append(Finding(
            "tls-weak-protocol", "Deprecated protocol negotiated: " + version, "high",
            "Old protocol versions have known attacks (POODLE, BEAST).",
            "Disable everything below TLS 1.2.", REF, version))
    name = cipher[0]
    if any(p in name.upper() for p in WEAK_CIPHER_PARTS):
        out.append(Finding(
            "tls-weak-cipher", "Weak cipher negotiated: " + name, "high",
            "Weak ciphers can be broken or are unauthenticated.",
            "Restrict the cipher list to AEAD suites (AES-GCM, ChaCha20).", REF, name))

    if cert.get("notAfter"):
        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        if days < 0:
            out.append(Finding(
                "tls-cert-expired", "Certificate expired", "high",
                "Browsers will block or warn on the site.", "Renew the certificate.", REF, cert["notAfter"]))
        elif days < 14:
            out.append(Finding(
                "tls-cert-expiring", "Certificate expires in %d days" % days, "low",
                "An expired certificate causes an outage and trust warnings.",
                "Renew now and automate renewal (ACME).", REF, cert["notAfter"]))
    return out
