import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from webguard.cookies import check_cookies
from webguard.headers import HEADER_CHECKS, Ctx
from webguard.models import Finding, ScanResult
from webguard.scanner import Options, Pacer, scan

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def run_checks(headers, https=True):
    ctx = Ctx(headers, https)
    return [f for check in HEADER_CHECKS for f in check(ctx)]


def ids(findings):
    return {f.id for f in findings}


class HeaderTests(unittest.TestCase):
    def test_perfect_headers_score_a(self):
        r = ScanResult("x", findings=run_checks(GOOD))
        self.assertEqual(r.findings, [])
        self.assertEqual((r.grade, r.score), ("A", 100))

    def test_empty_headers_fail(self):
        r = ScanResult("x", findings=run_checks({}))
        self.assertTrue({"hsts-missing", "csp-missing", "clickjacking", "nosniff"} <= ids(r.findings))
        self.assertEqual(r.grade, "F")

    def test_weak_csp(self):
        h = dict(GOOD, **{"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
        self.assertIn("csp-unsafe-inline", ids(run_checks(h)))

    def test_http_has_no_hsts_check(self):
        found = ids(run_checks({}, https=False))
        self.assertIn("transport-http", found)
        self.assertNotIn("hsts-missing", found)

    def test_version_disclosure(self):
        self.assertIn("disclosure-server", ids(run_checks(dict(GOOD, Server="nginx/1.18.0"))))
        self.assertNotIn("disclosure-server", ids(run_checks(dict(GOOD, Server="nginx"))))

    def test_cors_wildcard_with_credentials(self):
        h = dict(GOOD, **{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        self.assertIn("cors-wildcard-creds", ids(run_checks(h)))


class CookieTests(unittest.TestCase):
    def test_insecure_cookie(self):
        found = ids(check_cookies(["sessionid=abc; Path=/"], True))
        self.assertEqual(found, {"cookie-secure", "cookie-httponly", "cookie-samesite"})

    def test_secure_cookie_is_clean(self):
        self.assertEqual(check_cookies(["sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"], True), [])

    def test_samesite_none_without_secure(self):
        self.assertIn("cookie-samesite-none", ids(check_cookies(["a=b; HttpOnly; SameSite=None"], False)))


class PacerTests(unittest.TestCase):
    def test_first_call_never_sleeps(self):
        import time
        p = Pacer(0.2, 0)
        t = time.time()
        p.wait()
        self.assertLess(time.time() - t, 0.1)
        p.wait()
        self.assertGreaterEqual(time.time() - t, 0.2)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "demo/9.9")
        self.send_header("Set-Cookie", "session=1; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class EndToEnd(unittest.TestCase):
    def test_scan_local_http_server(self):
        srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            res = scan("http://127.0.0.1:%d" % srv.server_port, Options(timeout=5))
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(res.error, "")
        self.assertEqual(res.status, 200)
        self.assertEqual(res.requests_made, 1)  # plain HTTP: no TLS touch
        self.assertTrue({"transport-http", "cookie-httponly", "disclosure-server"} <= ids(res.findings))

    def test_unreachable_target_reports_error(self):
        res = scan("http://127.0.0.1:1", Options(timeout=2))
        self.assertTrue(res.error)


if __name__ == "__main__":
    unittest.main()
