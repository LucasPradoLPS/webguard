import argparse
import sys

from . import __version__
from .models import SEVERITIES
from .report import to_html, to_json, to_text
from .scanner import BROWSER_UA, HONEST_UA, Options, Pacer, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webguard",
        description="Passive web security posture scanner (headers, cookies, TLS). "
                    "Use only on systems you own or are authorized to test.")
    p.add_argument("targets", nargs="*", help="URL or host (https:// assumed)")
    p.add_argument("-f", "--targets-file", help="file with one target per line")
    p.add_argument("--insecure", action="store_true", help="accept self-signed certificates (labs)")
    p.add_argument("--no-tls", action="store_true", help="skip the TLS handshake check")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", metavar="FILE", help="write JSON report")
    p.add_argument("--html", metavar="FILE", help="write HTML report")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    g = p.add_argument_group("noise control")
    g.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    g.add_argument("--jitter", type=float, default=0.0, help="add random 0..N seconds to the delay")
    g.add_argument("--user-agent", help="custom User-Agent (default is an honest WebGuard UA)")
    g.add_argument("--stealth", action="store_true",
                   help="preset: browser User-Agent, 3s delay, 2s jitter (only where evasion is in scope)")
    p.add_argument("--version", action="version", version="webguard " + __version__)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    targets = list(args.targets)
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8") as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        print("error: no targets given", file=sys.stderr)
        return 2

    delay, jitter, ua = args.delay, args.jitter, args.user_agent or HONEST_UA
    if args.stealth:
        delay, jitter = delay or 3.0, jitter or 2.0
        ua = args.user_agent or BROWSER_UA
    opts = Options(timeout=args.timeout, insecure=args.insecure, user_agent=ua,
                   delay=delay, jitter=jitter, no_tls=args.no_tls)
    pacer = Pacer(delay, jitter)  # shared so spacing also applies between targets

    results = [scan(t, opts, pacer) for t in targets]

    print(to_text(results))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(results))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(results))

    if all(r.error for r in results):
        return 2
    limit = SEVERITIES.index(args.fail_on)
    bad = any(SEVERITIES.index(f.severity) <= limit for r in results for f in r.findings)
    return 1 if bad else 0
