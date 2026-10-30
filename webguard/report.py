"""Output formats: coloured terminal text, JSON and a self-contained HTML report."""
import json
import os
import sys
from datetime import datetime
from html import escape
from typing import List

from .models import SEVERITIES, ScanResult

COLORS = {"critical": "35;1", "high": "31;1", "medium": "33", "low": "36", "info": "37"}
HTML_COLORS = {"critical": "#a21caf", "high": "#dc2626", "medium": "#d97706", "low": "#0891b2", "info": "#6b7280"}


def _use_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(text: str, code: str, on: bool) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if on else text


def to_text(results: List[ScanResult]) -> str:
    on = _use_color()
    if on and os.name == "nt":
        os.system("")  # enables ANSI escapes on Windows consoles
    lines = []
    for r in results:
        lines.append(_c("== %s" % r.target, "1", on))
        if r.error:
            lines.append("  ERROR: " + r.error)
            continue
        lines.append("  %s -> HTTP %s | grade %s (%d/100) | %d request(s), %.2fs" % (
            r.final_url, r.status, r.grade, r.score, r.requests_made, r.duration))
        if not r.findings:
            lines.append("  no findings")
        for f in r.findings:
            lines.append("  [%s] %s" % (_c(f.severity.upper(), COLORS[f.severity], on), f.title))
            lines.append("      why: " + f.why)
            lines.append("      fix: " + f.fix)
            if f.evidence:
                lines.append("      evidence: " + f.evidence)
        lines.append("")
    return "\n".join(lines)


def to_json(results: List[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False)


CSS = """
:root{--bg:#f8fafc;--fg:#0f172a;--card:#fff;--mut:#64748b;--bd:#e2e8f0}
@media(prefers-color-scheme:dark){:root{--bg:#0b1120;--fg:#e2e8f0;--card:#111a2e;--mut:#94a3b8;--bd:#1e293b}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px}
main{max-width:860px;margin:auto}h1{margin:0 0 4px}.mut{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin:14px 0}
.grade{font-size:44px;font-weight:700}.pill{color:#fff;border-radius:99px;padding:1px 10px;font-size:12px;font-weight:600}
code{background:var(--bd);padding:1px 5px;border-radius:4px;word-break:break-all}
"""


def to_html(results: List[ScanResult]) -> str:
    body = []
    for r in results:
        body.append('<section class="card"><h2>%s</h2>' % escape(r.target))
        if r.error:
            body.append('<p>Error: %s</p></section>' % escape(r.error))
            continue
        counts = " &middot; ".join("%d %s" % (n, s) for s, n in r.counts().items() if n)
        body.append(
            '<div class="grade">%s <span class="mut" style="font-size:18px">%d/100</span></div>'
            '<p class="mut">%s &rarr; HTTP %s &middot; %d request(s) &middot; %s</p></section>' % (
                r.grade, r.score, escape(r.final_url), r.status, r.requests_made, counts or "no findings"))
        for sev in SEVERITIES:
            for f in (x for x in r.findings if x.severity == sev):
                body.append(
                    '<div class="card"><span class="pill" style="background:%s">%s</span> <b>%s</b>'
                    '<p><b>Why it matters:</b> %s</p><p><b>Fix:</b> %s</p>%s%s</div>' % (
                        HTML_COLORS[sev], sev.upper(), escape(f.title), escape(f.why), escape(f.fix),
                        '<p>Evidence: <code>%s</code></p>' % escape(f.evidence) if f.evidence else "",
                        '<p class="mut">Ref: %s</p>' % escape(f.ref) if f.ref else ""))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>WebGuard Report</title><style>%s</style></head><body><main>'
        '<h1>WebGuard Report</h1><p class="mut">Generated %s. Passive checks only; run solely against authorized targets.</p>'
        '%s</main></body></html>' % (CSS, datetime.now().strftime("%Y-%m-%d %H:%M"), "".join(body)))
