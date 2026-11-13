"""Self-contained HTML report (one file, no external CSS/JS), rendered with Jinja2.

Autoescaping is ON: code snippets come from the analysed app and must
never be able to inject HTML/JS into the report (stored XSS in a report
is a classic mistake in security tools).
"""

from __future__ import annotations

from datetime import timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from asal.core.models import Finding, Location, Origin, ScanResult, Severity, Status

TEMPLATES = Path(__file__).resolve().parent / "templates"
SEVERITY_ORDER = [s for s in sorted(Severity, key=lambda s: -s.rank)]


def numbered_lines(loc: Location) -> list[tuple[int | None, str, bool]]:
    """[(line_no, text, is_hit)] so the template can show line numbers and highlight the hit."""
    start = loc.snippet_start_line or loc.line
    out = []
    for i, text in enumerate(loc.snippet.splitlines()):
        n = start + i if start else None
        out.append((n, text, n is not None and n == loc.line))
    return out


def _context(scan: ScanResult) -> dict:
    app_findings = [f for f in scan.findings if f.origin == Origin.APP]
    lib_findings = [f for f in scan.findings if f.origin == Origin.LIBRARY]
    key_findings = [f for f in app_findings
                    if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.status != Status.FALSE_POSITIVE]
    return {
        "scan": scan,
        "app": scan.app,
        "scanned_at": scan.scanned_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "severities": [s.value for s in SEVERITY_ORDER],
        "by_severity_app": scan.count_by_severity(Origin.APP),
        "by_severity_lib": scan.count_by_severity(Origin.LIBRARY),
        "by_status": scan.count_by_status(),
        "app_findings": app_findings,
        "lib_findings": lib_findings,
        "key_findings": key_findings,
        "numbered_lines": numbered_lines,
        "code_rule_count": sum(1 for c in scan.checks if c.check_id.startswith("CODE-")),
        "coverage": {o: sum(1 for c in scan.checks if c.result.value == o)
                     for o in ("finding", "passed", "not_applicable", "error")},
    }


def render_html_report(scan: ScanResult) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    return env.get_template("report.html.j2").render(**_context(scan))


def write_html_report(scan: ScanResult, out_dir: Path) -> Path:
    path = Path(out_dir) / "report.html"
    path.write_text(render_html_report(scan), encoding="utf-8")
    return path
