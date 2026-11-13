"""Compare an ASAL report with a hand-written ground truth.

Usage:
    python benchmark/benchmark.py out/androgoat/report.json ground_truth/androgoat.yaml

Output: a Markdown table (printed and saved next to the report as benchmark.md).

Definitions
  Detected   static ground-truth item matched by at least one expected rule + location
  Missed     static ground-truth item with no matching finding
  Dynamic    needs a running app; reported separately, not counted as a miss
  Unmatched  ASAL finding (app code) that maps to no ground-truth item. These must be
             triaged: a real issue not listed in the ground truth, or a false positive.
             Review status from the dashboard is shown to make this explicit.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asal.core.models import Finding, Origin, ScanResult  # noqa: E402
from asal.reporting.json_report import load_report  # noqa: E402


def matches(item: dict, f: Finding) -> bool:
    if f.rule_id not in item.get("expected_rules", []):
        return False
    needle = item["match"]
    return any(needle in loc.file for loc in f.locations) or (f.component and needle in f.component)


def run(report_dir: Path, truth_path: Path) -> tuple[str, dict]:
    scan: ScanResult = load_report(report_dir)
    truth = yaml.safe_load(truth_path.read_text(encoding="utf-8"))
    items = truth["vulnerabilities"]
    app_findings = [f for f in scan.findings if f.origin == Origin.APP]

    rows, matched_ids = [], set()
    detected = missed = dynamic = 0
    for item in items:
        hits = [f for f in app_findings if matches(item, f)]
        matched_ids |= {f.id for f in hits}
        if item["scope"] == "dynamic":
            dynamic += 1
            result = "⚪ dynamic (out of scope)"
        elif hits:
            detected += 1
            result = "✅ detected"
        else:
            missed += 1
            result = "❌ missed" + ("" if item.get("expected_rules") else " (no rule yet)")
        rows.append(f"| {item['id']} | {item['name']} | {', '.join(item.get('expected_rules') or ['-'])} | {result} |")

    unmatched = [f for f in app_findings if f.id not in matched_ids]
    static_total = detected + missed
    recall = detected / static_total if static_total else 0.0

    lines = [
        f"## Benchmark: {truth['app']}",
        "",
        f"- Static ground-truth items: **{static_total}**",
        f"- Detected: **{detected}** · Missed: **{missed}** · Detection rate: **{recall:.0%}**",
        f"- Dynamic-only items (out of scope for static analysis): {dynamic}",
        f"- ASAL findings in app code: {len(app_findings)} · matched to ground truth: "
        f"{len(app_findings) - len(unmatched)} · unmatched (needs triage): {len(unmatched)}",
        "",
        "| ID | Vulnerability | Expected rule | Result |",
        "|---|---|---|---|",
        *rows,
    ]
    if unmatched:
        lines += ["", "### Unmatched findings (triage)", "",
                  "| Finding | Rule | Review status | Notes |", "|---|---|---|---|"]
        for f in unmatched:
            lines.append(f"| {f.title} | {f.rule_id} | {f.status.value} | {f.verification_notes or ''} |")
    stats = {"detected": detected, "missed": missed, "dynamic": dynamic, "unmatched": len(unmatched), "recall": recall}
    return "\n".join(lines) + "\n", stats


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("report", type=Path, help="report.json or the scan output folder")
    p.add_argument("truth", type=Path, help="ground_truth/<app>.yaml")
    args = p.parse_args()
    report_dir = args.report.parent if args.report.is_file() else args.report
    md, _ = run(report_dir, args.truth)
    out = report_dir / "benchmark.md"
    out.write_text(md, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(md)
    print(f"Saved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
