"""Command line entry point.

Usage:
    python -m asal scan samples/AndroGoat.apk -o out/androgoat
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from asal.core.apk_loader import ApkValidationError
from asal.core.scanner import run_scan
from asal.reporting.html_report import write_html_report
from asal.reporting.json_report import save_report


def _setup_logging(out_dir: Path, verbose: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(out_dir / "asal.log", encoding="utf-8"),
                  logging.StreamHandler(sys.stderr)],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asal", description="Android Security Assessment Lab")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Statically analyze an APK")
    scan.add_argument("apk", type=Path)
    scan.add_argument("-o", "--out", type=Path, default=Path("out"), help="Output folder")
    scan.add_argument("--skip-jadx", action="store_true", help="Manifest only (faster)")
    scan.add_argument("--include-libs", action="store_true", help="Also scan known third-party libraries")
    scan.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    _setup_logging(args.out, args.verbose)
    try:
        result = run_scan(args.apk, args.out, skip_jadx=args.skip_jadx, include_libraries=args.include_libs)
    except ApkValidationError as exc:
        print(f"[!] Invalid APK: {exc}", file=sys.stderr)
        return 2

    report = save_report(result, args.out)
    html = write_html_report(result, args.out)

    app = result.app
    print(f"\nApp:      {app.package_name}  v{app.version_name}  (minSdk {app.min_sdk}, targetSdk {app.target_sdk})")
    print(f"SHA-256:  {app.sha256}")
    print("Findings: " + ", ".join(f"{k}={v}" for k, v in result.count_by_severity().items()))
    for origin in ("app", "library"):
        items = [f for f in result.findings if f.origin.value == origin]
        if not items:
            continue
        print(f"\n  -- {origin.upper()} CODE --")
        for f in items:
            loc = f.locations[0]
            flag = " *" if f.severity != f.base_severity else ""
            print(f"  [{f.severity.value.upper():8}] {f.title}  ({loc.file}:{loc.line}){flag}")
    if any(f.severity != f.base_severity for f in result.findings):
        print("\n  * severity adjusted from context (see severity_reason in report.json)")
    if result.errors:
        print("\nWarnings:")
        for e in result.errors:
            print(f"  - {e}")
    if result.partial:
        print("\n[!] Results are PARTIAL: some analysis steps did not complete.")
    print(f"\nReport:   {report}")
    print(f"HTML:     {html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
