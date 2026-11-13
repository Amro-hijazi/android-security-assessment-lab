"""Scan pipeline: validate -> decompile -> analyze -> correlate -> ScanResult.

Each stage that fails is recorded in `errors` and the result is marked
`partial` instead of crashing, so the analyst always knows what was
and was not analyzed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from asal.analyzers.code_rules import CodeRuleEngine
from asal.analyzers.manifest import ManifestAnalyzer
from asal.analyzers.network_config import analyze_network_config
from asal.core.apk_loader import load_apk
from asal.core.decompiler import ToolNotFoundError, run_apktool, run_jadx
from asal.core.models import AppInfo, ScanResult
from asal.correlation.context_severity import apply_component_context
from asal.correlation.dedup import group_findings
from asal.reporting.json_report import apply_reviews, load_reviews

log = logging.getLogger(__name__)


def run_scan(apk_path: str | Path, out_dir: str | Path, skip_jadx: bool = False,
             include_libraries: bool = False) -> ScanResult:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    apk = load_apk(apk_path)  # raises ApkValidationError: nothing is decompiled if this fails
    log.info("APK OK: %s (sha256 %s)", apk.path.name, apk.sha256)
    scan = ScanResult(app=AppInfo(file_name=apk.path.name, sha256=apk.sha256, size_bytes=apk.size_bytes))

    # 1. Decompile
    apktool_dir, sources_dir = out_dir / "apktool", None
    try:
        apktool = run_apktool(apk.path, apktool_dir)
        scan.errors += apktool.messages
    except ToolNotFoundError as exc:
        apktool = None
        scan.errors.append(str(exc))

    if not skip_jadx:
        try:
            jadx = run_jadx(apk.path, out_dir / "jadx")
            scan.errors += jadx.messages
            if jadx.ok:
                sources_dir = jadx.output_dir / "sources"
            if not jadx.ok or jadx.partial:
                scan.partial = True
        except ToolNotFoundError as exc:
            scan.errors.append(str(exc))
            scan.partial = True

    # 2. Manifest analysis (also gives us the package name used by the code engine)
    if apktool and apktool.ok:
        try:
            analysis = ManifestAnalyzer(apktool_dir).analyze()
            scan.app = scan.app.model_copy(update={k: v for k, v in analysis.app_info.items() if v is not None})
            scan.findings += analysis.findings
            scan.checks += analysis.checks
            nsc_findings, nsc_checks = analyze_network_config(apktool_dir)
            scan.findings += nsc_findings
            scan.checks += nsc_checks
        except Exception as exc:  # malformed manifest must not kill the whole scan
            log.exception("Manifest analysis failed")
            scan.errors.append(f"Manifest analysis failed: {exc}")
            scan.partial = True
    else:
        scan.errors.append("Manifest analysis skipped because APKTool did not produce a manifest")
        scan.partial = True

    # 3. Code rules
    if sources_dir is not None:
        try:
            code = CodeRuleEngine(sources_dir, scan.app.package_name, include_libraries=include_libraries).analyze()
            scan.findings += code.findings
            scan.checks += code.checks
            log.info("Scanned %d Java files (%d library files skipped)", code.files_scanned, code.files_skipped_library)
        except Exception as exc:
            log.exception("Code analysis failed")
            scan.errors.append(f"Code analysis failed: {exc}")
            scan.partial = True
    elif not skip_jadx:
        scan.errors.append("Code analysis skipped because JADX produced no sources")

    # 4. Correlation: context-aware severity, then grouping of repeated hits
    apply_component_context(scan.findings, sources_dir)
    scan.findings = group_findings(scan.findings, scan.checks)

    scan.findings.sort(key=lambda f: (f.origin.value != "app", -f.severity.rank))

    # 5. Re-apply analyst decisions from earlier scans of the same APK (stable ids)
    restored = apply_reviews(scan, load_reviews(out_dir))
    if restored:
        log.info("Restored %d earlier review decision(s)", restored)
    return scan
