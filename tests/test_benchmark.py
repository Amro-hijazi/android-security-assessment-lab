import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmark"))

from benchmark import run  # noqa: E402

from asal.core.models import (  # noqa: E402
    AppInfo, Confidence, Finding, Location, MasvsCategory, ScanResult, Severity, Source,
)
from asal.reporting.json_report import save_report  # noqa: E402


def f(rule, file):
    return Finding(rule_id=rule, title=rule, description="d", severity=Severity.HIGH, base_severity=Severity.HIGH,
                   confidence=Confidence.HIGH, masvs_category=MasvsCategory.CODE, source=Source.CODE_RULE,
                   impact="i", remediation="r", locations=[Location(file=file, line=1, snippet="x")])


def test_benchmark_counts(tmp_path):
    truth = tmp_path / "t.yaml"
    truth.write_text(
        "app: T\nvulnerabilities:\n"
        "  - {id: T1, name: sqli, scope: static, expected_rules: [CODE-SQL-INJECTION], match: Login}\n"
        "  - {id: T2, name: log, scope: static, expected_rules: [CODE-SENSITIVE-LOG], match: Log}\n"
        "  - {id: T3, name: root, scope: dynamic, expected_rules: [], match: Root}\n")
    scan = ScanResult(app=AppInfo(file_name="a.apk", sha256="0" * 64, size_bytes=1), findings=[
        f("CODE-SQL-INJECTION", "sources/x/Login.java"),
        f("CODE-WEAK-HASH", "sources/x/Other.java"),
    ])
    save_report(scan, tmp_path)
    md, stats = run(tmp_path, truth)
    assert stats == {"detected": 1, "missed": 1, "dynamic": 1, "unmatched": 1, "recall": 0.5}
    assert "| T1 | sqli | CODE-SQL-INJECTION | ✅ detected |" in md
