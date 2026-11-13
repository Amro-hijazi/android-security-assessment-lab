from asal.core.models import (
    AppInfo, Confidence, Finding, Location, MasvsCategory, ScanResult, Severity, Source, Status,
)
from asal.reporting.html_report import render_html_report
from asal.reporting.json_report import apply_reviews, load_report, load_reviews, save_report, save_review


def make_scan(snippet='String s = "<script>alert(1)</script>";') -> ScanResult:
    f = Finding(
        rule_id="CODE-X", title="Test finding", description="d", severity=Severity.HIGH,
        base_severity=Severity.HIGH, confidence=Confidence.HIGH, masvs_category=MasvsCategory.CODE,
        source=Source.CODE_RULE, impact="i", remediation="r",
        locations=[Location(file="sources/a/B.java", line=11, snippet=f"a\n{snippet}\nc", snippet_start_line=10)],
    )
    return ScanResult(app=AppInfo(file_name="a.apk", sha256="0" * 64, size_bytes=1048576), findings=[f])


def test_html_escapes_code_from_the_app():
    html = render_html_report(make_scan())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_highlights_reported_line():
    html = render_html_report(make_scan())
    assert '<span class="row hit"><span class="ln">11</span>' in html


def test_review_survives_rescan(tmp_path):
    scan = make_scan()
    save_report(scan, tmp_path)
    fid = scan.findings[0].id
    save_review(tmp_path, fid, Status.VERIFIED, "confirmed with adb")

    rescan = make_scan()  # same rule + location -> same deterministic id
    assert apply_reviews(rescan, load_reviews(tmp_path)) == 1
    assert rescan.findings[0].status == Status.VERIFIED

    loaded = load_report(tmp_path)
    assert loaded.findings[0].verification_notes == "confirmed with adb"

    save_review(tmp_path, fid, Status.AUTO, None)  # resetting removes the stored decision
    assert load_reviews(tmp_path) == {}
