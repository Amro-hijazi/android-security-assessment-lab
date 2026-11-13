"""End-to-end pipeline test. APKTool/JADX are replaced by functions that copy
fixture output, so the test runs anywhere (Windows, Linux, CI) without the tools."""

import shutil
import zipfile
from pathlib import Path

import pytest

from asal.core import scanner
from asal.core.decompiler import DecompileResult
from asal.core.models import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "mini_app"


@pytest.fixture
def scan_result(tmp_path, monkeypatch):
    apk = tmp_path / "mini.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"x")
        zf.writestr("classes.dex", b"x")

    def fake_apktool(apk_path, out_dir):
        shutil.copytree(FIXTURE / "apktool", out_dir)
        return DecompileResult(tool="apktool", output_dir=out_dir, ok=True)

    def fake_jadx(apk_path, out_dir):
        shutil.copytree(FIXTURE / "jadx", out_dir)
        return DecompileResult(tool="jadx", output_dir=out_dir, ok=True)

    monkeypatch.setattr(scanner, "run_apktool", fake_apktool)
    monkeypatch.setattr(scanner, "run_jadx", fake_jadx)
    return scanner.run_scan(apk, tmp_path / "out")


def find(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_receiver_reading_intent_is_raised_with_evidence(scan_result):
    [f] = find(scan_result, "MANIFEST-EXPORTED-RECEIVER")
    assert f.base_severity == Severity.MEDIUM and f.severity == Severity.HIGH
    assert "SmsReceiver.java:5" in f.severity_reason
    assert any(loc.file.endswith("SmsReceiver.java") and loc.line == 5 for loc in f.locations)
    assert "adb shell am broadcast -n com.example.vuln/.SmsReceiver" in f.how_to_verify


def test_activity_without_input_keeps_severity(scan_result):
    [f] = find(scan_result, "MANIFEST-EXPORTED-ACTIVITY")
    assert f.severity == Severity.MEDIUM and f.severity_reason is None
    assert "No Intent input reading" in f.description


def test_repeated_hits_are_grouped_and_libraries_skipped(scan_result):
    [f] = find(scan_result, "CODE-SENSITIVE-LOG")
    assert "(2 locations)" in f.title
    assert {loc.file for loc in f.locations} == {
        "sources/com/example/vuln/NoInputActivity.java", "sources/com/example/vuln/SmsReceiver.java"}
    check = next(c for c in scan_result.checks if c.check_id == "CODE-SENSITIVE-LOG")
    assert check.finding_ids == [f.id]


def test_scan_is_complete_and_json_serializable(scan_result):
    assert not scan_result.partial and not scan_result.errors
    assert scan_result.app.package_name == "com.example.vuln"
    assert scan_result.model_dump_json()
