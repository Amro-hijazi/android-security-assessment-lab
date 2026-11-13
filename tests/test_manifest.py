"""Manifest analyzer tests against a hand-written fixture with known answers."""

from pathlib import Path

import pytest

from asal.analyzers.manifest import ManifestAnalyzer
from asal.core.models import CheckOutcome, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "manifest_basic"


@pytest.fixture(scope="module")
def result():
    return ManifestAnalyzer(FIXTURE).analyze()


def titles(result):
    return [f.title for f in result.findings]


def by_rule(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_app_info_from_manifest_and_apktool_yml(result):
    assert result.app_info["package_name"] == "com.example.vuln"
    assert result.app_info["version_name"] == "2.1"
    assert result.app_info["min_sdk"] == 21
    assert result.app_info["target_sdk"] == 27


def test_debuggable_detected(result):
    [f] = by_rule(result, "MANIFEST-DEBUGGABLE")
    assert f.severity == Severity.HIGH
    assert f.locations[0].line == 7


def test_launcher_and_non_exported_activities_ignored(result):
    joined = " ".join(titles(result))
    assert "MainActivity" not in joined
    assert "PrivateActivity" not in joined


def test_implicit_export_via_browsable_intent_filter_raises_severity(result):
    [f] = by_rule(result, "MANIFEST-EXPORTED-ACTIVITY")
    assert "DeepLinkActivity" in f.title
    assert "implicitly exported" in f.description
    assert "vuln://pay" in f.description
    assert f.base_severity == Severity.MEDIUM
    assert f.severity == Severity.HIGH
    assert "BROWSABLE" in f.severity_reason


def test_permission_strength(result):
    services = by_rule(result, "MANIFEST-EXPORTED-SERVICE")
    assert len(services) == 1 and "WeakService" in services[0].title  # normal-level permission is weak
    assert not by_rule(result, "MANIFEST-EXPORTED-RECEIVER")          # system permission counts as protected


def test_provider_not_exported_by_default_on_modern_target(result):
    assert not by_rule(result, "MANIFEST-EXPORTED-PROVIDER")


def test_cleartext_default_on_old_target_sdk(result):
    [f] = by_rule(result, "MANIFEST-CLEARTEXT")
    assert "targetSdk is 27" in f.description


def test_coverage_records_every_check(result):
    outcomes = {c.check_id: c.result for c in result.checks}
    assert outcomes["MANIFEST-ALLOW-BACKUP"] == CheckOutcome.FINDING      # absent = default true
    assert outcomes["MANIFEST-EXPORTED-RECEIVER"] == CheckOutcome.PASSED
    assert outcomes["MANIFEST-EXPORTED-ACTIVITY-ALIAS"] == CheckOutcome.NOT_APPLICABLE
    assert outcomes["MANIFEST-MIN-SDK"] == CheckOutcome.FINDING


def test_every_finding_has_evidence(result):
    for f in result.findings:
        assert f.locations and f.locations[0].snippet.strip()


def test_xxe_is_not_resolved(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?>\n<!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="&x;">'
        "<application/></manifest>"
    )
    # The hardened parser refuses the external entity instead of reading the file.
    from lxml.etree import XMLSyntaxError
    with pytest.raises(XMLSyntaxError, match="external entity"):
        ManifestAnalyzer(tmp_path).analyze()


def test_yaml_version_name_is_text(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p"><application/></manifest>')
    (tmp_path / "apktool.yml").write_text("versionInfo:\n  versionCode: 1\n  versionName: 1.0\n")
    info = ManifestAnalyzer(tmp_path).analyze().app_info
    assert info["version_name"] == "1.0" and info["version_code"] == "1"
