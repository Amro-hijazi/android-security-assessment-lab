import pytest
from pydantic import ValidationError

from asal.core.models import (
    AppInfo, Confidence, Finding, Location, MasvsCategory, Origin,
    ScanResult, Severity, Source, Status,
)


def make_finding(**overrides) -> Finding:
    data = dict(
        rule_id="MANIFEST-EXPORTED-ACTIVITY",
        title="Exported activity without permission",
        description="Activity can be started by any app.",
        severity=Severity.MEDIUM,
        base_severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        masvs_category=MasvsCategory.PLATFORM,
        cwe="cwe-926",
        source=Source.MANIFEST,
        locations=[Location(file="AndroidManifest.xml", line=42, snippet='<activity android:exported="true"/>')],
        impact="Other apps can open internal screens.",
        remediation="Set exported=false or require a permission.",
    )
    data.update(overrides)
    return Finding(**data)


def test_defaults_and_id_are_stable():
    a, b = make_finding(), make_finding()
    assert a.status == Status.AUTO
    assert a.origin == Origin.APP
    assert a.cwe == "CWE-926"
    assert a.id == b.id and a.id.startswith("MANIFEST-EXPORTED-ACTIVITY-")


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        make_finding(locations=[])


def test_severity_change_requires_reason():
    with pytest.raises(ValueError):
        make_finding(severity=Severity.HIGH)
    f = make_finding()
    f.adjust_severity(Severity.HIGH, "Reads Intent extras")
    assert f.severity == Severity.HIGH and f.severity_reason


def test_verification_requires_notes():
    f = make_finding()
    with pytest.raises(ValueError):
        f.set_status(Status.VERIFIED)
    f.set_status(Status.VERIFIED, "Launched via adb shell am start")
    assert f.status == Status.VERIFIED


def test_severity_helpers():
    assert Severity.MEDIUM.raise_by() == Severity.HIGH
    assert Severity.CRITICAL.raise_by() == Severity.CRITICAL
    assert Severity.INFO.lower_by() == Severity.INFO


def test_scan_result_counts_and_json_roundtrip():
    scan = ScanResult(
        app=AppInfo(file_name="a.apk", sha256="0" * 64, size_bytes=1),
        findings=[make_finding(), make_finding(origin=Origin.LIBRARY)],
    )
    assert scan.count_by_severity()["medium"] == 2
    assert scan.count_by_severity(Origin.APP)["medium"] == 1
    again = ScanResult.model_validate_json(scan.model_dump_json())
    assert again.findings[0].id == scan.findings[0].id
