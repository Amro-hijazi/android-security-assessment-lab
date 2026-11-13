from pathlib import Path

from asal.analyzers.network_config import analyze_network_config
from asal.core.models import CheckOutcome

FIXTURE = Path(__file__).parent / "fixtures" / "nsc"


def test_nsc_findings_and_coverage():
    findings, checks = analyze_network_config(FIXTURE)
    rules = {f.rule_id for f in findings}
    assert rules == {"NSC-CLEARTEXT-GLOBAL", "NSC-USER-CA"}           # debug-overrides user CA is ignored
    user_ca = next(f for f in findings if f.rule_id == "NSC-USER-CA")
    assert user_ca.locations[0].file == "res/xml/network_security_config.xml"
    assert user_ca.locations[0].line == 6
    pin = next(c for c in checks if c.check_id == "NSC-PINNING")
    assert pin.result == CheckOutcome.PASSED and "example.org" in pin.details


def test_no_config_is_not_applicable(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>')
    findings, checks = analyze_network_config(tmp_path)
    assert not findings and all(c.result == CheckOutcome.NOT_APPLICABLE for c in checks)
