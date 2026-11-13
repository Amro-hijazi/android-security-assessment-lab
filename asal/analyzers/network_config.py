"""Network Security Config analyzer (res/xml/<name>.xml referenced by the manifest).

Checks:
  - cleartext HTTP allowed globally (base-config) or for specific domains
  - user-installed CAs trusted outside <debug-overrides> (makes MITM with a user CA possible)
  - certificate pinning present (informational, recorded in coverage)
"""

from __future__ import annotations

from pathlib import Path

from lxml import etree

from asal.core.models import CheckOutcome, CheckResult, Confidence, Finding, Location, MasvsCategory, Severity, Source

ANDROID_NS = "http://schemas.android.com/apk/res/android"
NETWORK_1 = "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/"
NETWORK_2 = "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"


def find_config(apktool_dir: Path) -> Path | None:
    """Resolve android:networkSecurityConfig="@xml/name" to res/xml/name.xml."""
    manifest = apktool_dir / "AndroidManifest.xml"
    if not manifest.is_file():
        return None
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    app = etree.parse(str(manifest), parser).getroot().find("application")
    ref = app.get(f"{{{ANDROID_NS}}}networkSecurityConfig") if app is not None else None
    if not ref or not ref.startswith("@xml/"):
        return None
    path = apktool_dir / "res" / "xml" / f"{ref[5:]}.xml"
    return path if path.is_file() else None


def analyze_network_config(apktool_dir: Path) -> tuple[list[Finding], list[CheckResult]]:
    findings: list[Finding] = []
    checks: list[CheckResult] = []
    path = find_config(Path(apktool_dir))
    ids = ("NSC-CLEARTEXT", "NSC-USER-CA", "NSC-PINNING")
    if path is None:
        for cid, title in zip(ids, ("Cleartext traffic restricted by NSC", "User CAs not trusted",
                                    "Certificate pinning")):
            checks.append(CheckResult(check_id=cid, title=title, masvs_category=MasvsCategory.NETWORK,
                                      result=CheckOutcome.NOT_APPLICABLE, details="No Network Security Config"))
        return findings, checks

    rel = path.relative_to(apktool_dir).as_posix()
    raw = path.read_bytes()
    lines = raw.decode("utf-8", errors="replace").splitlines()
    root = etree.fromstring(raw, etree.XMLParser(resolve_entities=False, no_network=True))

    def loc(elem) -> Location:
        n = elem.sourceline or 1
        start = n
        while start > 1 and f"<{elem.tag}" not in lines[start - 1] and n - start < 10:
            start -= 1
        return Location(file=rel, line=start, snippet="\n".join(lines[start - 1:start + 3]), snippet_start_line=start)

    # 1. Cleartext
    clear = CheckResult(check_id="NSC-CLEARTEXT", title="Cleartext traffic restricted by NSC",
                        masvs_category=MasvsCategory.NETWORK, result=CheckOutcome.PASSED)
    base = root.find("base-config")
    if base is not None and base.get("cleartextTrafficPermitted") == "true":
        f = Finding(
            rule_id="NSC-CLEARTEXT-GLOBAL", title="Cleartext HTTP allowed for all domains",
            description='The Network Security Config base-config sets cleartextTrafficPermitted="true".',
            severity=Severity.MEDIUM, base_severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            masvs_category=MasvsCategory.NETWORK, cwe="CWE-319", source=Source.NETWORK_CONFIG,
            locations=[loc(base)],
            impact="Any HTTP request can be read or modified by an attacker on the same network.",
            remediation='Set cleartextTrafficPermitted="false" in base-config and use HTTPS.',
            how_to_verify="Route the device through Burp/mitmproxy and use the app; look for http:// requests.",
            references=[NETWORK_1],
        )
        findings.append(f)
        clear.finding_ids.append(f.id)
    domains = [d for d in root.findall("domain-config") if d.get("cleartextTrafficPermitted") == "true"]
    if domains:
        names = ", ".join(x.text.strip() for d in domains for x in d.findall("domain") if x.text)
        f = Finding(
            rule_id="NSC-CLEARTEXT-DOMAIN", title="Cleartext HTTP allowed for specific domains",
            description=f"cleartextTrafficPermitted=\"true\" for: {names}.",
            severity=Severity.LOW, base_severity=Severity.LOW, confidence=Confidence.HIGH,
            masvs_category=MasvsCategory.NETWORK, cwe="CWE-319", source=Source.NETWORK_CONFIG,
            locations=[loc(d) for d in domains],
            impact="Traffic to these domains can be intercepted.",
            remediation="Serve these domains over HTTPS and remove the exception.",
            references=[NETWORK_1],
        )
        findings.append(f)
        clear.finding_ids.append(f.id)
    if clear.finding_ids:
        clear.result = CheckOutcome.FINDING
    checks.append(clear)

    # 2. User CAs trusted (outside debug-overrides, which only apply to debuggable builds)
    user_ca = CheckResult(check_id="NSC-USER-CA", title="User CAs not trusted",
                          masvs_category=MasvsCategory.NETWORK, result=CheckOutcome.PASSED)
    for cfg in [base, *root.findall("domain-config")]:
        if cfg is None:
            continue
        for cert in cfg.iterfind("trust-anchors/certificates"):
            if cert.get("src") == "user":
                f = Finding(
                    rule_id="NSC-USER-CA", title="App trusts user-installed CA certificates",
                    description=f"<{cfg.tag}> trusts certificates from the user store.",
                    severity=Severity.MEDIUM, base_severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    masvs_category=MasvsCategory.NETWORK, cwe="CWE-295", source=Source.NETWORK_CONFIG,
                    locations=[loc(cert)],
                    impact="Anyone who can install a CA on the device (or trick the user into it) can intercept HTTPS.",
                    remediation='Remove <certificates src="user"/> or move it into <debug-overrides>.',
                    how_to_verify="Install the Burp CA as a user certificate (Settings > Security) and check "
                                  "whether app HTTPS traffic is visible in Burp.",
                    references=[NETWORK_1],
                )
                findings.append(f)
                user_ca.finding_ids.append(f.id)
    if user_ca.finding_ids:
        user_ca.result = CheckOutcome.FINDING
    checks.append(user_ca)

    # 3. Pinning (coverage only)
    pins = root.findall(".//pin-set")
    pinned = sorted({x.text.strip() for p in pins for x in p.getparent().findall("domain") if x.text})
    checks.append(CheckResult(
        check_id="NSC-PINNING", title="Certificate pinning", masvs_category=MasvsCategory.NETWORK,
        result=CheckOutcome.PASSED if pins else CheckOutcome.NOT_APPLICABLE,
        details=f"Pinning configured for: {', '.join(pinned)}" if pins else "No <pin-set> in the NSC",
    ))
    return findings, checks
