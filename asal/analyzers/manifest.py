"""AndroidManifest.xml analyzer.

Input: the folder produced by `apktool d`, which contains a plain-text
AndroidManifest.xml and apktool.yml (where APKTool stores minSdk/targetSdk).

The manifest is parsed as XML (never regex), so attributes are read
exactly as Android reads them, and every finding points to a real line.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from lxml import etree

from asal.core.models import (
    AppInfo, CheckOutcome, CheckResult, Confidence, Finding, Location,
    MasvsCategory, Severity, Source,
)

log = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
MASVS_URL = "https://mas.owasp.org/MASVS/"
MASVS_PLATFORM_1 = "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/"

# Permissions Android classifies as "dangerous" (runtime permissions). Informational only.
DANGEROUS_PERMISSIONS = {
    "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP",
    "BODY_SENSORS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH",
    "RECEIVE_MMS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS",
}

# Base severity per component type, justified in docs/methodology.md:
# providers expose data directly (query/insert/update/delete), so they start higher.
COMPONENT_SEVERITY = {
    "activity": Severity.MEDIUM,
    "activity-alias": Severity.MEDIUM,
    "service": Severity.MEDIUM,
    "receiver": Severity.MEDIUM,
    "provider": Severity.HIGH,
}


def a(name: str) -> str:
    """Qualified attribute name in the android: namespace."""
    return f"{{{ANDROID_NS}}}{name}"


@dataclass
class ManifestAnalysis:
    app_info: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)


class ManifestAnalyzer:
    def __init__(self, apktool_dir: Path):
        self.root_dir = Path(apktool_dir)
        self.manifest_path = self.root_dir / "AndroidManifest.xml"
        self.lines: list[str] = []
        self.package: str = ""
        self.min_sdk: int | None = None
        self.target_sdk: int | None = None
        self.custom_permissions: dict[str, str] = {}

    # ------------------------------------------------------------------ helpers

    def _parse(self) -> etree._Element:
        # Hardened parser: no external entities, no network access (XXE protection).
        parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
        raw = self.manifest_path.read_bytes()
        self.lines = raw.decode("utf-8", errors="replace").splitlines()
        return etree.fromstring(raw, parser)

    def _read_sdk_info(self, root: etree._Element) -> None:
        """minSdk/targetSdk: APKTool moves them out of the manifest into apktool.yml."""
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            self.min_sdk = _to_int(uses_sdk.get(a("minSdkVersion")))
            self.target_sdk = _to_int(uses_sdk.get(a("targetSdkVersion")))

        yml = self.root_dir / "apktool.yml"
        if yml.is_file() and (self.min_sdk is None or self.target_sdk is None):
            # Older APKTool versions start the file with a Java type tag (!!brut...) that
            # safe_load rejects, so drop tag lines before parsing.
            text = "\n".join(l for l in yml.read_text(errors="replace").splitlines() if not l.startswith("!!"))
            try:
                data = yaml.safe_load(text) or {}
            except yaml.YAMLError as exc:
                log.warning("Could not parse apktool.yml: %s", exc)
                data = {}
            sdk = data.get("sdkInfo") or {}
            self.min_sdk = self.min_sdk or _to_int(sdk.get("minSdkVersion"))
            self.target_sdk = self.target_sdk or _to_int(sdk.get("targetSdkVersion"))
            ver = data.get("versionInfo") or {}
            # YAML reads `versionName: 1.0` as a float, so always convert to text.
            name, code = ver.get("versionName"), ver.get("versionCode")
            self._yml_version = (str(name) if name is not None else None,
                                 str(code) if code is not None else None)

    def _location(self, elem: etree._Element, max_lines: int = 12) -> Location:
        """Evidence for an element: its start line plus the lines it spans."""
        # libxml2 reports the line where the start tag ENDS; for tags whose attributes span
        # several lines, walk back to the line that contains "<tag".
        tag_end = elem.sourceline or 1
        start = tag_end
        while start > 1 and f"<{elem.tag}" not in self.lines[start - 1] and tag_end - start < 30:
            start -= 1
        # Find the closing line: same line for self-closing tags, else the matching </tag>.
        end = tag_end
        if not self.lines[tag_end - 1].rstrip().endswith("/>"):
            for i in range(tag_end, min(tag_end + 200, len(self.lines))):
                if f"</{elem.tag}>" in self.lines[i]:
                    end = i + 1
                    break
        end = min(end, start - 1 + max_lines, len(self.lines))
        snippet = "\n".join(self.lines[start - 1:end]) or etree.tostring(elem, encoding="unicode")[:500]
        return Location(file="AndroidManifest.xml", line=start, snippet=snippet, snippet_start_line=start)

    def _full_name(self, name: str) -> str:
        if name.startswith("."):
            return self.package + name
        if "." not in name:
            return f"{self.package}.{name}"
        return name

    # ------------------------------------------------------------------ main

    def analyze(self) -> ManifestAnalysis:
        result = ManifestAnalysis()
        root = self._parse()
        self.package = root.get("package", "")
        self._yml_version = (None, None)
        self._read_sdk_info(root)

        result.app_info = {
            "package_name": self.package or None,
            "version_name": root.get(a("versionName")) or self._yml_version[0],
            "version_code": root.get(a("versionCode")) or self._yml_version[1],
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
        }

        for perm in root.findall("permission"):
            self.custom_permissions[perm.get(a("name"), "")] = perm.get(a("protectionLevel"), "normal")

        app = root.find("application")
        if app is None:
            result.checks.append(CheckResult(
                check_id="MANIFEST-APPLICATION", title="Application element present",
                masvs_category=MasvsCategory.CODE, result=CheckOutcome.ERROR,
                details="No <application> element found",
            ))
            return result

        self._check_debuggable(app, result)
        self._check_allow_backup(app, result)
        self._check_cleartext(app, result)
        self._check_components(app, result)
        self._check_min_sdk(root, result)
        self._check_dangerous_permissions(root, result)
        return result

    # ------------------------------------------------------------------ checks

    def _check_debuggable(self, app, result: ManifestAnalysis) -> None:
        check = CheckResult(check_id="MANIFEST-DEBUGGABLE", title="App is not debuggable",
                            masvs_category=MasvsCategory.RESILIENCE, result=CheckOutcome.PASSED)
        if app.get(a("debuggable")) == "true":
            f = Finding(
                rule_id="MANIFEST-DEBUGGABLE",
                title="Application is debuggable",
                description='android:debuggable="true" is set in the release manifest.',
                severity=Severity.HIGH, base_severity=Severity.HIGH, confidence=Confidence.HIGH,
                masvs_category=MasvsCategory.RESILIENCE, cwe="CWE-489", source=Source.MANIFEST,
                locations=[self._location(app, max_lines=3)],
                impact="Anyone with ADB access can attach a debugger, run code as the app (run-as) "
                       "and read its private files.",
                remediation='Remove android:debuggable or set it to "false" for release builds.',
                how_to_verify=f"adb shell run-as {self.package} ls -la\n"
                              "If the app's private files are listed, the build is debuggable.",
                references=[MASVS_URL],
            )
            result.findings.append(f)
            check.result, check.finding_ids = CheckOutcome.FINDING, [f.id]
        result.checks.append(check)

    def _check_allow_backup(self, app, result: ManifestAnalysis) -> None:
        check = CheckResult(check_id="MANIFEST-ALLOW-BACKUP", title="App data backup is restricted",
                            masvs_category=MasvsCategory.STORAGE, result=CheckOutcome.PASSED)
        value = app.get(a("allowBackup"))
        if value == "false":
            check.details = 'android:allowBackup="false"'
        else:
            explicit = value == "true"
            has_rules = app.get(a("fullBackupContent")) or app.get(a("dataExtractionRules"))
            details = ('android:allowBackup="true" is set explicitly.' if explicit
                       else "android:allowBackup is not set, so it defaults to true.")
            if has_rules:
                details += " Backup rules (fullBackupContent/dataExtractionRules) exist; review what they exclude."
            f = Finding(
                rule_id="MANIFEST-ALLOW-BACKUP",
                title="Application data can be backed up",
                description=details,
                severity=Severity.LOW, base_severity=Severity.LOW,
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                masvs_category=MasvsCategory.STORAGE, cwe="CWE-530", source=Source.MANIFEST,
                locations=[self._location(app, max_lines=3)],
                impact="Private app data (shared prefs, databases) may be extracted through backups. "
                       "Requires physical/ADB access, so likelihood is low.",
                remediation='Set android:allowBackup="false", or define backup rules that exclude sensitive files.',
                how_to_verify=f"adb backup -f app.ab {self.package}   (works for targetSdk < 31; "
                              "then extract app.ab with android-backup-extractor and inspect shared_prefs/ and databases/)",
                references=[MASVS_URL],
            )
            result.findings.append(f)
            check.result, check.finding_ids, check.details = CheckOutcome.FINDING, [f.id], details
        result.checks.append(check)

    def _check_cleartext(self, app, result: ManifestAnalysis) -> None:
        check = CheckResult(check_id="MANIFEST-CLEARTEXT", title="Cleartext traffic disabled in manifest",
                            masvs_category=MasvsCategory.NETWORK, result=CheckOutcome.PASSED)
        value = app.get(a("usesCleartextTraffic"))
        has_nsc = app.get(a("networkSecurityConfig")) is not None

        if has_nsc and value is None:
            check.result = CheckOutcome.NOT_APPLICABLE
            check.details = "A Network Security Config is defined; it is analyzed by the network_config analyzer."
        elif value == "true" or (value is None and self.target_sdk is not None and self.target_sdk < 28):
            explicit = value == "true"
            desc = ('android:usesCleartextTraffic="true" is set.' if explicit else
                    f"usesCleartextTraffic is not set and targetSdk is {self.target_sdk} (< 28), "
                    "so cleartext HTTP is allowed by default.")
            f = Finding(
                rule_id="MANIFEST-CLEARTEXT",
                title="Cleartext (HTTP) traffic is allowed",
                description=desc,
                severity=Severity.MEDIUM, base_severity=Severity.MEDIUM,
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                masvs_category=MasvsCategory.NETWORK, cwe="CWE-319", source=Source.MANIFEST,
                locations=[self._location(app, max_lines=3)],
                impact="Traffic sent over HTTP can be read or modified by an attacker on the same network.",
                remediation="Disable cleartext traffic and use HTTPS everywhere.",
                references=[MASVS_URL],
            )
            result.findings.append(f)
            check.result, check.finding_ids, check.details = CheckOutcome.FINDING, [f.id], desc
        result.checks.append(check)

    def _is_exported(self, elem, kind: str) -> tuple[bool, str]:
        """Apply Android's export rules and return (exported, explanation)."""
        value = elem.get(a("exported"))
        has_filter = elem.find("intent-filter") is not None
        if value == "true":
            return True, 'android:exported="true"'
        if value == "false":
            return False, 'android:exported="false"'
        if kind == "provider":
            # Providers were exported by default when targetSdk <= 16.
            if self.target_sdk is not None and self.target_sdk <= 16:
                return True, "provider without exported attribute and targetSdk <= 16 (exported by default)"
            return False, "provider without exported attribute (not exported by default)"
        if has_filter:
            # Before Android 12 (targetSdk 31) an intent-filter implied exported=true.
            return True, "no exported attribute but has an intent-filter (implicitly exported)"
        return False, "no exported attribute and no intent-filter"

    def _protection(self, elem, app, kind: str) -> tuple[str, str | None]:
        """Return ('none' | 'weak' | 'strong', permission_name)."""
        perm = elem.get(a("permission")) or app.get(a("permission"))
        if kind == "provider" and not perm:
            read, write = elem.get(a("readPermission")), elem.get(a("writePermission"))
            if read and write:
                perm = f"{read} / {write}"
            elif read or write:
                return "weak", read or write  # only one direction is protected
        if not perm:
            return "none", None
        level = self.custom_permissions.get(perm)
        if level is None:
            return "strong", perm  # system or platform permission
        if "signature" in level:
            return "strong", perm
        return "weak", perm  # custom permission with normal/dangerous level: any app can request it

    def _check_components(self, app, result: ManifestAnalysis) -> None:
        for kind, label in [("activity", "activity"), ("activity-alias", "activity alias"),
                            ("service", "service"), ("receiver", "broadcast receiver"),
                            ("provider", "content provider")]:
            check = CheckResult(
                check_id=f"MANIFEST-EXPORTED-{kind.upper()}",
                title=f"Exported {label}s are protected",
                masvs_category=MasvsCategory.PLATFORM,
                result=CheckOutcome.PASSED,
            )
            elems = app.findall(kind)
            if not elems:
                check.result, check.details = CheckOutcome.NOT_APPLICABLE, f"No {label} declared"
                result.checks.append(check)
                continue

            for elem in elems:
                exported, why = self._is_exported(elem, kind)
                if not exported or _is_launcher(elem):
                    continue  # launcher activity must be exported by design
                protection, perm = self._protection(elem, app, kind)
                if protection == "strong":
                    continue

                name = self._full_name(elem.get(a("name"), "?"))
                base = COMPONENT_SEVERITY[kind]
                desc = [f"{name} is exported ({why})"]
                desc.append("and requires no permission." if protection == "none" else
                            f"and is protected only by '{perm}', which any app can request (protectionLevel not signature).")
                deep = _deep_link_info(elem)
                if deep:
                    desc.append(f"It handles URIs: {deep}.")
                if kind == "provider" and elem.get(a("grantUriPermissions")) == "true":
                    desc.append("grantUriPermissions is enabled.")

                f = Finding(
                    rule_id=f"MANIFEST-EXPORTED-{kind.upper()}",
                    title=f"Exported {label} without proper protection: {name.split('.')[-1]}",
                    description=" ".join(desc),
                    severity=base, base_severity=base,
                    confidence=Confidence.HIGH,
                    masvs_category=MasvsCategory.PLATFORM, cwe="CWE-926", source=Source.MANIFEST,
                    locations=[self._location(elem)],
                    impact=_component_impact(kind),
                    remediation=f'Set android:exported="false" if other apps do not need this {label}; '
                                "otherwise protect it with a signature-level permission and validate all input.",
                    how_to_verify=_component_verify(kind, self.package, name, elem.get(a("authorities"))),
                    component=name,
                    references=[MASVS_PLATFORM_1],
                )
                if _is_browsable(elem):
                    f.adjust_severity(base.raise_by(1),
                                      "Reachable from a web page (BROWSABLE intent-filter), so remote input is possible.")
                result.findings.append(f)
                check.finding_ids.append(f.id)

            if check.finding_ids:
                check.result = CheckOutcome.FINDING
                check.details = f"{len(check.finding_ids)} unprotected exported {label}(s)"
            result.checks.append(check)

    def _check_min_sdk(self, root, result: ManifestAnalysis) -> None:
        check = CheckResult(check_id="MANIFEST-MIN-SDK", title="Minimum SDK is reasonably recent",
                            masvs_category=MasvsCategory.CODE, result=CheckOutcome.PASSED)
        if self.min_sdk is None:
            check.result, check.details = CheckOutcome.ERROR, "minSdkVersion could not be determined"
        elif self.min_sdk < 23:
            yml = self.root_dir / "apktool.yml"
            loc_file = "apktool.yml" if yml.is_file() else "AndroidManifest.xml"
            snippet = _find_line(yml, "minSdkVersion") if yml.is_file() else None
            f = Finding(
                rule_id="MANIFEST-MIN-SDK",
                title=f"App supports outdated Android versions (minSdk {self.min_sdk})",
                description=f"minSdkVersion is {self.min_sdk}. Android versions below 6.0 (API 23) "
                            "no longer receive security updates and lack runtime permissions.",
                severity=Severity.LOW, base_severity=Severity.LOW, confidence=Confidence.HIGH,
                masvs_category=MasvsCategory.CODE, cwe="CWE-1104", source=Source.MANIFEST,
                locations=[Location(file=loc_file, line=snippet[0] if snippet else None,
                                    snippet=snippet[1] if snippet else f"minSdkVersion: {self.min_sdk}")],
                impact="Users on old devices are exposed to known, unpatched platform vulnerabilities.",
                remediation="Raise minSdkVersion to a supported Android version (23 or higher).",
                references=[MASVS_URL],
            )
            result.findings.append(f)
            check.result, check.finding_ids = CheckOutcome.FINDING, [f.id]
        result.checks.append(check)

    def _check_dangerous_permissions(self, root, result: ManifestAnalysis) -> None:
        found = []
        for p in root.findall("uses-permission"):
            name = p.get(a("name"), "")
            if name.startswith("android.permission.") and name.split(".")[-1] in DANGEROUS_PERMISSIONS:
                found.append((name.split(".")[-1], p))
        check = CheckResult(check_id="MANIFEST-DANGEROUS-PERMISSIONS", title="Dangerous permissions requested",
                            masvs_category=MasvsCategory.PRIVACY, result=CheckOutcome.PASSED)
        if found:
            f = Finding(
                rule_id="MANIFEST-DANGEROUS-PERMISSIONS",
                title=f"App requests {len(found)} dangerous permission(s)",
                description="Requested: " + ", ".join(n for n, _ in found) +
                            ". Review whether each is needed for the app's features.",
                severity=Severity.INFO, base_severity=Severity.INFO, confidence=Confidence.HIGH,
                masvs_category=MasvsCategory.PRIVACY, source=Source.MANIFEST,
                locations=[self._location(el, max_lines=1) for _, el in found],
                impact="Unneeded permissions increase the data exposed if the app is compromised.",
                remediation="Remove permissions that are not required.",
                references=[MASVS_URL],
            )
            result.findings.append(f)
            check.result, check.finding_ids, check.details = CheckOutcome.FINDING, [f.id], f.description
        result.checks.append(check)


# ---------------------------------------------------------------------- module helpers

def _to_int(value) -> int | None:
    try:
        return int(str(value).strip("'\""))
    except (TypeError, ValueError):
        return None


def _filters(elem):
    return elem.findall("intent-filter")


def _is_launcher(elem) -> bool:
    for f in _filters(elem):
        actions = {x.get(a("name")) for x in f.findall("action")}
        cats = {x.get(a("name")) for x in f.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
            return True
    return False


def _is_browsable(elem) -> bool:
    return any(c.get(a("name")) == "android.intent.category.BROWSABLE"
               for f in _filters(elem) for c in f.findall("category"))


def _deep_link_info(elem) -> str:
    uris = []
    for f in _filters(elem):
        for d in f.findall("data"):
            scheme, host = d.get(a("scheme")), d.get(a("host"))
            if scheme:
                uris.append(f"{scheme}://{host or '*'}{d.get(a('path')) or d.get(a('pathPrefix')) or ''}")
    return ", ".join(sorted(set(uris)))


def _component_impact(kind: str) -> str:
    return {
        "activity": "Any installed app can start this screen directly, possibly bypassing "
                    "authentication or passing malicious Intent data.",
        "activity-alias": "Any installed app can start the target activity through this alias.",
        "service": "Any installed app can start or bind to this service and trigger its actions.",
        "receiver": "Any installed app can send broadcasts to this receiver and trigger its logic.",
        "provider": "Any installed app may query or modify the provider's data "
                    "(data leakage, SQL injection, path traversal).",
    }[kind]


def _component_verify(kind: str, package: str, name: str, authorities: str | None) -> str:
    short = name[len(package):] if package and name.startswith(package + ".") else name
    target = f"{package}/{short}"
    if kind in ("activity", "activity-alias"):
        return (f"adb shell am start -n {target}\n"
                "If the screen opens without login or other checks, access control is bypassed. "
                "Also try adding extras: --es key value")
    if kind == "service":
        return (f"adb shell am startservice -n {target}\n"
                "(on Android 8+ use: adb shell am start-foreground-service -n ...). "
                "Watch logcat for the service's behaviour.")
    if kind == "receiver":
        return (f"adb shell am broadcast -n {target}\n"
                "Add extras the receiver reads (see its onReceive in JADX), e.g. --es phone 123")
    auth = (authorities or "<authority>").split(";")[0]
    return (f"adb shell content query --uri content://{auth}/\n"
            "Try the paths used in the provider code (see its query/openFile methods in JADX).")


def _find_line(path: Path, needle: str) -> tuple[int, str] | None:
    for i, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        if re.search(needle, line):
            return i, line.strip()
    return None
