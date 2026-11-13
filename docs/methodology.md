# Methodology

## 1. Workflow

1. **Validate**: the APK is opened as a ZIP only. Size, structure, `AndroidManifest.xml`, `classes*.dex` and Zip Slip paths are checked. The APK is never installed or executed.
2. **Decompile**: APKTool (manifest + resources, `--no-src`) and JADX (Java sources, `--no-res`), each with a timeout.
3. **Analyze**: manifest analyzer, Network Security Config analyzer, YAML code rules.
4. **Correlate**: classify origin (app vs library), raise severity from context, group repeated hits.
5. **Review**: every finding starts as `auto`. The analyst verifies it manually (the finding includes *How to verify*) and marks it `verified` or `false_positive` **with notes**.
6. **Report**: HTML + JSON, including review decisions.

## 2. Severity: Likelihood × Impact

| Likelihood \ Impact | Low | Medium | High |
|---|---|---|---|
| **High** (any app / remote, no preconditions) | Medium | High | Critical |
| **Medium** (another installed app, or local network) | Low | Medium | High |
| **Low** (physical/ADB access, rooted device, user action) | Info | Low | Medium |

### Base severity per check

| Check | Severity | Justification |
|---|---|---|
| TLS validation disabled (`CODE-TRUST-ALL-CERTS`) | Critical | Network attacker (high likelihood) reads/modifies all HTTPS traffic (high impact). |
| Debuggable app | High | Anyone with ADB can run code as the app and read its sandbox. |
| Exported content provider without permission | High | Any installed app can query/modify data directly. |
| Hardcoded secret, hardcoded key/IV, weak cipher, SQL injection, JS bridge, world-readable file, command execution | High | Direct compromise of data or credentials once the precondition is met. |
| Exported activity / service / receiver without permission | Medium | Needs a malicious app on the device; impact depends on what the component does. |
| Cleartext traffic, user CA trusted, weak hash, WebView JS / file access, sensitive logs, sensitive SharedPreferences, external storage | Medium | Requires network position, local access or a second weakness. |
| Backup allowed, minSdk < 23, temp files, insecure random, clipboard | Low | Requires physical/ADB access or specific usage. |
| Dangerous permissions requested | Info | Privacy review item, not a vulnerability by itself. |

### Context adjustments (always recorded in `severity_reason`)

| Condition | Change | Reason |
|---|---|---|
| Exported activity/service/receiver **reads Intent data** (`getIntent()`, `get*Extra`, `getData()` …) | +1 level | Another app controls the input the component processes. |
| Exported activity has a **BROWSABLE** intent-filter | +1 level | Reachable from a web page, so remote input is possible. |

Severity is **never lowered automatically**: an exported screen with no input can still bypass authentication.

## 3. Confidence

- **High**: the pattern is unambiguous (e.g. `android:debuggable="true"`, empty `checkServerTrusted`).
- **Medium**: usually a real issue but context matters (e.g. a hardcoded string named `password`).
- **Low**: often legitimate (e.g. `new Random()` for UI, `Runtime.exec("su")` in a root check). Needs review.

## 4. Status

| Status | Meaning |
|---|---|
| `auto` | Reported by a rule, not reviewed. Potential issue only. |
| `verified` | Confirmed manually by the analyst; notes describe how (command, screenshot). |
| `false_positive` | Reviewed and rejected; notes describe why. |

## 5. Standards mapping

Findings map to **OWASP MASVS v2** control groups (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY) and to **CWE**. Rule references link to the relevant MASVS control page.
