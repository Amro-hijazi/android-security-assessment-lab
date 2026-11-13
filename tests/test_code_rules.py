"""Every rule gets at least one positive (must match) and one negative (must not match) sample.
Samples are written the way JADX prints decompiled code."""

from pathlib import Path

import pytest

from asal.analyzers.code_rules import CodeRuleEngine, load_rules
from asal.core.models import CheckOutcome, Origin

RULES = {r.id: r for r in load_rules()}
PKG = "com.example.vuln"

CASES = {
    "CODE-HARDCODED-SECRET": (
        [
            'private final String aws_access_key_id = "AKIAIOSFODNN7EXAMPLE";',
            'private final String aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCY";',
            'private final String openAIApiKey = "sk-abcdefghijklmnopqrstuvwxyz123456";',
            'String password = "SuperSecret123";',
            'if (pin.equals("1234")) { unlock(); }  // password check',
        ],
        [
            'String password = editText.getText().toString();',
            'String password = "";',
            'String password_hint = "Enter your password";',
            'String apiKey = "YOUR_API_KEY";',
        ],
    ),
    "CODE-WEAK-CIPHER": (
        ['Cipher c = Cipher.getInstance("AES");', 'Cipher.getInstance("AES/ECB/PKCS5Padding")',
         'Cipher.getInstance("DES/CBC/PKCS5Padding")'],
        ['Cipher.getInstance("AES/GCM/NoPadding")', 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")'],
    ),
    "CODE-HARDCODED-KEY-IV": (
        ['new SecretKeySpec("0123456789abcdef".getBytes(), "AES")',
         'new IvParameterSpec(new byte[]{1, 2, 3, 4})'],
        ['new SecretKeySpec(keyBytes, "AES")', 'new IvParameterSpec(iv)'],
    ),
    "CODE-WEAK-HASH": (
        ['MessageDigest.getInstance("MD5").digest(bytes)', 'MessageDigest.getInstance("SHA-1")'],
        ['MessageDigest.getInstance("SHA-256")'],
    ),
    "CODE-INSECURE-RANDOM": (
        ['int otp = new Random().nextInt(9999);', 'double d = Math.random();'],
        ['new SecureRandom().nextBytes(iv);'],
    ),
    "CODE-WEBVIEW-JS-ENABLED": (
        ['webView.getSettings().setJavaScriptEnabled(true);'],
        ['webView.getSettings().setJavaScriptEnabled(false);'],
    ),
    "CODE-WEBVIEW-JS-INTERFACE": (
        ['webView.addJavascriptInterface(new Bridge(), "Android");'],
        ['webView.removeJavascriptInterface("Android");'],
    ),
    "CODE-WEBVIEW-FILE-ACCESS": (
        ['settings.setAllowUniversalAccessFromFileURLs(true);', 'settings.setAllowFileAccess(true);'],
        ['settings.setAllowFileAccess(false);'],
    ),
    "CODE-WORLD-ACCESSIBLE-FILE": (
        ['getSharedPreferences("users", 1);', 'openFileOutput("f.txt", Context.MODE_WORLD_READABLE);'],
        ['getSharedPreferences("users", 0);', 'openOrCreateDatabase("aGoat", 0, null);'],
    ),
    "CODE-EXTERNAL-STORAGE": (
        ['File f = File.createTempFile("users", "_tmp", getExternalFilesDir(null));',
         'File dir = Environment.getExternalStorageDirectory();'],
        ['File dir = getFilesDir();', 'Environment.getExternalStorageState();'],
    ),
    "CODE-SQL-INJECTION": (
        ['String qry = "SELECT * FROM users WHERE username=\'" + ((Object) username.getText()) + \'\\\'\';',
         'db.rawQuery("SELECT * FROM t WHERE id=" + id, null);',
         'db.execSQL("DELETE FROM users WHERE name=\'" + name + "\'");'],
        ['db.rawQuery("SELECT * FROM t WHERE id=?", new String[]{id});',
         'db.execSQL("CREATE TABLE IF NOT EXISTS users (ID INTEGER)");'],
    ),
    "CODE-TRUST-ALL-CERTS": (
        ['public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {\n    }',
         'public boolean verify(String hostname, SSLSession session) {\n        return true;\n    }'],
        ['public void checkServerTrusted(X509Certificate[] chain, String authType) {\n        defaultTm.checkServerTrusted(chain, authType);\n    }'],
    ),
    "CODE-SENSITIVE-LOG": (
        ['Log.d("[Info]", "Connected using Access key " + this.aws_access_key_id + " and secret key " + this.aws_secret_access_key);',
         'Log.i("Login", "password=" + pwd);'],
        ['Log.i("DOWNLOAD", "Service onCreate");'],
    ),
    "CODE-SENSITIVE-PREFS": (
        ['edit.putString("password", password.getText().toString());', 'editor1.putString("pin", hashPIN(pinValue));'],
        ['edit.putString("username", name);', 'edit.putString("score", s);'],
    ),
    "CODE-COMMAND-EXEC": (
        ['Process p = Runtime.getRuntime().exec(ip1);', 'new ProcessBuilder("ping", host).start();'],
        ['Runtime.getRuntime().availableProcessors();'],
    ),
    "CODE-CLIPBOARD": (
        ['clipboard.setPrimaryClip(ClipData.newPlainText("pwd", s));'],
        ['clipboard.getPrimaryClip();'],
    ),
    "CODE-TEMP-FILE": (
        ['File userinfo = File.createTempFile("users", "tmp", new File(dataDir));'],
        ['File f = new File(getCacheDir(), "a.txt");'],
    ),
}


def scan(tmp_path: Path, rule_id: str, code: str, rel="com/example/vuln/Sample.java", **kw):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"package x;\n\npublic class Sample {{\n    void m() {{\n        {code}\n    }}\n}}\n")
    return CodeRuleEngine(tmp_path, PKG, rules=[RULES[rule_id]], **kw).analyze()


def test_every_rule_has_test_cases():
    assert set(CASES) == set(RULES), f"Missing tests for: {set(RULES) - set(CASES)}"


@pytest.mark.parametrize("rule_id, code", [(r, c) for r, (pos, _) in CASES.items() for c in pos])
def test_positive(tmp_path, rule_id, code):
    result = scan(tmp_path, rule_id, code)
    assert result.findings, f"{rule_id} should match: {code}"
    f = result.findings[0]
    assert f.locations[0].line == 5 and code.splitlines()[0].strip()[:20] in f.locations[0].snippet
    assert f.how_to_verify


@pytest.mark.parametrize("rule_id, code", [(r, c) for r, (_, neg) in CASES.items() for c in neg])
def test_negative(tmp_path, rule_id, code):
    assert not scan(tmp_path, rule_id, code).findings, f"{rule_id} should NOT match: {code}"


def test_origin_and_library_skipping(tmp_path):
    code = 'webView.getSettings().setJavaScriptEnabled(true);'
    assert scan(tmp_path, "CODE-WEBVIEW-JS-ENABLED", code).findings[0].origin == Origin.APP
    third = scan(tmp_path, "CODE-WEBVIEW-JS-ENABLED", code, rel="com/thirdparty/Ads.java")
    assert {f.origin for f in third.findings} == {Origin.APP, Origin.LIBRARY}
    skipped = scan(tmp_path / "x", "CODE-WEBVIEW-JS-ENABLED", code, rel="androidx/webkit/W.java")
    assert not skipped.findings and skipped.files_skipped_library == 1


def test_coverage_check_per_rule(tmp_path):
    result = scan(tmp_path, "CODE-WEAK-HASH", 'MessageDigest.getInstance("SHA-256");')
    [check] = result.checks
    assert check.result == CheckOutcome.PASSED
