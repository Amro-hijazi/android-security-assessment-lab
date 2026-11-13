import zipfile

import pytest

from asal.core.apk_loader import ApkValidationError, load_apk
from asal.core.decompiler import ToolNotFoundError, find_tool


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name in entries:
            zf.writestr(name, b"x")
    return path


def test_valid_apk(tmp_path):
    apk = make_zip(tmp_path / "ok.apk", ["AndroidManifest.xml", "classes.dex", "classes2.dex"])
    loaded = load_apk(apk)
    assert loaded.dex_files == ["classes.dex", "classes2.dex"]
    assert len(loaded.sha256) == 64


@pytest.mark.parametrize("entries, message", [
    (["classes.dex"], "AndroidManifest.xml"),
    (["AndroidManifest.xml"], "classes"),
    (["AndroidManifest.xml", "classes.dex", "../../evil.sh"], "Zip Slip"),
    (["AndroidManifest.xml", "classes.dex", "/etc/evil"], "Zip Slip"),
])
def test_rejected_archives(tmp_path, entries, message):
    apk = make_zip(tmp_path / "bad.apk", entries)
    with pytest.raises(ApkValidationError, match=message):
        load_apk(apk)


def test_not_a_zip(tmp_path):
    f = tmp_path / "x.apk"
    f.write_text("hello")
    with pytest.raises(ApkValidationError, match="ZIP"):
        load_apk(f)


def test_missing_tool_has_helpful_error(monkeypatch):
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("ASAL_JADX", raising=False)
    with pytest.raises(ToolNotFoundError, match="ASAL_JADX"):
        find_tool("jadx")
