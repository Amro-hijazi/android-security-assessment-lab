"""Validate an APK before any tool touches it.

We never install or execute the APK. This module only reads it as a
ZIP archive to make sure it looks like a real Android package and is
not crafted to attack the decompilers (e.g. Zip Slip paths).
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_APK_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_ENTRIES = 50_000              # protects against zip bombs with huge entry counts


class ApkValidationError(Exception):
    """Raised when a file is not a safe, valid APK."""


@dataclass
class LoadedApk:
    path: Path
    sha256: str
    size_bytes: int
    dex_files: list[str]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_unsafe_entry(name: str) -> bool:
    """True if a ZIP entry could escape the extraction folder (Zip Slip)."""
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    return (
        normalized.startswith("/")
        or (len(normalized) > 1 and normalized[1] == ":")  # Windows drive, e.g. C:/
        or ".." in p.parts
    )


def load_apk(path: str | Path) -> LoadedApk:
    """Check the file and return basic metadata. Raises ApkValidationError on problems."""
    path = Path(path)

    if not path.is_file():
        raise ApkValidationError(f"File not found: {path}")

    size = path.stat().st_size
    if size == 0:
        raise ApkValidationError("File is empty")
    if size > MAX_APK_SIZE:
        raise ApkValidationError(f"File is larger than {MAX_APK_SIZE // (1024 * 1024)} MB")

    if not zipfile.is_zipfile(path):
        raise ApkValidationError("Not a ZIP archive, so not a valid APK")

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile as exc:
        raise ApkValidationError(f"Corrupted ZIP archive: {exc}") from exc

    if len(names) > MAX_ENTRIES:
        raise ApkValidationError(f"Too many entries in archive ({len(names)})")

    unsafe = [n for n in names if _is_unsafe_entry(n)]
    if unsafe:
        raise ApkValidationError(
            f"Archive contains unsafe paths (possible Zip Slip): {unsafe[:3]}"
        )

    if "AndroidManifest.xml" not in names:
        raise ApkValidationError("AndroidManifest.xml is missing")

    dex_files = sorted(n for n in names if PurePosixPath(n).match("classes*.dex") and "/" not in n)
    if not dex_files:
        raise ApkValidationError("No classes*.dex file found")

    return LoadedApk(path=path.resolve(), sha256=_sha256(path), size_bytes=size, dex_files=dex_files)
