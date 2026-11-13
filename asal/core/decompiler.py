"""Run APKTool and JADX safely.

- Tools are located on PATH (or via ASAL_APKTOOL / ASAL_JADX env vars).
- subprocess is always called with an argument list, never shell=True,
  so a crafted file name cannot inject shell commands.
- Every call has a timeout so a hostile or huge APK cannot hang the scan.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

APKTOOL_TIMEOUT = 300   # seconds
JADX_TIMEOUT = 900      # seconds


class ToolNotFoundError(Exception):
    pass


@dataclass
class DecompileResult:
    tool: str
    output_dir: Path
    ok: bool
    partial: bool = False
    messages: list[str] = field(default_factory=list)


def find_tool(name: str) -> str:
    """Return the full path of a tool, preferring ASAL_<NAME> env var, then PATH."""
    override = os.environ.get(f"ASAL_{name.upper()}")
    if override and Path(override).is_file():
        return override
    found = shutil.which(name)
    if not found:
        raise ToolNotFoundError(
            f"'{name}' was not found. Install it and add it to PATH, "
            f"or set the ASAL_{name.upper()} environment variable."
        )
    return found


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    log.info("Running: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _tail(text: str, lines: int = 5) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def run_apktool(apk: Path, out_dir: Path) -> DecompileResult:
    """Decode the manifest and resources. --no-src skips smali (JADX handles code)."""
    result = DecompileResult(tool="apktool", output_dir=out_dir, ok=False)
    cmd = [find_tool("apktool"), "d", "--no-src", "-f", "-o", str(out_dir), str(apk)]
    try:
        proc = _run(cmd, APKTOOL_TIMEOUT)
    except subprocess.TimeoutExpired:
        result.messages.append(f"apktool timed out after {APKTOOL_TIMEOUT}s")
        return result

    manifest = out_dir / "AndroidManifest.xml"
    result.ok = proc.returncode == 0 and manifest.is_file()
    if not result.ok:
        result.messages.append(f"apktool failed (exit {proc.returncode}): {_tail(proc.stderr or proc.stdout)}")
    return result


def run_jadx(apk: Path, out_dir: Path) -> DecompileResult:
    """Decompile DEX to Java. JADX often exits non-zero when a few classes fail;
    if sources were still produced we keep them and mark the result partial."""
    result = DecompileResult(tool="jadx", output_dir=out_dir, ok=False)
    cmd = [find_tool("jadx"), "--no-res", "--threads-count", "4", "-d", str(out_dir), str(apk)]
    try:
        proc = _run(cmd, JADX_TIMEOUT)
    except subprocess.TimeoutExpired:
        result.messages.append(f"jadx timed out after {JADX_TIMEOUT}s")
        result.partial = (out_dir / "sources").is_dir()
        return result

    sources = out_dir / "sources"
    has_sources = sources.is_dir() and any(sources.rglob("*.java"))
    if proc.returncode == 0 and has_sources:
        result.ok = True
    elif has_sources:
        result.ok = True
        result.partial = True
        output = (proc.stdout or "") + (proc.stderr or "")
        match = re.search(r"finished with errors,\s*count:\s*(\d+)", output)
        total = sum(1 for _ in sources.rglob("*.java"))
        failed = f"{match.group(1)} decompilation error(s)" if match else "some decompilation errors"
        result.messages.append(
            f"jadx produced {total} Java files with {failed}; code rules may miss issues in "
            "the affected methods (see asal.log)"
        )
        log.debug("jadx output tail:\n%s", _tail(output, 20))
    else:
        result.messages.append(f"jadx failed (exit {proc.returncode}): {_tail(proc.stderr or proc.stdout)}")
    return result
