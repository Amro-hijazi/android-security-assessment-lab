"""Context-aware severity for exported components.

The manifest tells us a component is reachable by other apps; the code
tells us whether it actually consumes attacker-controlled input.
An exported component that reads Intent data is a real attack surface,
so its severity is raised one level and the reading line is added as
evidence. We never LOWER severity here: an exported screen with no
input can still bypass authentication (e.g. opening a protected screen).
"""

from __future__ import annotations

import re
from pathlib import Path

from asal.core.models import Finding, Location

INPUT_PATTERN = re.compile(
    r"getIntent\(\)"
    r"|\.get(String|Int|Long|Boolean|Parcelable|Serializable|Bundle|CharSequence)(ArrayList)?Extra\("
    r"|\.getExtras\(\)"
    r"|\.getData\(\)"
    r"|\.getQueryParameter\("
)

COMPONENT_RULES = {
    "MANIFEST-EXPORTED-ACTIVITY", "MANIFEST-EXPORTED-ACTIVITY-ALIAS",
    "MANIFEST-EXPORTED-SERVICE", "MANIFEST-EXPORTED-RECEIVER",
}


def component_source(sources_dir: Path, component: str) -> Path | None:
    """com.app.ui.LoginActivity -> sources/com/app/ui/LoginActivity.java"""
    outer = component.split("$")[0]
    path = sources_dir / (outer.replace(".", "/") + ".java")
    return path if path.is_file() else None


def apply_component_context(findings: list[Finding], sources_dir: Path | None) -> None:
    if sources_dir is None or not sources_dir.is_dir():
        return
    for f in findings:
        if f.rule_id not in COMPONENT_RULES or not f.component:
            continue
        src = component_source(sources_dir, f.component)
        if src is None:
            f.description += " (Source file not found in JADX output, so input handling was not checked.)"
            continue
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, start=1):
            if INPUT_PATTERN.search(line):
                rel = src.relative_to(sources_dir).as_posix()
                start = max(1, i - 2)
                f.locations.append(Location(file=f"sources/{rel}", line=i,
                                            snippet="\n".join(lines[start - 1:i + 2]), snippet_start_line=start))
                f.adjust_severity(f.severity.raise_by(1),
                                  f"Exported and reads Intent input in code ({rel}:{i}); "
                                  "other apps can send attacker-controlled data.")
                break
        else:
            f.description += f" No Intent input reading was found in {src.name}."
