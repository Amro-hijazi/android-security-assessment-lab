"""YAML rule engine for decompiled Java code.

Flow:
  1. Load and validate every rule in asal/rules/*.yaml (bad rules fail loudly).
  2. Walk JADX's sources/ folder, skipping well-known libraries by default.
  3. Run each rule's regexes on each file; drop hits whose line matches an exclude pattern.
  4. Emit one raw Finding per hit (grouping happens later in the correlation layer)
     and one CheckResult per rule for the coverage view.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from asal.core.models import (
    CheckOutcome, CheckResult, Confidence, Finding, Location, MasvsCategory,
    Origin, Severity, Source,
)

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
MAX_FILE_SIZE = 2 * 1024 * 1024   # skip huge generated files
MAX_LINE_LEN = 300                # keep snippets readable when code is minified
CONTEXT_LINES = 2

# Package prefixes of common third-party/platform libraries (as folder paths).
KNOWN_LIBRARY_PREFIXES = (
    "android/", "androidx/", "com/google/", "kotlin/", "kotlinx/", "okhttp3/", "okio/",
    "retrofit2/", "com/squareup/", "io/reactivex/", "com/facebook/", "org/apache/",
    "org/json/", "javax/", "dagger/", "com/bumptech/", "io/flutter/", "org/intellij/",
    "org/jetbrains/", "com/fasterxml/", "io/grpc/", "com/airbnb/",
)


class Rule(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    masvs: MasvsCategory
    cwe: str | None = None
    patterns: list[str] = Field(..., min_length=1)
    exclude_patterns: list[str] = Field(default_factory=list)
    impact: str
    remediation: str
    how_to_verify: str | None = None
    references: list[str] = Field(default_factory=list)

    @field_validator("patterns", "exclude_patterns")
    @classmethod
    def _valid_regex(cls, v: list[str]) -> list[str]:
        for p in v:
            re.compile(p)  # raises re.error with a clear message if a rule is broken
        return v

    def compiled(self) -> tuple[list[re.Pattern], list[re.Pattern]]:
        return [re.compile(p) for p in self.patterns], [re.compile(p) for p in self.exclude_patterns]


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for raw in data:
            rules.append(Rule(**raw))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Duplicate rule ids: {dupes}")
    return rules


@dataclass
class CodeAnalysis:
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped_library: int = 0


def classify_origin(rel_path: str, package: str | None) -> Origin:
    """APP if the file is under the app's package, otherwise LIBRARY."""
    if package and rel_path.startswith(package.replace(".", "/") + "/"):
        return Origin.APP
    return Origin.LIBRARY


def is_known_library(rel_path: str) -> bool:
    return rel_path.startswith(KNOWN_LIBRARY_PREFIXES)


def _snippet(lines: list[str], line_no: int) -> tuple[str, int]:
    start = max(1, line_no - CONTEXT_LINES)
    end = min(len(lines), line_no + CONTEXT_LINES)
    text = "\n".join(l if len(l) <= MAX_LINE_LEN else l[:MAX_LINE_LEN] + " ..." for l in lines[start - 1:end])
    return text, start


class CodeRuleEngine:
    def __init__(self, sources_dir: Path, package: str | None, rules: list[Rule] | None = None,
                 include_libraries: bool = False):
        self.sources_dir = Path(sources_dir)
        self.package = package
        self.rules = rules if rules is not None else load_rules()
        self.include_libraries = include_libraries

    def _iter_files(self, result: CodeAnalysis):
        for path in sorted(self.sources_dir.rglob("*.java")):
            rel = path.relative_to(self.sources_dir).as_posix()
            if rel.endswith(("/R.java", "/BuildConfig.java")) or "/R$" in rel:
                continue
            if not self.include_libraries and is_known_library(rel):
                result.files_skipped_library += 1
                continue
            if path.stat().st_size > MAX_FILE_SIZE:
                log.warning("Skipping large file %s", rel)
                continue
            yield path, rel

    def analyze(self) -> CodeAnalysis:
        result = CodeAnalysis()
        compiled = {r.id: r.compiled() for r in self.rules}
        hits: dict[str, list[Finding]] = {r.id: [] for r in self.rules}

        for path, rel in self._iter_files(result):
            result.files_scanned += 1
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            origin = classify_origin(rel, self.package)

            for rule in self.rules:
                patterns, excludes = compiled[rule.id]
                seen_lines: set[int] = set()
                for pattern in patterns:
                    for m in pattern.finditer(text):
                        line_no = text.count("\n", 0, m.start()) + 1
                        if line_no in seen_lines:
                            continue
                        line_text = lines[line_no - 1] if line_no <= len(lines) else ""
                        if any(x.search(line_text) for x in excludes):
                            continue
                        seen_lines.add(line_no)
                        snippet, start = _snippet(lines, line_no)
                        hits[rule.id].append(self._finding(rule, rel, line_no, snippet, start, origin))

        for rule in self.rules:
            rule_hits = hits[rule.id]
            result.findings += rule_hits
            result.checks.append(CheckResult(
                check_id=rule.id, title=rule.title, masvs_category=rule.masvs,
                result=CheckOutcome.FINDING if rule_hits else CheckOutcome.PASSED,
                details=f"{len(rule_hits)} match(es)" if rule_hits else f"No match in {result.files_scanned} files",
                finding_ids=[f.id for f in rule_hits],
            ))
        log.info("Code rules: %d files scanned, %d library files skipped, %d raw hits",
                 result.files_scanned, result.files_skipped_library, len(result.findings))
        return result

    @staticmethod
    def _finding(rule: Rule, rel: str, line: int, snippet: str, start: int, origin: Origin) -> Finding:
        return Finding(
            rule_id=rule.id, title=rule.title, description=rule.description,
            severity=rule.severity, base_severity=rule.severity, confidence=rule.confidence,
            masvs_category=rule.masvs, cwe=rule.cwe, origin=origin, source=Source.CODE_RULE,
            locations=[Location(file=f"sources/{rel}", line=line, snippet=snippet, snippet_start_line=start)],
            impact=rule.impact, remediation=rule.remediation, how_to_verify=rule.how_to_verify,
            references=rule.references,
        )
