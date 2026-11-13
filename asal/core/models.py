"""Core data models for ASAL.

Every analyzer produces the same objects defined here, so the
correlation layer, the UI and the reports never need to know which
analyzer a result came from. This file is the single source of truth.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Risk level, derived from Likelihood x Impact (see docs/methodology.md)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank so severities can be sorted and compared (higher = worse)."""
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def raise_by(self, steps: int = 1) -> "Severity":
        """Return the severity `steps` levels higher, capped at CRITICAL."""
        order = sorted(Severity, key=lambda s: s.rank)
        return order[min(self.rank + steps, len(order) - 1)]

    def lower_by(self, steps: int = 1) -> "Severity":
        """Return the severity `steps` levels lower, floored at INFO."""
        order = sorted(Severity, key=lambda s: s.rank)
        return order[max(self.rank - steps, 0)]


class Confidence(str, Enum):
    """How likely the automated detection is a true positive."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(str, Enum):
    """Analyst review state. Every automated finding starts as AUTO."""

    AUTO = "auto"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"


class Origin(str, Enum):
    """Where the vulnerable code lives."""

    APP = "app"
    LIBRARY = "library"


class Source(str, Enum):
    """Which analyzer produced the finding."""

    MANIFEST = "manifest"
    CODE_RULE = "code_rule"
    RESOURCE = "resource"
    NETWORK_CONFIG = "network_config"


class MasvsCategory(str, Enum):
    """OWASP MASVS v2 control groups."""

    STORAGE = "MASVS-STORAGE"
    CRYPTO = "MASVS-CRYPTO"
    AUTH = "MASVS-AUTH"
    NETWORK = "MASVS-NETWORK"
    PLATFORM = "MASVS-PLATFORM"
    CODE = "MASVS-CODE"
    RESILIENCE = "MASVS-RESILIENCE"
    PRIVACY = "MASVS-PRIVACY"


class CheckOutcome(str, Enum):
    """Result of a single check, used for the coverage view."""

    FINDING = "finding"
    PASSED = "passed"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Location(BaseModel):
    """One piece of evidence: where the issue is and what the code looks like."""

    file: str = Field(..., description="Path relative to the decompiled output root")
    line: int | None = Field(None, ge=1, description="1-based line of the matched code")
    snippet: str = Field(..., min_length=1, description="Matched line plus surrounding context")
    snippet_start_line: int | None = Field(
        None, ge=1, description="Line number of the first line in `snippet` (for highlighting)"
    )

    def key(self) -> str:
        """Stable identifier for this location, used for de-duplication."""
        return f"{self.file}:{self.line}"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A potential vulnerability backed by evidence.

    `severity` is the final value after context adjustment;
    `base_severity` is the rule's default. If they differ,
    `severity_reason` must explain why.
    """

    id: str = ""
    rule_id: str
    title: str
    description: str

    severity: Severity
    base_severity: Severity
    severity_reason: str | None = None
    confidence: Confidence

    masvs_category: MasvsCategory
    mastg_test_id: str | None = None
    cwe: str | None = None

    origin: Origin = Origin.APP
    source: Source
    component: str | None = Field(None, description="Affected Android component, e.g. com.app.LoginActivity")
    locations: list[Location] = Field(..., min_length=1)

    impact: str
    remediation: str
    how_to_verify: str | None = Field(
        None, description="Manual verification steps for the analyst (e.g. adb commands)"
    )
    references: list[str] = Field(default_factory=list)

    status: Status = Status.AUTO
    verification_notes: str | None = None

    @field_validator("cwe")
    @classmethod
    def _cwe_format(cls, v: str | None) -> str | None:
        if v is not None and not v.upper().startswith("CWE-"):
            raise ValueError("cwe must look like 'CWE-312'")
        return v.upper() if v else v

    def model_post_init(self, __context: object) -> None:
        if not self.id:
            self.id = self.compute_id()
        if self.severity != self.base_severity and not self.severity_reason:
            raise ValueError(
                f"{self.rule_id}: severity changed from {self.base_severity.value} "
                f"to {self.severity.value} without a severity_reason"
            )

    def compute_id(self) -> str:
        """Deterministic ID from rule + sorted locations.

        Re-scanning the same APK gives the same IDs, so analyst
        review decisions (verified / false_positive) can be carried over.
        """
        keys = "|".join(sorted(loc.key() for loc in self.locations))
        digest = hashlib.sha256(f"{self.rule_id}|{keys}".encode()).hexdigest()[:12]
        return f"{self.rule_id}-{digest}"

    def adjust_severity(self, new: Severity, reason: str) -> None:
        """Change severity from context, always recording why."""
        if new != self.severity:
            self.severity = new
            self.severity_reason = reason

    def set_status(self, status: Status, notes: str | None = None) -> None:
        """Record the analyst's decision. Verified / FP require notes as evidence."""
        if status != Status.AUTO and not (notes and notes.strip()):
            raise ValueError("verification_notes are required when verifying or rejecting a finding")
        self.status = status
        self.verification_notes = notes


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

class CheckResult(BaseModel):
    """Outcome of one check, so the report shows what was tested, not only what failed."""

    check_id: str
    title: str
    masvs_category: MasvsCategory
    result: CheckOutcome
    details: str = ""
    finding_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scan container
# ---------------------------------------------------------------------------

class AppInfo(BaseModel):
    """Basic metadata about the analysed APK."""

    file_name: str
    sha256: str
    size_bytes: int
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None


class ScanResult(BaseModel):
    """Everything one scan produces. Serialized as the JSON report."""

    tool_version: str = "0.1.0"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    app: AppInfo
    findings: list[Finding] = Field(default_factory=list)
    checks: list[CheckResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list, description="Non-fatal problems, e.g. a tool timed out")
    partial: bool = Field(False, description="True if some analyzers failed and results are incomplete")

    def count_by_severity(self, origin: Origin | None = None) -> dict[str, int]:
        counts = {s.value: 0 for s in sorted(Severity, key=lambda s: -s.rank)}
        for f in self.findings:
            if origin is None or f.origin == origin:
                counts[f.severity.value] += 1
        return counts

    def count_by_status(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Status}
        for f in self.findings:
            counts[f.status.value] += 1
        return counts
