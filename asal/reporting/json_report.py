"""Save/load scan results and the analyst's review decisions.

Reviews (verified / false_positive + notes) are stored separately in
reviews.json, keyed by finding id. Because finding ids are deterministic,
re-scanning the same APK keeps the analyst's earlier decisions.
"""

from __future__ import annotations

import json
from pathlib import Path

from asal.core.models import ScanResult, Status

REPORT_NAME = "report.json"
REVIEWS_NAME = "reviews.json"


def save_report(scan: ScanResult, out_dir: Path) -> Path:
    path = Path(out_dir) / REPORT_NAME
    path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_report(out_dir: Path) -> ScanResult:
    scan = ScanResult.model_validate_json((Path(out_dir) / REPORT_NAME).read_text(encoding="utf-8"))
    apply_reviews(scan, load_reviews(out_dir))
    return scan


def load_reviews(out_dir: Path) -> dict[str, dict]:
    path = Path(out_dir) / REVIEWS_NAME
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def apply_reviews(scan: ScanResult, reviews: dict[str, dict]) -> int:
    """Apply stored decisions to matching findings. Returns how many were applied."""
    applied = 0
    for f in scan.findings:
        r = reviews.get(f.id)
        if r:
            f.status = Status(r["status"])
            f.verification_notes = r.get("notes")
            applied += 1
    return applied


def save_review(out_dir: Path, finding_id: str, status: Status, notes: str | None) -> None:
    reviews = load_reviews(out_dir)
    if status == Status.AUTO:
        reviews.pop(finding_id, None)
    else:
        reviews[finding_id] = {"status": status.value, "notes": notes}
    (Path(out_dir) / REVIEWS_NAME).write_text(json.dumps(reviews, indent=2), encoding="utf-8")
