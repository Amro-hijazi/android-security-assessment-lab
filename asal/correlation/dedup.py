"""Group repeated code findings.

The same rule often matches many lines (e.g. 15 Log calls). Showing 15
separate findings hides the important ones, so code-rule hits with the
same rule and origin are merged into ONE finding with many locations.
Manifest findings stay separate: each component has its own context.
"""

from __future__ import annotations

from collections import OrderedDict

from asal.core.models import CheckResult, Finding, Source

MAX_LOCATIONS = 50


def group_findings(findings: list[Finding], checks: list[CheckResult]) -> list[Finding]:
    groups: "OrderedDict[tuple, list[Finding]]" = OrderedDict()
    others: list[Finding] = []
    for f in findings:
        if f.source == Source.CODE_RULE:
            groups.setdefault((f.rule_id, f.origin), []).append(f)
        else:
            others.append(f)

    id_map: dict[str, str] = {}
    merged: list[Finding] = []
    for (_, _), items in groups.items():
        first = items[0]
        if len(items) == 1:
            merged.append(first)
            continue
        locations = [loc for f in items for loc in f.locations]
        files = {loc.file for loc in locations}
        extra = len(locations) - MAX_LOCATIONS
        g = first.model_copy(deep=True, update={
            "id": "",
            "title": f"{first.title} ({len(locations)} locations)",
            "description": f"{first.description} Found {len(locations)} times in {len(files)} file(s)"
                           + (f"; showing the first {MAX_LOCATIONS}." if extra > 0 else "."),
            "locations": locations[:MAX_LOCATIONS],
            "severity": max((f.severity for f in items), key=lambda s: s.rank),
        })
        g.id = g.compute_id()
        for f in items:
            id_map[f.id] = g.id
        merged.append(g)

    for c in checks:
        if c.finding_ids:
            c.finding_ids = list(dict.fromkeys(id_map.get(i, i) for i in c.finding_ids))
    return others + merged
