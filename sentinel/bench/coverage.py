"""Which Benchmark categories and OWASP Top 10 2025 categories are measured.

A category is "Not covered" when there is no ground truth for it. A Benchmark
category is "No rule coverage" when the rule set never flags it (no finding
with an accepted CWE anywhere in that category, real or fake).
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinel.bench.data import BenchmarkCase
from sentinel.bench.metrics import accepted_cwes, case_id
from sentinel.core.models import Finding
from sentinel.core.owasp_map import categories, map_cwes


def uncovered_benchmark_categories(
    cases: list[BenchmarkCase], findings: Iterable[Finding]
) -> list[str]:
    """Benchmark categories where the rules raised no matching finding at all."""
    by_id = {c.test_id: c for c in cases}
    seen: set[str] = set()
    for f in findings:
        case = by_id.get(case_id(f.file))
        if case and accepted_cwes(case) & set(f.cwes):
            seen.add(case.category)
    return sorted({c.category for c in cases} - seen)


def owasp_coverage(cases: list[BenchmarkCase]) -> dict[str, dict]:
    """OWASP 2025 id -> {name, status, cases, source}. Measured iff cases exist."""
    counts: dict[str, int] = {}
    for c in cases:
        for cat in map_cwes([c.cwe]):
            counts[cat] = counts.get(cat, 0) + 1
    return {
        cat: {
            "name": name,
            "status": "Measured" if counts.get(cat) else "Not covered",
            "cases": counts.get(cat, 0),
            "source": "OWASP Benchmark v1.2" if counts.get(cat) else "",
        }
        for cat, name in categories().items()
    }
