"""Score scanner findings against the OWASP Benchmark answer key.

A test case counts as *flagged* when at least one finding sits in its source
file and carries a CWE that belongs to the case's category. This is the
Benchmark's own per-category scoring idea: real vulnerability flagged = TP,
fake vulnerability flagged = FP, and so on.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from pydantic import BaseModel

from sentinel.bench.data import BenchmarkCase
from sentinel.core.models import Finding

# CWEs accepted per Benchmark category. Each category's own CWE is always
# accepted; aliases cover rule sets that tag the same weakness differently.
# GitLab's WeakMessageDigest rule is tagged CWE-327 while the Benchmark's hash
# category is CWE-328, so 327 is accepted for "hash".
CATEGORY_ALIASES: dict[str, set[int]] = {"hash": {327}}


class Counts(BaseModel):
    """Confusion counts and derived metrics for one group of test cases."""

    category: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def real(self) -> int:
        return self.tp + self.fn

    @property
    def fake(self) -> int:
        return self.fp + self.tn

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / self.real if self.real else None

    @property
    def fpr(self) -> float | None:
        return self.fp / self.fake if self.fake else None

    @property
    def youden(self) -> float | None:
        """Benchmark score: true positive rate minus false positive rate."""
        if self.recall is None or self.fpr is None:
            return None
        return self.recall - self.fpr


def case_id(file: str) -> str:
    """BenchmarkTest00001 from any path ending in BenchmarkTest00001.java."""
    return PurePosixPath(file.replace("\\", "/")).stem


def accepted_cwes(case: BenchmarkCase) -> set[int]:
    return {case.cwe} | CATEGORY_ALIASES.get(case.category, set())


def flagged_ids(
    cases: Iterable[BenchmarkCase], findings: Iterable[Finding]
) -> set[str]:
    """Test ids that have a finding in their file with an accepted CWE."""
    by_id = {c.test_id: c for c in cases}
    flagged: set[str] = set()
    for f in findings:
        case = by_id.get(case_id(f.file))
        if case and accepted_cwes(case) & set(f.cwes):
            flagged.add(case.test_id)
    return flagged


def score(
    cases: list[BenchmarkCase],
    findings: Iterable[Finding],
    only_ids: set[str] | None = None,
) -> list[Counts]:
    """Per-category counts plus an 'overall' row, optionally on a subset."""
    flagged = flagged_ids(cases, findings)
    rows: dict[str, Counts] = {}
    for c in cases:
        if only_ids is not None and c.test_id not in only_ids:
            continue
        row = rows.setdefault(c.category, Counts(category=c.category))
        hit = c.test_id in flagged
        if c.is_real:
            row.tp += hit
            row.fn += not hit
        else:
            row.fp += hit
            row.tn += not hit
    out = [rows[k] for k in sorted(rows)]
    total = Counts(category="overall")
    for r in out:
        total.tp, total.fp = total.tp + r.tp, total.fp + r.fp
        total.tn, total.fn = total.tn + r.tn, total.fn + r.fn
    return [*out, total]
