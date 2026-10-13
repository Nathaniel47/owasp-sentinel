"""Load and validate ground-truth data for the benchmark targets (read-only)."""

from __future__ import annotations

import csv
from pathlib import Path

import yaml
from pydantic import BaseModel

TARGETS = Path(__file__).resolve().parents[2] / "targets"
BENCHMARK_CSV = "expectedresults-1.2.csv"
BENCHMARK_JAVA = "src/main/java/org/owasp/benchmark/testcode"


class BenchmarkCase(BaseModel):
    """One OWASP Benchmark test case with its official expected result."""

    test_id: str
    category: str
    is_real: bool
    cwe: int
    path: str  # relative to the Benchmark checkout


class JuiceShopChallenge(BaseModel):
    """One documented Juice Shop vulnerability challenge."""

    key: str
    name: str
    category: str
    difficulty: int
    tags: list[str] = []
    has_code_snippets: bool = False


class QualityIssue(BaseModel):
    dataset: str
    kind: str
    detail: str


def load_benchmark(
    root: Path = TARGETS / "benchmark",
) -> tuple[list[BenchmarkCase], list[QualityIssue]]:
    """Read the answer key; drop rows that cannot be used and report why."""
    cases: list[BenchmarkCase] = []
    issues: list[QualityIssue] = []
    seen: set[str] = set()
    with (root / BENCHMARK_CSV).open(encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            test_id, category, real, cwe = (c.strip() for c in row[:4])
            rel = f"{BENCHMARK_JAVA}/{test_id}.java"
            if test_id in seen:
                issues.append(
                    QualityIssue(dataset="benchmark", kind="duplicate", detail=test_id)
                )
                continue
            seen.add(test_id)
            if real not in ("true", "false") or not cwe.isdigit():
                issues.append(
                    QualityIssue(dataset="benchmark", kind="malformed", detail=test_id)
                )
                continue
            if not (root / rel).is_file():
                issues.append(
                    QualityIssue(
                        dataset="benchmark", kind="missing_source", detail=test_id
                    )
                )
                continue
            cases.append(
                BenchmarkCase(
                    test_id=test_id,
                    category=category,
                    is_real=real == "true",
                    cwe=int(cwe),
                    path=rel,
                )
            )
    return cases, issues


def load_juice_shop(
    root: Path = TARGETS / "juice-shop",
) -> tuple[list[JuiceShopChallenge], list[QualityIssue]]:
    """Read the documented challenge list (data/static/challenges.yml)."""
    static = root / "data" / "static"
    raw = yaml.safe_load((static / "challenges.yml").read_text(encoding="utf-8"))
    challenges: list[JuiceShopChallenge] = []
    issues: list[QualityIssue] = []
    seen: set[str] = set()
    for item in raw:
        key = item.get("key")
        if not key or not item.get("category") or item.get("difficulty") is None:
            issues.append(
                QualityIssue(
                    dataset="juice-shop",
                    kind="missing_field",
                    detail=str(item.get("name")),
                )
            )
            continue
        if key in seen:
            issues.append(
                QualityIssue(dataset="juice-shop", kind="duplicate", detail=key)
            )
            continue
        seen.add(key)
        has_code = any((static / "codefixes").glob(f"{key}_*"))
        challenges.append(
            JuiceShopChallenge(
                key=key,
                name=item["name"],
                category=item["category"],
                difficulty=int(item["difficulty"]),
                tags=item.get("tags") or [],
                has_code_snippets=has_code,
            )
        )
    return challenges, issues
