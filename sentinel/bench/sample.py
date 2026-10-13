"""Seeded, stratified sample of the OWASP Benchmark (PLAN.md section 3)."""

from __future__ import annotations

import csv
import random
from collections import defaultdict
from pathlib import Path

from sentinel.bench.data import BenchmarkCase

SEED = 42
SAMPLE_SIZE = 450


def stratified_sample(
    cases: list[BenchmarkCase], n: int = SAMPLE_SIZE, seed: int = SEED
) -> list[BenchmarkCase]:
    """Pick ~n cases: equal per category, half real / half fake in each.

    Small categories (e.g. xpathi has only 15 real cases) are taken at their
    balanced maximum and the shortfall goes to categories with spare cases.
    """
    rng = random.Random(seed)
    pools: dict[str, dict[bool, list[BenchmarkCase]]] = defaultdict(
        lambda: {True: [], False: []}
    )
    for c in sorted(cases, key=lambda c: c.test_id):
        pools[c.category][c.is_real].append(c)
    cats = sorted(pools)
    # per-category number of *pairs* (one real + one fake)
    cap = {c: min(len(pools[c][True]), len(pools[c][False])) for c in cats}
    pairs = {c: 0 for c in cats}
    budget = n // 2
    while budget > 0 and any(pairs[c] < cap[c] for c in cats):
        for c in cats:
            if budget > 0 and pairs[c] < cap[c]:
                pairs[c] += 1
                budget -= 1
    picked: list[BenchmarkCase] = []
    for c in cats:
        for real in (True, False):
            picked += rng.sample(pools[c][real], pairs[c])
    return sorted(picked, key=lambda c: c.test_id)


def save_sample_ids(sample: list[BenchmarkCase], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["test_id", "category", "is_real", "cwe"])
        for c in sample:
            w.writerow([c.test_id, c.category, str(c.is_real).lower(), c.cwe])


def load_sample_ids(path: Path) -> list[str]:
    with path.open(encoding="utf-8", newline="") as fh:
        return [r["test_id"] for r in csv.DictReader(fh)]
