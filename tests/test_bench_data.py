from pathlib import Path

from sentinel.bench.data import (
    BENCHMARK_CSV,
    BENCHMARK_JAVA,
    BenchmarkCase,
    load_benchmark,
    load_juice_shop,
)
from sentinel.bench.sample import load_sample_ids, save_sample_ids, stratified_sample


def _make_benchmark(root: Path, rows: list[str], present: list[str]) -> None:
    (root / BENCHMARK_JAVA).mkdir(parents=True)
    (root / BENCHMARK_CSV).write_text(
        "# header\n" + "\n".join(rows) + "\n", encoding="utf-8"
    )
    for name in present:
        (root / BENCHMARK_JAVA / f"{name}.java").write_text("class X {}")


def test_load_benchmark_reports_quality_issues(tmp_path: Path) -> None:
    rows = [
        "BenchmarkTest00001,sqli,true,89",
        "BenchmarkTest00001,sqli,true,89",  # duplicate
        "BenchmarkTest00002,sqli,maybe,89",  # malformed
        "BenchmarkTest00003,xss,false,79",  # source missing
        "BenchmarkTest00004,xss,false,79",
    ]
    _make_benchmark(
        tmp_path,
        rows,
        ["BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00004"],
    )
    cases, issues = load_benchmark(tmp_path)
    assert [c.test_id for c in cases] == ["BenchmarkTest00001", "BenchmarkTest00004"]
    assert sorted(i.kind for i in issues) == [
        "duplicate",
        "malformed",
        "missing_source",
    ]


def _cases() -> list[BenchmarkCase]:
    out = []
    n = 0
    for cat, real, fake in [("a", 30, 40), ("b", 5, 50), ("c", 40, 40)]:
        for is_real, count in ((True, real), (False, fake)):
            for _ in range(count):
                n += 1
                out.append(
                    BenchmarkCase(
                        test_id=f"T{n:05d}",
                        category=cat,
                        is_real=is_real,
                        cwe=1,
                        path="p",
                    )
                )
    return out


def test_sample_is_deterministic_balanced_and_capped() -> None:
    cases = _cases()
    s1 = stratified_sample(cases, n=60, seed=1)
    s2 = stratified_sample(list(reversed(cases)), n=60, seed=1)
    assert [c.test_id for c in s1] == [c.test_id for c in s2]
    assert len(s1) == 60
    assert sum(c.is_real for c in s1) == 30
    assert sum(c.category == "b" for c in s1) == 10  # capped by 5 real cases
    assert [c.test_id for c in s1] != [
        c.test_id for c in stratified_sample(cases, n=60, seed=2)
    ]


def test_sample_roundtrip(tmp_path: Path) -> None:
    s = stratified_sample(_cases(), n=20, seed=3)
    save_sample_ids(s, tmp_path / "ids.csv")
    assert load_sample_ids(tmp_path / "ids.csv") == [c.test_id for c in s]


def test_load_juice_shop(tmp_path: Path) -> None:
    static = tmp_path / "data" / "static"
    (static / "codefixes").mkdir(parents=True)
    (static / "codefixes" / "aChallenge_1.ts").write_text("x")
    (static / "challenges.yml").write_text(
        "- {name: A, category: XSS, difficulty: 2, key: aChallenge}\n"
        "- {name: A2, category: XSS, difficulty: 2, key: aChallenge}\n"
        "- {name: B, category: XSS, key: bChallenge}\n",
        encoding="utf-8",
    )
    ch, issues = load_juice_shop(tmp_path)
    assert [c.key for c in ch] == ["aChallenge"]
    assert ch[0].has_code_snippets
    assert sorted(i.kind for i in issues) == ["duplicate", "missing_field"]


def test_saved_sample_matches_regeneration() -> None:
    """results/sample_ids.csv must equal a fresh seeded run (reproducibility)."""
    import pytest

    from sentinel.bench.build_data import RESULTS
    from sentinel.bench.data import TARGETS

    if not (TARGETS / "benchmark").exists():
        pytest.skip("targets not fetched")
    cases, _ = load_benchmark()
    expected = [c.test_id for c in stratified_sample(cases)]
    assert load_sample_ids(RESULTS / "sample_ids.csv") == expected
    assert len(expected) == 450
