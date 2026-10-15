from sentinel.bench.coverage import owasp_coverage, uncovered_benchmark_categories
from sentinel.bench.data import BenchmarkCase
from sentinel.bench.metrics import case_id, score
from sentinel.core.models import Finding


def _case(n: int, cat: str, real: bool, cwe: int) -> BenchmarkCase:
    return BenchmarkCase(
        test_id=f"BenchmarkTest{n:05d}", category=cat, is_real=real, cwe=cwe, path="x"
    )


def _find(n: int, cwes: list[int]) -> Finding:
    return Finding(
        tool="t",
        rule_id="r",
        message="m",
        file=f"/targets/b/BenchmarkTest{n:05d}.java",
        start_line=1,
        end_line=1,
        cwes=cwes,
    )


CASES = [
    _case(1, "xss", True, 79),
    _case(2, "xss", False, 79),
    _case(3, "xss", True, 79),
    _case(4, "hash", True, 328),
    _case(5, "sqli", True, 89),
    _case(6, "sqli", False, 89),
]
FINDINGS = [
    _find(1, [79]),  # TP
    _find(2, [79]),  # FP
    _find(3, [22]),  # wrong CWE: does not count, so FN
    _find(4, [327]),  # hash alias: TP
]


def test_case_id_handles_windows_and_posix_paths() -> None:
    assert case_id("C:\\a\\BenchmarkTest00007.java") == "BenchmarkTest00007"
    assert case_id("/t/BenchmarkTest00007.java") == "BenchmarkTest00007"


def test_score_per_category_and_overall() -> None:
    rows = {r.category: r for r in score(CASES, FINDINGS)}
    xss = rows["xss"]
    assert (xss.tp, xss.fp, xss.tn, xss.fn) == (1, 1, 0, 1)
    assert xss.precision == 0.5 and xss.recall == 0.5 and xss.fpr == 1.0
    assert xss.youden == -0.5
    assert rows["hash"].tp == 1
    sqli = rows["sqli"]
    assert (sqli.tp, sqli.fn, sqli.tn) == (0, 1, 1) and sqli.precision is None
    assert rows["overall"].tp == 2 and rows["overall"].fn == 2


def test_score_subset() -> None:
    rows = score(CASES, FINDINGS, only_ids={"BenchmarkTest00001"})
    assert [r.category for r in rows] == ["xss", "overall"]
    assert rows[-1].tp == 1 and rows[-1].fp == 0


def test_uncovered_categories() -> None:
    assert uncovered_benchmark_categories(CASES, FINDINGS) == ["sqli"]


def test_owasp_coverage_marks_unmeasured_as_not_covered() -> None:
    cov = owasp_coverage(CASES)
    assert cov["A05"]["status"] == "Measured" and cov["A05"]["cases"] == 5
    assert cov["A09"]["status"] == "Not covered" and cov["A09"]["cases"] == 0
