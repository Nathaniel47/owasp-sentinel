import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.api import demo, main
from sentinel.api.routes import benchmark
from sentinel.api.routes import demo as demo_routes
from sentinel.core.models import Finding
from sentinel.llm.client import FakeClient, LLMError
from sentinel.scanners.runner import ScannerError

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(main.app)


def _finding(line: int = 2, rule: str = "x.y.SqlInjection") -> Finding:
    return Finding(
        tool="opengrep",
        rule_id=rule,
        message="m <b>bold</b>",
        file="/tmp/whatever/Snippet.java",
        start_line=line,
        end_line=line,
        cwes=[89],
        owasp=["A05"],
        language="java",
    )


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    for rel in ("targets/sast-rules/java", "targets/sast-rules/javascript"):
        (tmp_path / rel).mkdir(parents=True)
    (tmp_path / "targets/sast-rules/python").mkdir(parents=True)
    (tmp_path / "rules/java").mkdir(parents=True)
    return tmp_path


@pytest.fixture(autouse=True)
def fresh_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo, "scan_limiter", demo.RateLimiter(1000, 60))
    monkeypatch.setattr(demo, "llm_limiter", demo.RateLimiter(1000, 60))
    monkeypatch.setattr(demo, "llm_daily", demo.DailyCap(1000))
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)


def test_scan_snippet_maps_owasp_and_hides_temp_path(fake_root: Path) -> None:
    seen: dict = {}

    def scanner(target: Path, configs: list[str]) -> list[Finding]:
        seen["name"] = target.name
        seen["text"] = target.read_text(encoding="utf-8")
        return [_finding(2), _finding(2)]  # duplicate is collapsed

    out = demo.scan_snippet("a\nb\nc", "java", fake_root, scanner=scanner)
    assert seen == {"name": "Snippet.java", "text": "a\nb\nc"}
    assert len(out.findings) == 1
    view = out.findings[0]
    assert view.finding.file == "Snippet.java"
    assert view.owasp == [("A05", "Injection")]
    assert [n for n, _, hit in view.excerpt if hit] == [2]


@pytest.mark.parametrize(
    ("code", "language", "status"),
    [("", "java", 400), ("x", "php", 400), ("x" * 20001, "java", 413)],
)
def test_validation(code: str, language: str, status: int, fake_root: Path) -> None:
    with pytest.raises(demo.DemoError) as exc:
        demo.scan_snippet(code, language, fake_root, scanner=lambda t, c: [])
    assert exc.value.status == status


def test_scanner_failure_becomes_safe_error(fake_root: Path) -> None:
    def boom(target: Path, configs: list[str]) -> list[Finding]:
        raise ScannerError("secret path /app/internal")

    with pytest.raises(demo.DemoError) as exc:
        demo.scan_snippet("x", "java", fake_root, scanner=boom)
    assert exc.value.status == 503 and "/app" not in exc.value.message


def test_missing_rules_is_a_clean_503(tmp_path: Path) -> None:
    with pytest.raises(demo.DemoError) as exc:
        demo.scan_snippet("x", "java", tmp_path, scanner=lambda t, c: [])
    assert exc.value.status == 503


def test_triage_needs_host_config(fake_root: Path) -> None:
    out = demo.scan_snippet(
        "a\nb", "java", fake_root, use_llm=True, scanner=lambda t, c: [_finding()]
    )
    assert "not enabled" in out.triage_note
    assert out.findings[0].verdict is None


def test_triage_adds_verdict_and_respects_daily_cap(
    fake_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "test-not-a-real-key")
    reply = json.dumps(
        {"verdict": "false_positive", "confidence": 0.9, "explanation": "safe"}
    )
    fake = FakeClient(lambda s, p: reply)
    out = demo.scan_snippet(
        "a\nb\nc",
        "java",
        fake_root,
        use_llm=True,
        scanner=lambda t, c: [_finding(2)],
        client_factory=lambda: fake,
    )
    assert out.findings[0].verdict and out.findings[0].verdict.explanation == "safe"
    assert fake.calls == 1
    monkeypatch.setattr(demo, "llm_daily", demo.DailyCap(0))
    again = demo.scan_snippet(
        "a\nb\nc",
        "java",
        fake_root,
        use_llm=True,
        scanner=lambda t, c: [_finding(2)],
        client_factory=lambda: fake,
    )
    assert "quota" in again.triage_note and fake.calls == 1


def test_llm_failure_degrades_to_plain_results(
    fake_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "test-not-a-real-key")

    def broken(system: str, prompt: str) -> str:
        raise LLMError("gemini HTTP 429")

    out = demo.scan_snippet(
        "a\nb",
        "java",
        fake_root,
        use_llm=True,
        scanner=lambda t, c: [_finding()],
        client_factory=lambda: FakeClient(broken),
    )
    assert len(out.findings) == 1 and "unavailable" in out.triage_note


def test_rate_limiter_window() -> None:
    rl = demo.RateLimiter(2, 10)
    assert rl.allow("a", 0) and rl.allow("a", 1) and not rl.allow("a", 2)
    assert rl.allow("b", 2)  # keys are independent
    assert rl.allow("a", 11)  # window slid past the first hit


def test_rate_limiter_bounds_memory() -> None:
    rl = demo.RateLimiter(1, 100, max_keys=2)
    assert rl.allow("a", 0) and rl.allow("b", 0)
    assert not rl.allow("c", 1)  # table full of live keys: refuse, do not grow


def test_home_lists_examples_and_works_without_js() -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "/try/java-sqli" in r.text and "<script" not in r.text
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_bundled_examples_load_and_are_small() -> None:
    ex = demo.examples()
    assert {"java-sqli", "js-eval", "py-weak-hash"} <= set(ex)
    for e in ex.values():
        assert e["language"] in demo.LANGUAGES and len(e["code"]) < 2000


def _stub(code: str, language: str, root: Path, **kw: object) -> demo.ScanView:
    f = _finding(2)
    return demo.ScanView(
        language, [demo.FindingView(f, [("A05", "Injection")], [(2, "x", True)])]
    )


def test_try_example_and_post_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo_routes.demo, "scan_snippet", _stub)
    r = client.get("/try/java-sqli")
    assert r.status_code == 200 and "SqlInjection" in r.text
    r = client.post("/scan", content="code=a%0Ab&language=java")
    assert r.status_code == 200 and "SqlInjection" in r.text


def test_snippet_is_escaped_in_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def stub(code: str, language: str, root: Path, **kw: object) -> demo.ScanView:
        f = _finding(1)
        return demo.ScanView(
            language,
            [demo.FindingView(f, [], [(1, "<script>alert(1)</script>", True)])],
        )

    monkeypatch.setattr(demo_routes.demo, "scan_snippet", stub)
    r = client.post("/scan", content="code=%3Cscript%3E&language=java")
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text
    assert "m &lt;b&gt;bold&lt;/b&gt;" in r.text


def test_oversized_body_is_refused_before_scanning() -> None:
    r = client.post("/scan", content="code=" + "a" * 100_000 + "&language=java")
    assert r.status_code == 413


def test_unknown_example_and_bad_language() -> None:
    assert client.get("/try/nope").status_code == 404
    r = client.post("/scan", content="code=x&language=php")
    assert r.status_code == 400 and "Pick Java" in r.text


def test_http_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo, "scan_limiter", demo.RateLimiter(1, 60))
    h = {"x-forwarded-for": "9.9.9.9"}
    assert (
        client.post("/scan", content="code=&language=java", headers=h).status_code
        == 400
    )
    r = client.post("/scan", content="code=&language=java", headers=h)
    assert r.status_code == 429
    other = {"x-forwarded-for": "8.8.8.8"}
    assert (
        client.post("/scan", content="code=&language=java", headers=other).status_code
        == 400
    )


def test_benchmark_page_labels_preliminary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cell = {m: {"mean": 0.5, "sd": 0.0, "values": [0.5]} for m in benchmark_metrics()}
    triage = {
        "model": "m",
        "temperature": 0.3,
        "runs_completed": 1,
        "sample_cases": 450,
        "findings_triaged_per_run": 10,
        "configs": {
            "A": {"xss": cell, "overall": cell},
            "C": {"xss": cell, "overall": cell},
        },
    }
    tf = tmp_path / "t.json"
    tf.write_text(json.dumps(triage), encoding="utf-8")
    monkeypatch.setattr(benchmark, "TRIAGE_FILE", tf)
    html = client.get("/benchmark").text
    assert "PRELIMINARY" in html and "A05" in html
    triage["runs_completed"] = 3
    tf.write_text(json.dumps(triage), encoding="utf-8")
    assert "PRELIMINARY" not in client.get("/benchmark").text


def benchmark_metrics() -> tuple[str, ...]:
    return ("precision", "recall", "fpr", "youden")
