import json
from pathlib import Path

from sentinel.core.models import Finding
from sentinel.llm.cache import CachedClient
from sentinel.llm.client import FakeClient
from sentinel.llm.fix import extract_diff, suggest_fix
from sentinel.llm.triage import filter_findings, parse_verdict, triage


def _finding(file: str = "a.py", line: int = 2) -> Finding:
    return Finding(
        tool="t",
        rule_id="r1",
        message="m",
        file=file,
        start_line=line,
        end_line=line,
        language="python",
    )


def _reply(verdict: str, conf: float = 0.9) -> str:
    return json.dumps({"verdict": verdict, "confidence": conf, "explanation": "e"})


def test_parse_verdict_accepts_wrapped_json_and_defaults_to_uncertain() -> None:
    wrapped = f"Sure:\n{_reply('false_positive')}"
    assert parse_verdict(wrapped).verdict == "false_positive"
    assert parse_verdict("no json here").verdict == "uncertain"
    assert parse_verdict('{"verdict": "maybe"}').verdict == "uncertain"


def test_cache_hits_and_distinct_runs(tmp_path: Path) -> None:
    fake = FakeClient(lambda s, p: "ok")
    c0 = CachedClient(fake, tmp_path, run=0)
    assert c0.complete("s", "p") == c0.complete("s", "p")
    assert (fake.calls, c0.hits, c0.misses) == (1, 1, 1)
    CachedClient(fake, tmp_path, run=1).complete("s", "p")
    assert fake.calls == 2


def test_triage_prompt_has_numbered_context(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\nbad()\ny = 2\n", encoding="utf-8")
    seen: list[str] = []

    def respond(system: str, prompt: str) -> str:
        seen.append(prompt)
        return _reply("true_positive")

    verdict = triage(_finding(), tmp_path, FakeClient(respond))
    assert verdict.verdict == "true_positive"
    assert "2: bad()" in seen[0]


def test_filter_drops_only_confident_false_positives(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a\nb\nc\n", encoding="utf-8")
    replies = iter(
        [_reply("false_positive"), _reply("false_positive", 0.2), _reply("junk")]
    )
    client = FakeClient(lambda s, p: next(replies))
    findings = [_finding(line=i) for i in (1, 2, 3)]
    kept, dropped = filter_findings(findings, tmp_path, client)
    assert [f.start_line for f in kept] == [2, 3]
    assert [f.start_line for f, _ in dropped] == [1]


def test_extract_diff_and_suggest_fix(tmp_path: Path) -> None:
    assert extract_diff("no diff") is None
    diff = "```diff\n@@ -1,1 +1,1 @@\n-a\n+b\n```"
    assert extract_diff(diff) == "@@ -1,1 +1,1 @@\n-a\n+b\n"
    (tmp_path / "a.py").write_text("a\n", encoding="utf-8")
    client = FakeClient(lambda s, p: diff)
    assert suggest_fix(_finding(line=1), tmp_path, client)
    assert suggest_fix(_finding("missing.py"), tmp_path, client) is None
