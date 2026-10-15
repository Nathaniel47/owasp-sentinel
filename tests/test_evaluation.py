import json
import shutil
import subprocess
import urllib.error
from pathlib import Path

import pytest
import yaml

from sentinel.bench.metrics import Counts
from sentinel.bench.run_triage import (
    BudgetClient,
    CallBudgetReached,
    kept_after_triage,
    key,
    summarise,
)
from sentinel.core.models import Finding
from sentinel.core.owasp_map import map_cwes
from sentinel.llm import client as llm_client
from sentinel.llm.client import FakeClient, GeminiClient, LLMError, from_env
from sentinel.llm.triage import Verdict

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "java" / "sentinel-java.yml"
FIXTURE = ROOT / "tests" / "fixtures" / "java" / "CustomRules.java"


def test_custom_rules_are_wellformed_mit_and_map_to_owasp() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    cwes = {r["id"]: r["metadata"]["cwe"] for r in rules}
    assert cwes == {
        "sentinel_java_sqli": ["CWE-89"],
        "sentinel_java_trust_boundary": ["CWE-501"],
        "sentinel_java_weak_random": ["CWE-330"],
        "sentinel_java_xpath_injection": ["CWE-643"],
    }
    assert all(r["metadata"]["license"] == "MIT" for r in rules)
    assert map_cwes([89, 501, 330, 643]) == ["A04", "A05", "A06"]


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep not installed")
def test_custom_rules_fire_on_fixture_only_where_vulnerable() -> None:
    out = subprocess.run(
        [
            "opengrep",
            "scan",
            "--sarif",
            "--quiet",
            "--config",
            str(RULES),
            str(FIXTURE),
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    hits = sorted(
        (
            r["ruleId"].rsplit(".", 1)[-1],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in json.loads(out)["runs"][0]["results"]
    )
    assert hits == [
        ("sentinel_java_sqli", 10),
        ("sentinel_java_trust_boundary", 22),
        ("sentinel_java_weak_random", 27),
        ("sentinel_java_weak_random", 28),
        ("sentinel_java_xpath_injection", 34),
    ]


def test_owasp_2025_map_spot_checks_against_official_lists() -> None:
    # Spot values read from the official top10.owasp.org/2025 category pages.
    assert map_cwes([22]) == ["A01"] and map_cwes([614]) == ["A02"]
    assert map_cwes([327, 328, 330]) == ["A04"]
    assert map_cwes([79, 89, 90, 643, 78]) == ["A05"]
    assert map_cwes([501]) == ["A06"] and map_cwes([502]) == ["A08"]
    assert map_cwes([829]) == ["A08"]  # the old draft wrongly had it in A03
    assert map_cwes([209]) == ["A10"]  # the old draft wrongly had it in A06
    assert map_cwes([35]) == []  # the old draft wrongly had it in A01
    data = yaml.safe_load((ROOT / "sentinel/core/owasp_2025.yaml").read_text("utf-8"))
    flat = [c for v in data["cwes"].values() for c in v]
    assert len(flat) == len(set(flat)), "a CWE sits in two categories"


def _finding(line: int) -> Finding:
    return Finding(
        tool="t", rule_id="r", message="m", file="/x/BenchmarkTest00001.java",
        start_line=line, end_line=line,
    )  # fmt: skip


def test_kept_after_triage_drops_only_confident_false_positives() -> None:
    fs = [_finding(1), _finding(2), _finding(3)]
    verdicts = {
        key(fs[0]): Verdict(verdict="false_positive", confidence=0.9, explanation="e"),
        key(fs[1]): Verdict(verdict="false_positive", confidence=0.3, explanation="e"),
        key(fs[2]): Verdict(verdict="uncertain", confidence=0.0, explanation="e"),
    }
    assert kept_after_triage(fs, verdicts) == fs[1:]


def test_budget_client_stops_at_limit() -> None:
    b = BudgetClient(FakeClient(lambda s, p: "ok"), limit=2)
    b.complete("s", "p")
    b.complete("s", "p")
    with pytest.raises(CallBudgetReached):
        b.complete("s", "p")


def test_summarise_mean_and_sd_over_runs() -> None:
    runs = [
        [Counts(category="overall", tp=8, fp=2, tn=8, fn=2)],
        [Counts(category="overall", tp=6, fp=4, tn=6, fn=4)],
    ]
    s = summarise(runs)["overall"]
    assert s["precision"]["mean"] == pytest.approx(0.7)
    assert s["precision"]["sd"] == pytest.approx(0.1414, abs=1e-3)


def test_gemini_key_only_in_header_and_never_in_errors(monkeypatch) -> None:
    secret = "SECRET-KEY-123"
    seen: dict = {}

    def fake_urlopen(req, timeout=0):
        seen["url"], seen["headers"] = req.full_url, dict(req.header_items())
        raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(llm_client.urllib.request, "urlopen", fake_urlopen)
    c = GeminiClient("gemini-x", secret, max_retries=0)
    with pytest.raises(LLMError) as exc:
        c.complete("sys", "prompt")
    assert secret not in seen["url"] and secret not in str(exc.value)
    assert seen["headers"]["X-goog-api-key"] == secret


def test_gemini_parses_reply_and_from_env_default(monkeypatch) -> None:
    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return json.dumps(
                {"candidates": [{"content": {"parts": [{"text": "hi"}]}}]}
            ).encode()

    monkeypatch.setattr(
        llm_client.urllib.request, "urlopen", lambda r, timeout=0: Resp()
    )
    assert GeminiClient("m", "k").complete("s", "p") == "hi"
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert from_env().name == f"gemini:{llm_client.DEFAULT_GEMINI_MODEL}"
