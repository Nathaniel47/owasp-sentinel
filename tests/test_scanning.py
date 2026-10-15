import json
import subprocess
from pathlib import Path

import pytest

from sentinel.core.owasp_map import categories, map_cwes
from sentinel.core.sarif import language_of, parse_sarif
from sentinel.scanners import runner

FIX = Path(__file__).parent / "fixtures"


def _sarif() -> dict:
    return json.loads((FIX / "sarif" / "semgrep.sarif").read_text(encoding="utf-8"))


def test_parse_sarif_normalises_and_skips_malformed() -> None:
    findings = parse_sarif(_sarif(), tool="semgrep")
    assert [f.rule_id for f in findings] == ["java.sqli", "js.xss"]
    sqli, xss = findings
    assert (sqli.cwes, sqli.owasp, sqli.language) == ([89], ["A05"], "java")
    assert (sqli.start_line, sqli.end_line, sqli.severity) == (3, 4, "error")
    assert xss.end_line == 3 and xss.owasp == ["A05"] and xss.language == "javascript"


def test_language_of_covers_scoped_languages() -> None:
    expected = {
        "a.java": "java",
        "a.ts": "typescript",
        "a.jsx": "javascript",
        "a.mjs": "javascript",
        "a.cjs": "javascript",
        "a.mts": "typescript",
        "a.cts": "typescript",
        "a.py": "python",
        "a.php": "php",
        "README": "unknown",
    }
    assert {n: language_of(n) for n in expected} == expected


def test_owasp_map() -> None:
    assert map_cwes([89, 79]) == ["A05"]
    assert map_cwes([327, 22]) == ["A01", "A04"]
    assert map_cwes([999999]) == []
    assert len(categories()) == 10


def test_fixtures_exist_for_each_language() -> None:
    for lang, name in [
        ("java", "SqlInjection.java"),
        ("javascript", "xss.js"),
        ("python", "weak_hash.py"),
        ("php", "lfi.php"),
    ]:
        assert (FIX / lang / name).is_file()


def test_commands_are_read_only_argv() -> None:
    cmd = runner.semgrep_command(Path("x"), "rules/")
    assert cmd[:2] == ["opengrep", "scan"] and "--sarif" in cmd
    assert runner.bandit_command(Path("x"))[0] == "bandit"


def test_multiple_configs_become_repeated_flags() -> None:
    cmd = runner.semgrep_command(Path("x"), ["a/", "b/"])
    assert cmd.count("--config") == 2 and cmd[-1] == "x"


def test_missing_scanner_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    with pytest.raises(runner.ScannerError, match="not installed"):
        runner.run_semgrep(FIX, "rules/")


def test_scan_runs_bandit_only_for_python(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_run(cmd: list[str], timeout: int) -> str:
        calls.append(cmd[0])
        return json.dumps(_sarif())

    monkeypatch.setattr(runner, "_run", fake_run)
    runner.scan(FIX / "java", "rules/")
    assert calls == ["opengrep"]
    calls.clear()
    out = runner.scan(FIX / "python", "rules/")
    assert calls == ["opengrep", "bandit"] and len(out) == 4


def test_run_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/bin/x")
    done = subprocess.CompletedProcess([], 2, stdout="", stderr="boom")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: done)
    with pytest.raises(runner.ScannerError, match="failed"):
        runner._run(["semgrep"], 5)


def test_scan_batched_splits_files_and_reports_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cmds: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int) -> str:
        cmds.append(cmd)
        return json.dumps(_sarif())

    monkeypatch.setattr(runner, "_run", fake_run)
    files = [Path(f"f{i}.java") for i in range(5)]
    seen: list[tuple[int, int]] = []
    out = runner.scan_batched(
        files, "rules/", batch_size=2, progress=lambda d, t: seen.append((d, t))
    )
    assert seen == [(2, 5), (4, 5), (5, 5)]
    assert [c[-1] for c in cmds] == ["f1.java", "f3.java", "f4.java"]
    assert "f0.java" in cmds[0] and len(out) == 6  # 2 findings per batch
