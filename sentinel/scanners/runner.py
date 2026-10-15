"""Run Semgrep/Opengrep and Bandit as subprocesses and normalise their SARIF.

Scanners only read code; nothing scanned is ever executed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from sentinel.core.models import Finding
from sentinel.core.sarif import language_of, parse_sarif

DEFAULT_TIMEOUT = 300


class ScannerError(RuntimeError):
    """A scanner is missing, timed out, or produced unusable output."""


def _run(cmd: list[str], timeout: int) -> str:
    if shutil.which(cmd[0]) is None:
        raise ScannerError(f"{cmd[0]} is not installed or not on PATH")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{cmd[0]} timed out after {timeout}s") from exc
    # Semgrep/Bandit exit 1 when findings exist; 2+ means a real failure.
    if proc.returncode > 1 or not proc.stdout.strip():
        raise ScannerError(f"{cmd[0]} failed ({proc.returncode}): {proc.stderr[:300]}")
    return proc.stdout


def semgrep_command(
    target: Path, config: str | list[str], binary: str = "opengrep"
) -> list[str]:
    """Argv for a Semgrep or Opengrep SARIF scan with pinned rule config(s)."""
    configs = [config] if isinstance(config, str) else config
    cmd = [binary, "scan", "--sarif", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    return [*cmd, str(target)]


def bandit_command(target: Path) -> list[str]:
    """Argv for a recursive Bandit scan with SARIF output."""
    return ["bandit", "-r", str(target), "-f", "sarif", "-q"]


def run_semgrep(
    target: Path,
    config: str | list[str],
    binary: str = "opengrep",
    timeout: int = DEFAULT_TIMEOUT,
) -> list[Finding]:
    out = _run(semgrep_command(target, config, binary), timeout)
    return parse_sarif(json.loads(out), tool=binary)


def run_bandit(target: Path, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    out = _run(bandit_command(target), timeout)
    return parse_sarif(json.loads(out), tool="bandit")


def scan(
    target: Path,
    config: str | list[str],
    binary: str = "opengrep",
    timeout: int = DEFAULT_TIMEOUT,
) -> list[Finding]:
    """Scan a file or directory: Semgrep/Opengrep always, Bandit if Python exists."""
    target = Path(target)
    files = [target] if target.is_file() else list(target.rglob("*"))
    findings = run_semgrep(target, config, binary, timeout)
    if any(language_of(str(f)) == "python" for f in files):
        findings += run_bandit(target, timeout)
    return findings


def scan_batched(
    files: Sequence[Path],
    config: str | list[str],
    binary: str = "opengrep",
    timeout: int = DEFAULT_TIMEOUT,
    batch_size: int = 200,
    progress: Callable[[int, int], None] | None = None,
) -> list[Finding]:
    """Scan many files in batches so one slow batch cannot sink the whole run.

    `timeout` applies per batch. `progress(done, total)` is called after each.
    Bandit runs once per Python batch, same as `scan`.
    """
    findings: list[Finding] = []
    total = len(files)
    for start in range(0, total, batch_size):
        batch = files[start : start + batch_size]
        cmd = semgrep_command(batch[0], config, binary)[:-1]
        cmd += [str(f) for f in batch]
        findings += parse_sarif(json.loads(_run(cmd, timeout)), tool=binary)
        py = [f for f in batch if language_of(str(f)) == "python"]
        if py:
            cmd = ["bandit", *[str(f) for f in py], "-f", "sarif", "-q"]
            findings += parse_sarif(json.loads(_run(cmd, timeout)), tool="bandit")
        if progress:
            progress(min(start + batch_size, total), total)
    return findings
