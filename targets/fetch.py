"""Fetch benchmark targets at pinned commits into targets/<name>/ (never committed)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _git(args: list[str], cwd: Path | None = None) -> str:
    out = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


def fetch_target(name: str, repo: str, commit: str) -> Path:
    """Clone `repo` and check out exactly `commit`. Reuses an existing checkout."""
    dest = HERE / name
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        _git(["init", "-q"], dest)
        _git(["remote", "add", "origin", repo], dest)
    try:
        head = _git(["rev-parse", "HEAD"], dest)
    except subprocess.CalledProcessError:
        head = ""
    if head != commit:
        _git(["fetch", "-q", "--depth", "1", "origin", commit], dest)
        _git(["checkout", "-q", "--detach", commit], dest)
    return dest


def main(names: list[str]) -> None:
    pins = json.loads((HERE / "commits.json").read_text(encoding="utf-8"))
    for name in names or list(pins):
        pin = pins[name]
        path = fetch_target(name, pin["repo"], pin["commit"])
        print(f"{name}: {pin['commit'][:10]} -> {path}")


if __name__ == "__main__":
    main(sys.argv[1:])
