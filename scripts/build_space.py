"""Assemble the Hugging Face Space folder (build/space/) from this repository.

    python scripts/build_space.py

The Space is its own git repository whose README.md must start with a YAML card, so
the folder is generated rather than the GitHub README being changed. The Dockerfile
is copied with LF line endings (a CRLF checkout on Windows breaks `\` continuations).
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "space"
DIRS = ["sentinel", "web", "rules", "results"]
FILES = ["pyproject.toml", "Dockerfile", ".dockerignore"]
EXTRA = {
    "scripts/merge_rules.py": "scripts/merge_rules.py",
    "targets/fetch.py": "targets/fetch.py",
    "targets/commits.json": "targets/commits.json",
    "deploy/space_card.md": "README.md",
}
SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", "scan_*.json", ".gitkeep")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    for d in DIRS:
        shutil.copytree(ROOT / d, OUT / d, ignore=SKIP)
    for f in FILES:
        shutil.copyfile(ROOT / f, OUT / f)
    for src, dst in EXTRA.items():
        (OUT / dst).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / src, OUT / dst)
    for name in ("Dockerfile", ".dockerignore"):
        text = (OUT / name).read_bytes().replace(b"\r\n", b"\n")
        (OUT / name).write_bytes(text)
    size = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    print(f"Space folder ready: {OUT} ({size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
