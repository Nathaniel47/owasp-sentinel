"""Precompute scans of the bundled examples (run once at image build time).

    python -m sentinel.api.warm <project root>

Writes <root>/demo-cache/examples.json so one-click examples answer instantly.
Anything not in the cache is scanned live.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sentinel.api import demo


def main(root: Path) -> None:
    demo.load_examples(root / "web" / "examples")
    cache: dict[str, list] = {}
    for name, ex in demo.examples().items():
        findings = demo.scan_raw(ex["code"], ex["language"], root)
        cache[demo.cache_key(ex["language"], ex["code"])] = findings
        print(f"{name}: {len(findings)} findings")
    demo.save_precomputed(root / "demo-cache" / "examples.json", cache)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
