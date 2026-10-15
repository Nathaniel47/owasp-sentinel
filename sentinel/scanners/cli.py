"""Command line: scan a path and print finding counts (reads code only)."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from sentinel.scanners.runner import scan


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", type=Path)
    ap.add_argument("--config", action="append", required=True)
    ap.add_argument("--binary", default="opengrep")
    ap.add_argument("--out", type=Path, help="write findings as JSON")
    args = ap.parse_args(argv)
    findings = scan(args.target, args.config, args.binary)
    print(f"target={args.target} findings={len(findings)}")
    print("by language:", dict(Counter(f.language for f in findings)))
    print("by OWASP:", dict(Counter(o for f in findings for o in f.owasp)))
    print("top rules:", Counter(f.rule_id for f in findings).most_common(5))
    if args.out:
        args.out.write_text(
            json.dumps([f.model_dump() for f in findings], indent=1), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
