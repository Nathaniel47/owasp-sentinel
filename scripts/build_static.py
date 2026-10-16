"""Render the static demo (home + benchmark pages) into build/static/.

    python scripts/build_static.py

Pure HTML from results/benchmark.json and results/triage_eval.json, no scanner, no
server, no JavaScript. The pages show a PRELIMINARY banner while fewer than 3
triage runs are recorded. Deployed as a free static Hugging Face Space.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from sentinel.api.routes import benchmark

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "static"
README_URL = "https://github.com/Nathaniel47/owasp-sentinel#demo"
NAV = {"home_url": "index.html", "bench_url": "benchmark.html", "home_label": "Home"}


def main() -> None:
    t = benchmark._triage()
    if t is None:
        raise SystemExit("results/triage_eval.json is missing; nothing to show")
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    env = benchmark.env
    home = env.get_template("static_home.html").render(
        t=t, readme_url=README_URL, **NAV
    )
    page = env.get_template("benchmark.html").render(d=benchmark._load(), t=t, **NAV)
    (OUT / "index.html").write_text(home, encoding="utf-8")
    (OUT / "benchmark.html").write_text(page, encoding="utf-8")
    (OUT / "README.md").write_text(
        (ROOT / "deploy" / "static_space_card.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    print(
        f"Static demo ready: {OUT} ({'preliminary' if t['preliminary'] else 'final'})"
    )


if __name__ == "__main__":
    main()
