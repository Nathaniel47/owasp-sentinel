"""Build the data artefacts: saved sample IDs and the data report.

Run after `python targets/fetch.py`:  python -m sentinel.bench.build_data
Output is deterministic (fixed seed, no timestamps), so reruns give identical files.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from sentinel.bench.data import (
    TARGETS,
    BenchmarkCase,
    JuiceShopChallenge,
    QualityIssue,
    load_benchmark,
    load_juice_shop,
)
from sentinel.bench.sample import SAMPLE_SIZE, SEED, save_sample_ids, stratified_sample

RESULTS = Path(__file__).resolve().parents[2] / "results"

LICENCES = {
    "benchmark": (
        "GPL-2.0",
        "Free to run and study. Copying its source into this repo would make the "
        "repo GPL-derived, so it is fetched at a pinned commit, never vendored. "
        "Only IDs and labels (facts about the files) are stored here.",
    ),
    "juice-shop": (
        "MIT",
        "Permissive: reuse allowed with the copyright notice. Still fetched, not "
        "vendored, per CLAUDE.md. Challenge names/categories are quoted as metadata.",
    ),
}


def _table(header: list[str], rows: list[list[object]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def _licence_line(name: str) -> str:
    first = ""
    for line in (TARGETS / name / "LICENSE").read_text(encoding="utf-8").splitlines():
        if line.strip():
            first = line.strip()
            break
    spdx, note = LICENCES[name]
    return f'**{spdx}** (LICENSE file begins: "{first}"). {note}'


def benchmark_section(
    cases: list[BenchmarkCase], sample: list[BenchmarkCase], issues: list[QualityIssue]
) -> str:
    by_cat: dict[str, Counter[bool]] = defaultdict(Counter)
    for c in cases:
        by_cat[c.category][c.is_real] += 1
    samp: dict[str, Counter[bool]] = defaultdict(Counter)
    for c in sample:
        samp[c.category][c.is_real] += 1
    cwes: dict[str, set[int]] = defaultdict(set)
    for c in cases:
        cwes[c.category].add(c.cwe)
    rows = []
    for cat in sorted(by_cat):
        r, f = by_cat[cat][True], by_cat[cat][False]
        rows.append(
            [
                cat,
                ",".join(map(str, sorted(cwes[cat]))),
                r,
                f,
                f"{r / (r + f):.0%}",
                samp[cat][True],
                samp[cat][False],
            ]
        )
    n_real = sum(c.is_real for c in cases)
    first = cases[0]
    src_lines = [
        len((TARGETS / "benchmark" / c.path).read_text(encoding="utf-8").splitlines())
        for c in cases
    ]
    return f"""## OWASP Benchmark (Java), main scored set

- Licence: {_licence_line("benchmark")}
- Cases usable: **{len(cases)}** ({n_real} real vulnerabilities, {len(cases) - n_real} fake, {n_real / len(cases):.1%} real). Rows rejected by cleaning: {len(issues)}.
- Java file size: min {min(src_lines)}, median {sorted(src_lines)[len(src_lines) // 2]}, max {max(src_lines)} lines.
- Stratified sample: **{len(sample)}** cases, seed {SEED}, saved to `results/sample_ids.csv`.

{_table(["category", "CWE", "real", "fake", "% real", "sample real", "sample fake"], rows)}

Sample record: `{json.dumps(first.model_dump())}`

### Quality problems found
- Imbalance: `weakrand` is 56% fake while `trustbound` is 66% real; `sqli` (504 cases) is about 14x bigger than `xpathi` (35). Scores must be reported per category, not only overall.
- `xpathi` has only 15 real cases, so the balanced sample takes 15 real + 15 fake there; the other 10 categories get 21 real + 21 fake each. Per-category numbers for `xpathi` and `ldapi` rest on few cases (wide error bars).
- Labels are generated from templates: many files differ in a few lines, so cases are not independent and "real" is defined by the Benchmark's own data-flow design, not by an independent audit.
- The key has no OWASP Top 10 2025 column. A separate CWE to A01..A10 mapping is needed (week 1 `owasp_map`), and categories such as `hash`/`crypto` map to Cryptographic Failures while `securecookie`/`trustbound` need a judgement call.
- Answer key is from Benchmark v1.2 (2016); it predates the 2025 Top 10.
"""


def juice_section(ch: list[JuiceShopChallenge], issues: list[QualityIssue]) -> str:
    cats = Counter(c.category for c in ch)
    diff = Counter(c.difficulty for c in ch)
    no_code = [c for c in ch if not c.has_code_snippets]
    rows = [[k, v] for k, v in sorted(cats.items(), key=lambda kv: (-kv[1], kv[0]))]
    return f"""## OWASP Juice Shop (JavaScript/TypeScript), small hand-labelled set

- Licence: {_licence_line("juice-shop")}
- Documented challenges: **{len(ch)}** (rows rejected by cleaning: {len(issues)}).
- Challenges with vulnerable/fixed code snippets in `data/static/codefixes`: {len(ch) - len(no_code)}; without: {len(no_code)}.
- Difficulty (1-6): {", ".join(f"{k}: {diff[k]}" for k in sorted(diff))}.

{_table(["Juice Shop category", "challenges"], rows)}

Sample record: `{json.dumps(ch[0].model_dump())}`

### Quality problems found
- The list is **challenges, not findings**: it says what is broken, not which file and line. Mapping challenges to code locations is the manual labelling step (PLAN week 2 and 4); there are no line-level labels yet.
- Juice Shop uses its own category names (e.g. "Sensitive Data Exposure", "Observability Failures"), not OWASP Top 10 2025, so it needs a mapping before it can enter the coverage matrix.
- Many challenges are runtime or client-side behaviours (e.g. forged tokens, business logic) that a static scanner cannot see; recall here will be bounded.
- Some challenges are disabled in some environments (Docker/Heroku) but still exist in source.
- Report these results separately from the Benchmark (PLAN section 3); they are never merged.
"""


def main() -> None:
    cases, b_issues = load_benchmark()
    ch, j_issues = load_juice_shop()
    sample = stratified_sample(cases)
    RESULTS.mkdir(exist_ok=True)
    save_sample_ids(sample, RESULTS / "sample_ids.csv")
    pins = json.loads((TARGETS / "commits.json").read_text(encoding="utf-8"))
    pin_lines = "\n".join(
        f"- {k}: `{v['repo']}` @ `{v['commit']}`" for k, v in pins.items()
    )
    scope = (
        "## Out of scope (per PLAN.md)\n\n"
        "WebGoat is not in PLAN.md and is not fetched. DVWA (PHP) is optional, only "
        "if weeks 1-5 finish early, so it is not fetched yet (its licence must be checked at fetch time; "
        "the same fetch-don't-vendor rule would apply).\n"
    )
    report = (
        "# Data report\n\n"
        "Generated by `python -m sentinel.bench.build_data`; do not edit by hand.\n\n"
        f"Pinned sources:\n{pin_lines}\n\n"
        "No train/test split: nothing is trained. The evaluation uses the full "
        f"Benchmark for the baseline and one fixed stratified sample "
        f"(~{SAMPLE_SIZE}, seed {SEED}) for LLM triage.\n\n"
        + benchmark_section(cases, sample, b_issues)
        + "\n"
        + juice_section(ch, j_issues)
        + "\n"
        + scope
    )
    (RESULTS / "data_report.md").write_text(report, encoding="utf-8", newline="\n")
    print(f"benchmark={len(cases)} sample={len(sample)} juice={len(ch)}")


if __name__ == "__main__":
    main()
