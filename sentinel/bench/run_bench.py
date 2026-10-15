"""Score a saved scan against the Benchmark answer key and write results/.

    python -m sentinel.bench.run_bench results/scan_benchmark_full.json

Outputs: baseline_full.csv/.md, baseline_sample.csv, coverage.md, benchmark.json
(the last feeds the /benchmark page). No LLM is involved.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from sentinel.bench.coverage import owasp_coverage, uncovered_benchmark_categories
from sentinel.bench.data import load_benchmark
from sentinel.bench.metrics import Counts, score
from sentinel.bench.sample import load_sample_ids
from sentinel.core.models import Finding

RESULTS = Path(__file__).resolve().parents[2] / "results"
COLS = ["category", "tp", "fp", "tn", "fn", "precision", "recall", "fpr", "youden"]


def _row(c: Counts) -> dict:
    return {
        "category": c.category,
        "tp": c.tp,
        "fp": c.fp,
        "tn": c.tn,
        "fn": c.fn,
        "precision": c.precision,
        "recall": c.recall,
        "fpr": c.fpr,
        "youden": c.youden,
    }


def _fmt(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}"


def markdown_table(rows: list[Counts]) -> str:
    head = "| Category | TP | FP | TN | FN | Precision | Recall | FPR | Youden |"
    lines = [head, "|---|--:|--:|--:|--:|--:|--:|--:|--:|"]
    for c in rows:
        lines.append(
            f"| {c.category} | {c.tp} | {c.fp} | {c.tn} | {c.fn} | "
            f"{_fmt(c.precision)} | {_fmt(c.recall)} | {_fmt(c.fpr)} | "
            f"{_fmt(c.youden)} |"
        )
    return "\n".join(lines)


def write_csv(rows: list[Counts], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS, lineterminator="\n")
        w.writeheader()
        w.writerows(_row(c) for c in rows)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--benchmark", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=RESULTS)
    args = ap.parse_args(argv)

    cases, _ = load_benchmark(*([args.benchmark] if args.benchmark else []))
    findings = [
        Finding.model_validate(d)
        for d in json.loads(args.findings.read_text(encoding="utf-8"))
    ]
    sample_ids = set(load_sample_ids(args.out / "sample_ids.csv"))
    full = score(cases, findings)
    sample = score(cases, findings, only_ids=sample_ids)
    uncovered = uncovered_benchmark_categories(cases, findings)
    owasp = owasp_coverage(cases)

    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(full, args.out / "baseline_full.csv")
    write_csv(sample, args.out / "baseline_sample.csv")
    none = "None: every category has at least one matching finding."
    (args.out / "baseline_full.md").write_text(
        "# Opengrep + GitLab sast-rules baseline, full OWASP Benchmark v1.2\n\n"
        f"{len(cases)} test cases, {len(findings)} findings. A case is flagged when "
        "a finding in its file carries the category's CWE (`hash` also accepts "
        "CWE-327). Youden = recall - FPR (the Benchmark's own score).\n\n"
        f"{markdown_table(full)}\n\n"
        "## Same baseline on the 450-case stratified sample\n\n"
        f"{markdown_table(sample)}\n\n"
        "## Benchmark categories the rules never flag\n\n"
        + ("\n".join(f"- {c}" for c in uncovered) if uncovered else none)
        + "\n",
        encoding="utf-8",
    )
    (args.out / "coverage.md").write_text(
        "# OWASP Top 10 2025 coverage\n\n| ID | Category | Status | Cases | Source |\n"
        "|---|---|---|--:|---|\n"
        + "\n".join(
            f"| {k} | {v['name']} | {v['status']} | {v['cases']} | {v['source']} |"
            for k, v in owasp.items()
        )
        + "\n",
        encoding="utf-8",
    )
    page = {
        "full": [_row(c) for c in full],
        "sample": [_row(c) for c in sample],
        "uncovered_categories": uncovered,
        "owasp_coverage": owasp,
        "n_cases": len(cases),
        "n_findings": len(findings),
    }
    (args.out / "benchmark.json").write_text(json.dumps(page, indent=1), "utf-8")
    print(markdown_table(full))
    print("uncovered:", uncovered)


if __name__ == "__main__":
    main()
