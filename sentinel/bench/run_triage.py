"""Evaluate LLM triage on the 450-case Benchmark sample (PLAN.md section 3).

    python -m sentinel.bench.run_triage --runs 3 --max-calls 400

Three configurations are scored on the same sample, with the same metric code:
  A. Opengrep + GitLab sast-rules            (results/scan_benchmark_full.json)
  B. A + Sentinel custom rules               (results/scan_benchmark_custom.json)
  C. B + LLM triage, mean/sd over N runs     (every finding in a sample file is
                                              triaged; no ground truth is used)

Every LLM call goes through the cache, so a stopped run resumes where it left off
and finished runs cost nothing to re-score (`--eval-only`). The run stops cleanly
at `--max-calls` or when the provider's quota is exhausted. Code is only read.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path

from sentinel.bench.data import BENCHMARK_JAVA, TARGETS, load_benchmark
from sentinel.bench.metrics import Counts, score
from sentinel.bench.sample import load_sample_ids
from sentinel.core.models import Finding
from sentinel.llm.cache import CachedClient
from sentinel.llm.client import (
    DEFAULT_GEMINI_MODEL,
    GeminiClient,
    LLMClient,
    LLMError,
    from_env,
)
from sentinel.llm.triage import Verdict, triage

RESULTS = Path(__file__).resolve().parents[2] / "results"
TESTCODE = TARGETS / "benchmark" / BENCHMARK_JAVA
CONTEXT_LINES = 40  # Benchmark files are short; this is usually the whole servlet
MIN_CONFIDENCE = 0.5
TEMPERATURE = 0.3  # >0 so repeated runs can differ; the spread is reported


class CallBudgetReached(RuntimeError):
    """The --max-calls cap was hit; progress is saved in the cache."""


class BudgetClient(LLMClient):
    """Counts real (uncached) provider calls and refuses past `limit`."""

    def __init__(self, inner: LLMClient, limit: int) -> None:
        self.inner, self.limit, self.used = inner, limit, 0
        self.name = inner.name

    def complete(self, system: str, prompt: str) -> str:
        if self.used >= self.limit:
            raise CallBudgetReached(f"reached --max-calls={self.limit}")
        self.used += 1
        return self.inner.complete(system, prompt)


def load_dotenv(path: Path = Path(".env")) -> None:
    """Copy KEY=VALUE lines from .env into os.environ (never printed or logged)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.partition("=")
        if sep and not name.startswith("#") and name.strip():
            os.environ.setdefault(name.strip(), value.strip())


def key(f: Finding) -> str:
    return f"{Path(f.file).name}:{f.rule_id}:{f.start_line}"


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Finding.model_validate(d) for d in data]


def sample_findings(findings: list[Finding], ids: set[str]) -> list[Finding]:
    """Unique findings in sample files, with file paths pointed at local sources."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if Path(f.file).stem in ids:
            local = f.model_copy(update={"file": str(TESTCODE / Path(f.file).name)})
            seen.setdefault(key(f), local)
    return sorted(seen.values(), key=key)


def run_triage_once(
    findings: list[Finding], client: LLMClient, progress_every: int = 25
) -> dict[str, Verdict]:
    verdicts: dict[str, Verdict] = {}
    for i, f in enumerate(findings, 1):
        verdicts[key(f)] = triage(f, Path("."), client, CONTEXT_LINES)
        if i % progress_every == 0:
            print(f"  triaged {i}/{len(findings)}", flush=True)
    return verdicts


def kept_after_triage(
    findings: list[Finding], verdicts: dict[str, Verdict]
) -> list[Finding]:
    """Drop only confident false positives (same policy as filter_findings)."""
    out = []
    for f in findings:
        v = verdicts[key(f)]
        if not (v.verdict == "false_positive" and v.confidence >= MIN_CONFIDENCE):
            out.append(f)
    return out


def _stats(values: list[float | None]) -> tuple[float | None, float | None]:
    xs = [v for v in values if v is not None]
    if not xs:
        return None, None
    return statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)


def _fmt(mean: float | None, sd: float | None) -> str:
    if mean is None:
        return "n/a"
    return f"{mean:.3f}" if not sd else f"{mean:.3f} ± {sd:.3f}"


METRICS = ("precision", "recall", "fpr", "youden")


def summarise(per_run: list[list[Counts]]) -> dict[str, dict]:
    """category -> metric -> {mean, sd, values} over runs (one run has sd 0)."""
    out: dict[str, dict] = {}
    for rows in zip(*per_run, strict=True):
        out[rows[0].category] = {
            m: {
                **dict(
                    zip(
                        ("mean", "sd"),
                        _stats([getattr(r, m) for r in rows]),
                        strict=True,
                    )
                ),
                "values": [getattr(r, m) for r in rows],
            }
            for m in METRICS
        }
    return out


def static_summary(rows: list[Counts]) -> dict[str, dict]:
    return {
        c.category: {
            m: {"mean": getattr(c, m), "sd": 0.0, "values": [getattr(c, m)]}
            for m in METRICS
        }
        for c in rows
    }


def comparison_table(configs: dict[str, dict[str, dict]]) -> str:
    """Overall precision / recall / FPR / Youden for every configuration."""
    lines = [
        "| Configuration | Precision | Recall | FPR | Youden |",
        "|---|--:|--:|--:|--:|",
    ]
    for name, summary in configs.items():
        o = summary["overall"]
        cells = [_fmt(o[m]["mean"], o[m]["sd"]) for m in METRICS]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def category_table(configs: dict[str, dict[str, dict]]) -> str:
    cats = [c for c in next(iter(configs.values())) if c != "overall"]
    names = list(configs)
    head = "| Category | " + " | ".join(f"{n} P / R / FPR" for n in names) + " |"
    lines = [head, "|---|" + "---|" * len(names)]
    for cat in [*cats, "overall"]:
        cells = []
        for n in names:
            s = configs[n][cat]
            cells.append(" / ".join(_fmt(s[m]["mean"], None) for m in METRICS[:3]))
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--max-calls", type=int, default=400, help="real API calls cap")
    ap.add_argument("--min-interval", type=float, default=6.0, help="seconds/call")
    ap.add_argument("--eval-only", action="store_true", help="never call the API")
    ap.add_argument("--estimate", action="store_true", help="print call count, exit")
    ap.add_argument("--out", type=Path, default=RESULTS)
    ap.add_argument("--cache", type=Path, default=Path(".llm_cache"))
    args = ap.parse_args(argv)

    cases, _ = load_benchmark()
    ids = set(load_sample_ids(args.out / "sample_ids.csv"))
    base = load_findings(args.out / "scan_benchmark_full.json")
    custom = load_findings(args.out / "scan_benchmark_custom.json")
    f_base = sample_findings(base, ids)
    f_all = sample_findings(base + custom, ids)
    n = len(f_all)
    print(
        f"{n} findings in the sample -> {n} calls/run, {n * args.runs} for "
        f"{args.runs} runs (before cache hits)"
    )
    if args.estimate:
        return 0

    inner = None
    if not args.eval_only:
        load_dotenv()
        if not os.environ.get("LLM_PROVIDER"):
            sys.exit("set LLM_PROVIDER / LLM_MODEL / LLM_API_KEY in .env")
        inner = from_env()
        if isinstance(inner, GeminiClient):
            inner.temperature = TEMPERATURE
            inner.min_interval = args.min_interval
    if inner:
        model = inner.name
    else:  # eval-only: the model the .env configures (the cache key embeds it)
        load_dotenv()
        provider = os.environ.get("LLM_PROVIDER", "unknown")
        model = f"{provider}:{os.environ.get('LLM_MODEL') or DEFAULT_GEMINI_MODEL}"
    budget = BudgetClient(inner, args.max_calls) if inner else None

    run_files: list[Path] = []
    for r in range(args.runs):
        path = args.out / f"triage_run{r + 1}.json"
        run_files.append(path)
        if path.is_file() or args.eval_only:
            continue
        assert budget is not None
        client = CachedClient(budget, args.cache, run=r + 1)
        print(f"run {r + 1}/{args.runs} ({model})", flush=True)
        try:
            verdicts = run_triage_once(f_all, client)
        except (CallBudgetReached, LLMError) as exc:
            print(f"stopped: {exc}. {budget.used} API calls used; re-run to resume.")
            break
        path.write_text(
            json.dumps({k: v.model_dump() for k, v in verdicts.items()}, indent=1),
            encoding="utf-8",
        )
        print(f"run {r + 1} done, {budget.used} API calls so far")

    done = [p for p in run_files if p.is_file()]
    if not done:
        print("no completed triage run yet")
        return 1
    per_run: list[list[Counts]] = []
    stats = {"dropped": [], "uncertain": []}
    for p in done:
        raw = json.loads(p.read_text(encoding="utf-8"))
        verdicts = {k: Verdict.model_validate(v) for k, v in raw.items()}
        kept = kept_after_triage(f_all, verdicts)
        per_run.append(score(cases, kept, only_ids=ids))
        stats["dropped"].append(len(f_all) - len(kept))
        stats["uncertain"].append(
            sum(v.verdict == "uncertain" for v in verdicts.values())
        )
    n_runs = f"{len(done)} run" + ("" if len(done) == 1 else "s")
    configs = {
        "A. Opengrep (sast-rules)": static_summary(score(cases, f_base, only_ids=ids)),
        "B. A + custom rules": static_summary(score(cases, f_all, only_ids=ids)),
        f"C. B + LLM triage ({n_runs})": summarise(per_run),
    }
    report = {
        "model": model,
        "temperature": TEMPERATURE,
        "runs_completed": len(done),
        "sample_cases": len(ids),
        "findings_triaged_per_run": n,
        "findings_dropped_per_run": stats["dropped"],
        "uncertain_per_run": stats["uncertain"],
        "configs": configs,
    }
    (args.out / "triage_eval.json").write_text(json.dumps(report, indent=1), "utf-8")
    md = (
        f"# Evaluation on the 450-case stratified sample\n\n"
        f"Model: `{model}` (temperature {TEMPERATURE}). Runs: {len(done)}. "
        f"Findings triaged per run: {n}; dropped per run: {stats['dropped']}; "
        f"unparseable/uncertain per run: {stats['uncertain']}.\n\n"
        f"Mean ± sd over runs (A and B are deterministic).\n\n"
        f"{comparison_table(configs)}\n\n## Per category (precision / recall / FPR)"
        f"\n\n{category_table(configs)}\n"
    )
    (args.out / "triage_eval.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
