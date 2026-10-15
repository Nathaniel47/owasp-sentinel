"""Charts from results/triage_eval.json (needs matplotlib: pip install .[charts])."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = Path(__file__).resolve().parents[2] / "results"
COLORS = ["#8c8c8c", "#2a7ab0", "#d9822b"]  # baseline, + rules, + triage


def _short(name: str) -> str:
    return name.split(" (")[0]


def make_charts(report: dict, out: Path) -> list[Path]:
    configs = report["configs"]
    names = list(configs)
    model = report["model"]
    paths: list[Path] = []

    # 1. Overall precision / recall / FPR, error bars = sd over triage runs.
    fig, ax = plt.subplots(figsize=(7, 4))
    metrics = ["precision", "recall", "fpr"]
    width = 0.26
    for i, name in enumerate(names):
        o = configs[name]["overall"]
        xs = [j + (i - 1) * width for j in range(len(metrics))]
        means = [o[m]["mean"] or 0 for m in metrics]
        sds = [o[m]["sd"] or 0 for m in metrics]
        bars = ax.bar(xs, means, width, yerr=sds, capsize=3, color=COLORS[i])
        bars.set_label(_short(name))
        for x, v in zip(xs, means, strict=True):
            ax.text(x, v + 0.02, f"{v:.2f}", ha="center", fontsize=8)
    ax.set_xticks(range(len(metrics)), ["Precision", "Recall", "False-positive rate"])
    ax.set_ylim(0, 1.1)
    ax.set_title(f"450-case sample, overall (triage model: {model})")
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    paths.append(out / "chart_overall.png")
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)

    # 2. Per-category Youden index (recall - FPR); 0 = no better than guessing.
    cats = [c for c in configs[names[0]] if c != "overall"]
    fig, ax = plt.subplots(figsize=(9, 4))
    for i, name in enumerate(names):
        vals = [configs[name][c]["youden"]["mean"] or 0 for c in cats]
        xs = [j + (i - 1) * width for j in range(len(cats))]
        ax.bar(xs, vals, width, color=COLORS[i], label=_short(name))
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xticks(range(len(cats)), cats, rotation=30)
    ax.set_ylabel("Youden (recall - FPR)")
    ax.set_title("Benchmark score per category")
    ax.legend(fontsize=8)
    fig.tight_layout()
    paths.append(out / "chart_per_category.png")
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)

    # 3. Precision vs recall: each triage run is a point, so spread is visible.
    fig, ax = plt.subplots(figsize=(5, 4.5))
    for i, name in enumerate(names):
        o = configs[name]["overall"]
        ax.scatter(
            o["recall"]["values"], o["precision"]["values"], s=40, color=COLORS[i]
        )
        ax.annotate(
            _short(name),
            (o["recall"]["mean"], o["precision"]["mean"]),
            textcoords="offset points",
            xytext=(6, 4),
            fontsize=8,
        )
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision vs recall (one dot per run)")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    paths.append(out / "chart_precision_recall.png")
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)
    return paths


def main() -> None:
    report = json.loads((RESULTS / "triage_eval.json").read_text(encoding="utf-8"))
    for p in make_charts(report, RESULTS):
        print("wrote", p)


if __name__ == "__main__":
    main()
