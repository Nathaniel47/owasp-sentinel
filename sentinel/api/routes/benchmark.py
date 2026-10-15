"""Benchmark page: renders precomputed results/benchmark.json."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(os.environ.get("SENTINEL_ROOT") or Path(__file__).resolve().parents[3])
RESULTS_FILE = ROOT / "results" / "benchmark.json"
_env = Environment(
    loader=FileSystemLoader(ROOT / "web" / "templates"),
    autoescape=select_autoescape(["html"]),
)
router = APIRouter()


def _load() -> dict:
    if not RESULTS_FILE.is_file():
        raise HTTPException(404, "no results yet; run sentinel.bench.run_bench")
    return json.loads(RESULTS_FILE.read_text(encoding="utf-8"))


@router.get("/benchmark.json")
def benchmark_json() -> dict:
    return _load()


@router.get("/benchmark", response_class=HTMLResponse)
def benchmark_page() -> str:
    return _env.get_template("benchmark.html").render(d=_load())
