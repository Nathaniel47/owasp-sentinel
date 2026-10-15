"""Benchmark page: renders precomputed results/benchmark.json."""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinel.core.owasp_map import map_cwes

ROOT = Path(os.environ.get("SENTINEL_ROOT") or Path(__file__).resolve().parents[3])
RESULTS_FILE = ROOT / "results" / "benchmark.json"
TRIAGE_FILE = ROOT / "results" / "triage_eval.json"
FULL_RUNS = 3
# Benchmark test category -> CWE (results/owasp_map_check.md); OWASP id comes from
# the official-list map in owasp_2025.yaml.
CATEGORY_CWE = {
    "pathtraver": 22,
    "securecookie": 614,
    "crypto": 327,
    "hash": 328,
    "weakrand": 330,
    "cmdi": 78,
    "ldapi": 90,
    "sqli": 89,
    "xpathi": 643,
    "xss": 79,
    "trustbound": 501,
}
env = Environment(
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


def _triage() -> dict | None:
    """Triage evaluation, or None before any run has been scored."""
    if not TRIAGE_FILE.is_file():
        return None
    t = json.loads(TRIAGE_FILE.read_text(encoding="utf-8"))
    names = list(t["configs"])
    cats = [c for c in t["configs"][names[0]] if c != "overall"]
    t["rows"] = [
        {
            "category": c,
            "owasp": (
                ", ".join(map_cwes([CATEGORY_CWE[c]])) if c in CATEGORY_CWE else ""
            ),
            "cells": [t["configs"][n][c] for n in names],
        }
        for c in [*cats, "overall"]
    ]
    t["names"] = names
    t["preliminary"] = t["runs_completed"] < FULL_RUNS
    return t


@router.get("/benchmark", response_class=HTMLResponse)
def benchmark_page() -> str:
    return env.get_template("benchmark.html").render(d=_load(), t=_triage())
