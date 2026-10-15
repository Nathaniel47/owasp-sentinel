import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.api import main
from sentinel.api.routes import benchmark

client = TestClient(main.app)


def test_page_404_without_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(benchmark, "RESULTS_FILE", tmp_path / "none.json")
    assert client.get("/benchmark").status_code == 404


def test_page_renders_results_and_not_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = dict(category="xss", tp=1, fp=0, tn=1, fn=0)
    row.update(precision=1.0, recall=None, fpr=0.0, youden=None)
    data = {
        "full": [row],
        "sample": [row],
        "uncovered_categories": ["sqli"],
        "owasp_coverage": {
            "A09": {"name": "Logging", "status": "Not covered", "cases": 0}
        },
        "n_cases": 2,
        "n_findings": 1,
    }
    f = tmp_path / "benchmark.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(benchmark, "RESULTS_FILE", f)
    html = client.get("/benchmark").text
    assert "sqli" in html and "Not covered" in html and "n/a" in html
    assert client.get("/benchmark.json").json()["n_cases"] == 2
