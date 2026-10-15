"""Map CWE ids to OWASP Top 10 2025 categories."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

MAP_FILE = Path(__file__).with_name("owasp_2025.yaml")


@lru_cache(maxsize=1)
def _data() -> dict:
    return yaml.safe_load(MAP_FILE.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _cwe_index() -> dict[int, list[str]]:
    index: dict[int, list[str]] = {}
    for category, cwes in _data()["cwes"].items():
        for cwe in cwes:
            index.setdefault(int(cwe), []).append(category)
    return index


def categories() -> dict[str, str]:
    """Category id -> name."""
    return dict(_data()["categories"])


def map_cwes(cwes: list[int]) -> list[str]:
    """Sorted unique OWASP categories for the given CWE ids (unknown CWEs ignored)."""
    index = _cwe_index()
    return sorted({cat for cwe in cwes for cat in index.get(cwe, [])})
