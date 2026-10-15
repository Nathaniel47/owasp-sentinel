"""Prompt/response cache keyed by hash, so reruns are free and reproducible."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sentinel.llm.client import LLMClient

DEFAULT_DIR = Path(".llm_cache")


class CachedClient(LLMClient):
    """Wraps a client; identical (provider, system, prompt, run) calls hit disk.

    `run` lets repeated experiments (e.g. 3 triage runs) get distinct entries.
    """

    def __init__(self, inner: LLMClient, directory: Path = DEFAULT_DIR, run: int = 0):
        self.inner, self.dir, self.run = inner, Path(directory), run
        self.name = inner.name
        self.hits = self.misses = 0

    def _path(self, system: str, prompt: str) -> Path:
        key = json.dumps([self.inner.name, self.run, system, prompt])
        return self.dir / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    def complete(self, system: str, prompt: str) -> str:
        path = self._path(system, prompt)
        if path.is_file():
            self.hits += 1
            return json.loads(path.read_text(encoding="utf-8"))["response"]
        self.misses += 1
        response = self.inner.complete(system, prompt)
        self.dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"response": response}), encoding="utf-8")
        return response
