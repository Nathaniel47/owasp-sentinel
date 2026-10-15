"""Provider interface for every LLM call (cache wrapping lives in cache.py)."""

from __future__ import annotations

import json
import os
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable


class LLMClient(ABC):
    """One text-in, text-out call. All providers implement this."""

    name: str = "llm"

    @abstractmethod
    def complete(self, system: str, prompt: str) -> str: ...


class FakeClient(LLMClient):
    """Deterministic client for tests and offline runs."""

    name = "fake"

    def __init__(self, respond: Callable[[str, str], str]) -> None:
        self.respond = respond
        self.calls = 0

    def complete(self, system: str, prompt: str) -> str:
        self.calls += 1
        return self.respond(system, prompt)


class AnthropicClient(LLMClient):
    """Anthropic Messages API over plain HTTPS (no SDK dependency)."""

    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: str, api_key: str, max_tokens: int = 1024) -> None:
        self.model, self.api_key, self.max_tokens = model, api_key, max_tokens
        self.name = f"anthropic:{model}"

    def complete(self, system: str, prompt: str) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode()
        req = urllib.request.Request(
            self.URL,
            data=body,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            data = json.load(resp)
        return "".join(b.get("text", "") for b in data.get("content", []))


def from_env() -> LLMClient:
    """Build the configured provider from LLM_PROVIDER / LLM_MODEL / LLM_API_KEY."""
    provider = os.environ.get("LLM_PROVIDER", "")
    if provider == "anthropic":
        key = os.environ.get("LLM_API_KEY", "")
        model = os.environ.get("LLM_MODEL", "")
        if not key or not model:
            raise RuntimeError("LLM_API_KEY and LLM_MODEL are required")
        return AnthropicClient(model, key)
    raise RuntimeError(f"unsupported or unset LLM_PROVIDER: {provider!r}")
