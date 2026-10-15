"""Provider interface for every LLM call (cache wrapping lives in cache.py)."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable

DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite"


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


class LLMError(RuntimeError):
    """A provider call failed. Messages never contain the API key."""


class GeminiClient(LLMClient):
    """Google Gemini generateContent over plain HTTPS (no SDK dependency).

    The key travels only in the `x-goog-api-key` header: never in the URL, never
    in an exception message or log line. Calls are spaced to `min_interval`
    seconds (free-tier requests-per-minute) and 429/5xx replies are retried with
    backoff. `calls` counts HTTP requests that reached the API.
    """

    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(
        self,
        model: str,
        api_key: str,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        min_interval: float = 0.0,
        max_retries: int = 6,
    ) -> None:
        self.model, self.api_key, self.max_tokens = model, api_key, max_tokens
        self.temperature, self.min_interval = temperature, min_interval
        self.max_retries = max_retries
        self.name = f"gemini:{model}"
        self.calls = 0
        self._last = 0.0

    def _post(self, body: bytes) -> dict:
        req = urllib.request.Request(
            self.URL.format(model=self.model),
            data=body,
            headers={
                "x-goog-api-key": self.api_key,
                "content-type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=90) as resp:  # noqa: S310
            return json.load(resp)

    def complete(self, system: str, prompt: str) -> str:
        body = json.dumps(
            {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": self.temperature,
                    "maxOutputTokens": self.max_tokens,
                    "responseMimeType": "application/json",
                },
            }
        ).encode()
        for attempt in range(self.max_retries + 1):
            wait = self._last + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.calls += 1
            try:
                data = self._post(body)
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 503) and attempt < self.max_retries:
                    time.sleep(min(60.0, 5.0 * 2**attempt))
                    continue
                raise LLMError(f"gemini HTTP {exc.code}") from None
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < self.max_retries:
                    time.sleep(min(60.0, 5.0 * 2**attempt))
                    continue
                raise LLMError(f"gemini network error: {type(exc).__name__}") from None
            parts = (
                (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
            )
            return "".join(p.get("text", "") for p in parts)
        raise LLMError("gemini: retries exhausted")


def from_env() -> LLMClient:
    """Build the configured provider from LLM_PROVIDER / LLM_MODEL / LLM_API_KEY."""
    provider = os.environ.get("LLM_PROVIDER", "")
    if provider == "anthropic":
        key = os.environ.get("LLM_API_KEY", "")
        model = os.environ.get("LLM_MODEL", "")
        if not key or not model:
            raise RuntimeError("LLM_API_KEY and LLM_MODEL are required")
        return AnthropicClient(model, key)
    if provider == "gemini":
        key = os.environ.get("LLM_API_KEY", "")
        if not key:
            raise RuntimeError("LLM_API_KEY is required")
        model = os.environ.get("LLM_MODEL", "") or DEFAULT_GEMINI_MODEL
        return GeminiClient(model, key)
    raise RuntimeError(f"unsupported or unset LLM_PROVIDER: {provider!r}")
