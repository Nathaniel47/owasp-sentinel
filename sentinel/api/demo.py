"""Demo service: scan a pasted snippet, optionally add LLM triage.

The snippet is written to a temp file whose name the visitor cannot choose, read by
the scanner, and deleted. It is never imported, compiled or executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinel.core.models import Finding
from sentinel.core.owasp_map import categories
from sentinel.llm.cache import CachedClient
from sentinel.llm.client import LLMClient, LLMError, from_env
from sentinel.llm.triage import Verdict, triage
from sentinel.scanners.runner import ScannerError, scan

DEFAULT_MAX_BYTES = 20000
MAX_TRIAGED_PER_SCAN = 8
SCAN_TIMEOUT = 60
# language -> (fixed temp file name, rule configs relative to the project root)
LANGUAGES: dict[str, tuple[str, list[str]]] = {
    "java": ("Snippet.java", ["targets/sast-rules/java", "rules/java"]),
    "javascript": ("snippet.js", ["targets/sast-rules/javascript"]),
    "python": ("snippet.py", ["targets/sast-rules/python"]),
}
LANGUAGE_LABELS = {"java": "Java", "javascript": "JavaScript", "python": "Python"}

Scanner = Callable[[Path, list[str]], list[Finding]]


class DemoError(Exception):
    """A request the demo refuses; `status` is the HTTP code, `message` is safe."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


def max_bytes() -> int:
    return int(os.environ.get("MAX_SNIPPET_BYTES") or DEFAULT_MAX_BYTES)


class RateLimiter:
    """Sliding-window limiter, in memory (one process; resets on restart)."""

    def __init__(self, limit: int, window: float, max_keys: int = 5000) -> None:
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._hits) >= self.max_keys and key not in self._hits:
                self._hits = {
                    k: q
                    for k, q in self._hits.items()
                    if q and q[-1] > now - self.window
                }
                if len(self._hits) >= self.max_keys:
                    return False
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


class DailyCap:
    """A calls-per-UTC-day budget shared by all visitors."""

    def __init__(self, limit: int) -> None:
        self.limit, self._day, self._used = limit, "", 0
        self._lock = threading.Lock()

    def take(self, n: int = 1) -> bool:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock:
            if today != self._day:
                self._day, self._used = today, 0
            if self._used + n > self.limit:
                return False
            self._used += n
            return True


_scan_slots = threading.BoundedSemaphore(2)
scan_limiter = RateLimiter(limit=10, window=60.0)
llm_limiter = RateLimiter(limit=6, window=3600.0)
llm_daily = DailyCap(int(os.environ.get("DEMO_LLM_DAILY_CAP") or 100))


def llm_enabled() -> bool:
    """True when the host configured a provider via secrets/env vars."""
    return bool(os.environ.get("LLM_PROVIDER") and os.environ.get("LLM_API_KEY"))


def rule_configs(root: Path, language: str) -> list[str]:
    """Merged rules file when the image build made one (faster), else the dirs."""
    merged = root / "rules-merged" / f"{language}.yml"
    if merged.is_file():
        return [str(merged)]
    return [str(root / d) for d in LANGUAGES[language][1] if (root / d).exists()]


def _default_scanner(target: Path, configs: list[str]) -> list[Finding]:
    # Opengrep leaves temp files behind; give it a private TMPDIR that is removed.
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "TMPDIR": tmp}
        return scan(target, configs, timeout=SCAN_TIMEOUT, env=env)


_precomputed: dict[str, list[Finding]] = {}


def cache_key(language: str, code: str) -> str:
    return hashlib.sha256(f"{language}|{code}".encode()).hexdigest()


def load_precomputed(path: Path) -> None:
    """Load scans made by `python -m sentinel.api.warm`; absent file means none."""
    _precomputed.clear()
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        _precomputed.update(
            {k: [Finding.model_validate(f) for f in v] for k, v in raw.items()}
        )


def save_precomputed(path: Path, cache: dict[str, list]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    dump = {k: [f.model_dump() for f in v] for k, v in cache.items()}
    path.write_text(json.dumps(dump), encoding="utf-8")


def validate(code: str, language: str) -> None:
    if language not in LANGUAGES:
        raise DemoError(400, "Pick Java, JavaScript or Python.")
    if not code.strip():
        raise DemoError(400, "Paste some code first.")
    if len(code.encode("utf-8")) > max_bytes():
        raise DemoError(413, f"Snippet too large (limit {max_bytes()} bytes).")


@dataclass
class FindingView:
    finding: Finding
    owasp: list[tuple[str, str]]
    excerpt: list[tuple[int, str, bool]]
    verdict: Verdict | None = None


@dataclass
class ScanView:
    language: str
    findings: list[FindingView]
    triage_note: str = ""


def _excerpt(lines: list[str], f: Finding, pad: int = 2) -> list[tuple[int, str, bool]]:
    lo, hi = max(0, f.start_line - 1 - pad), min(len(lines), f.end_line + pad)
    return [
        (i + 1, lines[i], f.start_line <= i + 1 <= f.end_line) for i in range(lo, hi)
    ]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per rule and line; two tools flagging the same CWE on the same
    line (e.g. Opengrep and Bandit on `md5`) are shown once, Opengrep's first."""
    seen: set[tuple] = set()
    out = []
    ordered = sorted(
        findings, key=lambda f: (f.start_line, f.tool == "bandit", f.rule_id)
    )
    for f in ordered:
        keys = {(f.rule_id, f.start_line)} | {(c, f.start_line) for c in f.cwes}
        if not keys & seen:
            out.append(f)
        seen |= keys
    return out


def _make_client() -> LLMClient:
    cache_dir = Path(os.environ.get("DEMO_CACHE_DIR") or tempfile.gettempdir())
    return CachedClient(from_env(), cache_dir / "sentinel_llm_cache")


def scan_raw(
    code: str,
    language: str,
    root: Path,
    scanner: Scanner | None = None,
) -> list[Finding]:
    """Run the scanner on a snippet (no cache, no triage). Raises DemoError."""
    validate(code, language)
    filename = LANGUAGES[language][0]
    configs = rule_configs(root, language)
    if not configs:
        raise DemoError(503, "Scanner rules are not installed on this server.")
    if not _scan_slots.acquire(timeout=5):
        raise DemoError(503, "The scanner is busy. Try again in a few seconds.")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / filename
            target.write_text(code, encoding="utf-8")
            try:
                return _dedupe((scanner or _default_scanner)(target, configs))
            except ScannerError:
                raise DemoError(503, "The scan failed or timed out.") from None
    finally:
        _scan_slots.release()


def scan_snippet(
    code: str,
    language: str,
    root: Path,
    *,
    use_llm: bool = False,
    llm_key: str = "",
    scanner: Scanner | None = None,
    client_factory: Callable[[], LLMClient] = _make_client,
) -> ScanView:
    """Scan one snippet. Raises DemoError for refusals; never executes `code`."""
    validate(code, language)
    filename = LANGUAGES[language][0]
    cached = _precomputed.get(cache_key(language, code))
    found = cached if cached is not None else scan_raw(code, language, root, scanner)
    names = categories()
    lines = code.splitlines()
    views = [
        FindingView(
            f.model_copy(update={"file": filename}),
            [(o, names.get(o, o)) for o in f.owasp],
            _excerpt(lines, f),
        )
        for f in found
    ]
    note = ""
    if use_llm:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / filename
            target.write_text(code, encoding="utf-8")
            note = _add_triage(views, target, llm_key, client_factory)
    return ScanView(language, views, note)


def _add_triage(
    views: list[FindingView],
    target: Path,
    llm_key: str,
    client_factory: Callable[[], LLMClient],
) -> str:
    """Attach a verdict to up to MAX_TRIAGED_PER_SCAN findings. Returns a note."""
    if not llm_enabled():
        return "AI triage is not enabled on this server."
    if not views:
        return ""
    if not llm_limiter.allow(llm_key):
        return "AI triage limit reached (6 scans per hour); showing scan results only."
    chosen = views[:MAX_TRIAGED_PER_SCAN]
    if not llm_daily.take(len(chosen)):
        return "Today's shared AI triage quota is used up. Try again tomorrow."
    try:
        client = client_factory()
        for v in chosen:
            local = v.finding.model_copy(update={"file": str(target)})
            v.verdict = triage(local, Path("."), client)
    except (LLMError, RuntimeError):
        return "AI triage is unavailable right now; showing scan results only."
    if len(views) > len(chosen):
        return f"AI triage covered the first {len(chosen)} of {len(views)} findings."
    return ""


_EXAMPLES: dict[str, dict[str, str]] = {}


def examples() -> dict[str, dict[str, str]]:
    """Bundled one-click examples: id -> {title, language, code}."""
    return _EXAMPLES


def load_examples(directory: Path) -> None:
    """Read web/examples/*.{java,js,py}; the first comment line is the title."""
    suffix = {".java": "java", ".js": "javascript", ".py": "python"}
    _EXAMPLES.clear()
    for p in sorted(directory.glob("*")):
        lang = suffix.get(p.suffix)
        if lang:
            code = p.read_text(encoding="utf-8")
            title = code.splitlines()[0].lstrip("/# ").split(" (")[0].strip()
            _EXAMPLES[p.stem] = {"title": title, "language": lang, "code": code}
