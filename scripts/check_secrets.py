"""Pre-commit hook: block anything that looks like an API key or secret.

Reads only the files pre-commit passes in; never prints a matched value.
Also blocks committing `.env`, and requires `.env.example` values to be empty.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS: dict[str, re.Pattern[str]] = {
    "Google/Gemini API key": re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    "Google AI Studio key": re.compile(r"\bAQ\.[0-9A-Za-z_\-]{30,}"),
    "Anthropic API key": re.compile(r"sk-ant-[0-9A-Za-z_\-]{20,}"),
    "OpenAI-style key": re.compile(r"\bsk-[0-9A-Za-z_\-]{32,}"),
    "GitHub token": re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[0-9A-Za-z_]{30,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{20,}"),
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Assigned secret": re.compile(
        r"""(?i)\b\w*(?:api[_-]?key|secret|token|passw(?:or)?d)\w*\s*[=:]\s*"""
        r"""['"]?([A-Za-z0-9_\-./+=]{20,})['"]?"""
    ),
}
PLACEHOLDER = re.compile(r"(?i)(example|your|placeholder|changeme|xxx|<|\$\{|os\.)")


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    if path.name == ".env" or path.name.startswith(".env."):
        if path.name != ".env.example":
            return [f"{path}: env files must not be committed"]
        for n, line in enumerate(path.read_text("utf-8").splitlines(), 1):
            name, sep, value = line.partition("=")
            if sep and not name.startswith("#") and value.strip():
                problems.append(f"{path}:{n}: .env.example value for {name} not empty")
    try:
        lines = path.read_text("utf-8", errors="ignore").splitlines()
    except OSError:
        return problems
    for n, line in enumerate(lines, 1):
        for label, pat in PATTERNS.items():
            m = pat.search(line)
            if not m:
                continue
            if label == "Assigned secret" and PLACEHOLDER.search(m.group(1)):
                continue
            problems.append(f"{path}:{n}: looks like a {label}")
    return problems


def main(argv: list[str]) -> int:
    problems = [p for f in argv for p in check_file(Path(f))]
    for p in problems:
        print(p)
    if problems:
        print("Commit blocked: keep secrets in .env (git-ignored); rotate leaks.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
