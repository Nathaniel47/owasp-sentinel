"""Turn SARIF (static analysis JSON) into Finding records."""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.models import Finding
from sentinel.core.owasp_map import map_cwes

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_LEVELS = {"error": "error", "warning": "warning", "note": "info", "none": "info"}
LANGUAGES = {
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".php": "php",
}


def language_of(path: str) -> str:
    """Language from the file extension, or 'unknown'."""
    dot = path.rfind(".")
    return LANGUAGES.get(path[dot:].lower(), "unknown") if dot >= 0 else "unknown"


def _cwes_from(*sources: Any) -> list[int]:
    found: set[int] = set()
    for source in sources:
        for text in source if isinstance(source, list) else [source]:
            if isinstance(text, str):
                found.update(int(m) for m in _CWE_RE.findall(text))
    return sorted(found)


def parse_sarif(sarif: dict[str, Any], tool: str) -> list[Finding]:
    """Normalise every result in a SARIF document. Malformed results are skipped."""
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        rules = {
            r.get("id"): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for res in run.get("results", []):
            try:
                loc = res["locations"][0]["physicalLocation"]
                region = loc["region"]
                start = int(region["startLine"])
                rule_id = res["ruleId"]
                file = loc["artifactLocation"]["uri"]
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})
            cwes = _cwes_from(
                props.get("tags", []),
                props.get("cwe", []),
                rule.get("shortDescription", {}).get("text"),
                res.get("properties", {}).get("tags", []),
            )
            file = file.removeprefix("file:///").removeprefix("file://")
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    message=res.get("message", {}).get("text", ""),
                    file=file,
                    start_line=start,
                    end_line=int(region.get("endLine", start)),
                    severity=_LEVELS.get(res.get("level", "warning"), "warning"),
                    snippet=region.get("snippet", {}).get("text", ""),
                    cwes=cwes,
                    owasp=map_cwes(cwes),
                    language=language_of(file),
                )
            )
    return findings
