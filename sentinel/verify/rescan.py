"""Verify a fix: apply the diff to a temp copy and re-run the same scanner."""

from __future__ import annotations

import ast
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel

from sentinel.core.models import Finding
from sentinel.verify.apply_patch import PatchError, apply_unified_diff

Scan = Callable[[Path], list[Finding]]


class FixResult(BaseModel):
    verified: bool
    reason: str
    patched_source: str = ""


def parses(source: str, language: str) -> bool:
    """Syntax check. Real parse for Python; bracket balance for other languages."""
    if language == "python":
        try:
            ast.parse(source)
        except SyntaxError:
            return False
        return True
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for ch in source:
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs and (not stack or stack.pop() != pairs[ch]):
            return False
    return not stack


def _same_place(a: Finding, b: Finding) -> bool:
    return a.rule_id == b.rule_id


def verify_fix(finding: Finding, root: Path, diff: str, scan: Scan) -> FixResult:
    """A fix counts only if the finding disappears, nothing new appears, and the
    patched file still parses. The original tree is never modified.
    """
    src_file = root / finding.file
    try:
        source = src_file.read_text(encoding="utf-8")
        patched = apply_unified_diff(source, diff)
    except (OSError, PatchError) as exc:
        return FixResult(verified=False, reason=f"patch failed: {exc}")
    if not parses(patched, finding.language):
        return FixResult(verified=False, reason="patched file does not parse")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / src_file.name
        shutil.copyfile(src_file, work)
        before = scan(work)
        work.write_text(patched, encoding="utf-8")
        after = scan(work)
    still = [f for f in after if _same_place(f, finding)]
    if len(still) >= len([f for f in before if _same_place(f, finding)]):
        return FixResult(verified=False, reason="finding still present")
    old_rules = {f.rule_id for f in before}
    new = [f for f in after if f.rule_id not in old_rules]
    if new:
        return FixResult(verified=False, reason=f"new finding: {new[0].rule_id}")
    return FixResult(
        verified=True, reason="finding gone, no new findings", patched_source=patched
    )
