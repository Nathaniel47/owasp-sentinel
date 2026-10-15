"""Apply a single-file unified diff to text. Pure string handling, no execution."""

from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchError(ValueError):
    """The diff is malformed or does not match the source."""


def apply_unified_diff(source: str, diff: str) -> str:
    """Return `source` with `diff` applied; raise PatchError on any mismatch.

    Context and removed lines must match exactly (modulo trailing whitespace);
    hunk positions may drift by searching nearby, as `patch` does.
    """
    lines = source.split("\n")
    out: list[str] = []
    pos = 0  # next unread index in `lines`
    hunks = _split_hunks(diff)
    if not hunks:
        raise PatchError("no hunks found")
    for start, body in hunks:
        old = [ln[1:] for ln in body if ln[:1] in (" ", "-")]
        new = [ln[1:] for ln in body if ln[:1] in (" ", "+")]
        at = _locate(lines, old, max(start - 1, pos))
        if at < pos:
            raise PatchError("hunks overlap or are out of order")
        out += lines[pos:at] + new
        pos = at + len(old)
    return "\n".join(out + lines[pos:])


def _split_hunks(diff: str) -> list[tuple[int, list[str]]]:
    hunks: list[tuple[int, list[str]]] = []
    for raw in diff.split("\n"):
        m = _HUNK.match(raw)
        if m:
            hunks.append((int(m.group(1)), []))
        elif (
            hunks and raw[:1] in (" ", "+", "-") and not raw.startswith(("---", "+++"))
        ):
            hunks[-1][1].append(raw)
        elif hunks and raw == "":
            hunks[-1][1].append(" ")  # blank context line stripped by the model
    for _, body in hunks:  # drop trailing blank pseudo-context
        while body and body[-1] == " ":
            body.pop()
    return hunks


def _locate(lines: list[str], old: list[str], hint: int) -> int:
    want = [x.rstrip() for x in old]
    span = len(old)
    order = sorted(range(max(len(lines) - span, 0) + 1), key=lambda i: abs(i - hint))
    for i in order:
        if [x.rstrip() for x in lines[i : i + span]] == want:
            return i
    raise PatchError("hunk context not found in source")
