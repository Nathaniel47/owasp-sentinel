from pathlib import Path

import pytest

from sentinel.core.models import Finding
from sentinel.verify.apply_patch import PatchError, apply_unified_diff
from sentinel.verify.rescan import parses, verify_fix

SRC = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n    return 1\n"
DIFF = (
    "--- a/x.py\n+++ b/x.py\n@@ -3,4 +3,4 @@\n \n def run(cmd):\n"
    "-    os.system(cmd)\n+    print(cmd)\n     return 1\n"
)


def _finding() -> Finding:
    return Finding(
        tool="t",
        rule_id="shell",
        message="m",
        file="x.py",
        start_line=5,
        end_line=5,
        language="python",
    )


def fake_scan(path: Path) -> list[Finding]:
    """Flags any line containing os.system, like a one-rule scanner."""
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "os.system" in line:
            out.append(_finding().model_copy(update={"start_line": i, "end_line": i}))
    return out


def test_apply_diff_with_line_drift() -> None:
    drifted = "# header\n# more\n" + SRC
    assert "print(cmd)" in apply_unified_diff(drifted, DIFF)
    assert "os.system" not in apply_unified_diff(SRC, DIFF)


def test_apply_diff_rejects_mismatch_and_empty() -> None:
    with pytest.raises(PatchError):
        apply_unified_diff("totally different\n", DIFF)
    with pytest.raises(PatchError):
        apply_unified_diff(SRC, "not a diff")


def test_parses() -> None:
    assert parses("x = (1,", "python") is False
    assert parses("class A { void f() { } }", "java")
    assert not parses("class A { void f() { }", "java")


def test_verified_fix(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text(SRC, encoding="utf-8")
    result = verify_fix(_finding(), tmp_path, DIFF, fake_scan)
    assert result.verified, result.reason
    assert (tmp_path / "x.py").read_text(encoding="utf-8") == SRC  # untouched


def test_fix_that_leaves_finding_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text(SRC, encoding="utf-8")
    noop = DIFF.replace("+    print(cmd)", "+    os.system(cmd)  # still bad")
    result = verify_fix(_finding(), tmp_path, noop, fake_scan)
    assert not result.verified and result.reason == "finding still present"


def test_fix_that_breaks_syntax_or_introduces_finding(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text(SRC, encoding="utf-8")
    broken = DIFF.replace("+    print(cmd)", "+    print((cmd")
    assert "parse" in verify_fix(_finding(), tmp_path, broken, fake_scan).reason

    def scan_new(path: Path) -> list[Finding]:
        found = fake_scan(path)
        if "print(cmd)" in path.read_text(encoding="utf-8"):
            found.append(_finding().model_copy(update={"rule_id": "print-leak"}))
        return found

    result = verify_fix(_finding(), tmp_path, DIFF, scan_new)
    assert not result.verified and "new finding" in result.reason
