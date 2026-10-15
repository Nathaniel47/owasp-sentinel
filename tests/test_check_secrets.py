import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "check_secrets", Path(__file__).parents[1] / "scripts" / "check_secrets.py"
)
cs = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(cs)  # type: ignore[union-attr]


def test_flags_keys_without_echoing_them(tmp_path: Path, capsys) -> None:
    fake = "AIza" + "a" * 35
    f = tmp_path / "x.py"
    f.write_text(f'key = "{fake}"\nLLM_API_KEY = "{"b" * 30}"\n', encoding="utf-8")
    assert cs.main([str(f)]) == 1
    assert fake not in capsys.readouterr().out


def test_allows_placeholders_and_env_lookups(tmp_path: Path) -> None:
    f = tmp_path / "ok.py"
    f.write_text(
        'key = os.environ.get("LLM_API_KEY")\nLLM_API_KEY=your-key-here-xxxxxxxxxx\n'
    )
    assert cs.main([str(f)]) == 0


def test_env_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=\n")
    assert cs.main([str(tmp_path / ".env")]) == 1
    ex = tmp_path / ".env.example"
    ex.write_text("A=\nB=1\n")
    assert cs.main([str(ex)]) == 1
    ex.write_text("A=\nB=\n")
    assert cs.main([str(ex)]) == 0
