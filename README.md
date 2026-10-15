# OWASP Sentinel

Hybrid LLM + SAST scanner for OWASP Top 10 (2025), benchmarked on known-vulnerable
code (OWASP Benchmark for Java, Juice Shop for JavaScript). See [PLAN.md](PLAN.md).

**Status:** Step 2 done (repo setup). Scanner, benchmark and LLM work not started.

## Quickstart (Windows, PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
uvicorn sentinel.api.main:app --reload   # http://localhost:8000/health
```

With Docker:

```powershell
copy .env.example .env
docker compose up --build
```

## Repo layout

See section 2 of [PLAN.md](PLAN.md). Benchmark targets are fetched into `targets/`
at pinned commits and are never committed.

## Benchmark data

Targets are fetched at pinned commits (`targets/commits.json`), never vendored.

| Dataset | Used for | Licence |
|---|---|---|
| OWASP BenchmarkJava | Java ground truth | GPL-2.0 (fetched, not copied) |
| OWASP Juice Shop | JavaScript ground truth | MIT (fetched, not copied) |

DVWA and WebGoat are out of scope and not fetched.

To run the full data check locally, including the reproducibility test that is
skipped in CI (it needs the fetched Benchmark checkout):

```powershell
python targets/fetch.py
pytest tests/test_bench_data.py
```

## Rules licence decision

_TBD (week 1):_ Semgrep Registry rules vs Opengrep + community rules. Record the
choice and the reasoning here after reading the Semgrep Rules License.

## Development

```powershell
pre-commit install   # ruff + black on every commit
pytest
```

Coding rules are in [CLAUDE.md](CLAUDE.md).
