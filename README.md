# OWASP Sentinel

Hybrid LLM + SAST scanner for OWASP Top 10 (2025), benchmarked on known-vulnerable
code (OWASP Benchmark for Java, Juice Shop for JavaScript). See [PLAN.md](PLAN.md).

**Status:** Steps 2-5 done. Baseline scored on the full Benchmark (`results/baseline_full.md`); LLM triage, verified auto-fix and the `/benchmark` page are built and unit-tested, but no real LLM run has been done yet, so there are no with-triage numbers. The GitHub App is out of scope per PLAN.md.

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

**Decision: Opengrep engine + openly licensed rules only.** Rules are fetched at a
pinned commit into `targets/` (see `targets/commits.json`) and never copied into
this repo.

| Component | Source | Licence |
|---|---|---|
| Engine | [Opengrep](https://github.com/opengrep/opengrep) v1.31.0 (release binary, sha256-pinned in the Dockerfile) | LGPL-2.1 |
| Rules (Java, JS, Python) | GitLab [sast-rules](https://gitlab.com/gitlab-org/security-products/sast-rules) @ `53bf5cf6df` | MIT (repo LICENSE; `doc/` is CC BY-SA 4.0 and is not used) |
| Python scanner | [Bandit](https://github.com/PyCQA/bandit) | Apache-2.0 |

Rejected:
- **Semgrep Registry rules**: Semgrep Rules License restricts use in hosted services,
  and PLAN.md ships a public demo.
- **`opengrep/opengrep-rules`**: a mirror of semgrep-rules under LGPL-2.1 *plus the
  Commons Clause*, which forbids selling a service whose value comes from the
  software. That is not open-source, so it is excluded.

Licences were read from each repo's LICENSE file on 2026-10-15. This is not legal
advice. GitLab's rule set has no PHP rules, so PHP stays out of scope (PLAN.md
already makes it optional).

## Running scans (Docker, works on Windows)

No native Semgrep/Opengrep install is needed. Fetch targets and rules, then:

```powershell
python targets/fetch.py
docker compose --profile scan run --rm scanner /targets/juice-shop `
  --config /targets/sast-rules/javascript --config /targets/sast-rules/java `
  --out /out/scan_juice_shop.json
```

The scanner container mounts `targets/` read-only and only reads the code.

Full Benchmark scan, fast path (sources copied into a Docker volume, batches of 200
files, progress printed; ~5 min vs ~14 min reading the Windows folder directly):

```powershell
$env:MSYS_NO_PATHCONV=1   # Git Bash only
docker compose --profile scan run --rm seed-volume
docker compose --profile scan run --rm scanner-fast /work/benchmark/testcode `
  --config /work/sast-rules/java --batch-size 200 --out /out/scan_benchmark_full.json
python -m sentinel.bench.run_bench results/scan_benchmark_full.json
uvicorn sentinel.api.main:app   # then open http://localhost:8000/benchmark
```

## Development

```powershell
pre-commit install   # ruff + black on every commit
pytest
```

Coding rules are in [CLAUDE.md](CLAUDE.md).
