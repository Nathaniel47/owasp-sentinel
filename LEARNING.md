# LEARNING.md: the data pipeline in plain language

## What "data" means in this project
Nothing here is trained, so there is no training data. The data is **answer keys**:
lists saying which code is really vulnerable. We later compare the scanner's
findings against them to compute precision and recall.

## Step 1: Fetch targets at pinned commits (`targets/fetch.py`, `commits.json`)
- **What:** downloads the OWASP Benchmark (Java) and Juice Shop (JS/TS) from GitHub.
- **Why pinned:** a repo changes over time. Fixing an exact commit means everyone
  gets identical files, so results can be reproduced months later.
- **Why not committed:** the Benchmark is GPL-2.0. Copying its source into this repo
  could make the repo GPL too. Fetching on demand avoids that (and CLAUDE.md demands it).

## Step 2: Load and clean (`sentinel/bench/data.py`)
- **Benchmark:** reads `expectedresults-1.2.csv` (test name, category, real/fake, CWE).
  Cleaning checks: no duplicate IDs, valid values, and that the Java file exists. Bad
  rows are dropped *and reported*, never silently. (Result: 0 bad rows of 2,740.)
- **Juice Shop:** reads the documented challenge list (`challenges.yml`): 116
  challenges with category and difficulty. Same checks.
- **Why it matters:** a wrong label or a missing file would quietly corrupt every
  metric downstream, and you would never know.
- Records use Pydantic models (`BenchmarkCase`, `JuiceShopChallenge`) so later modules
  get typed, validated data.

## Step 3: Stratified sample instead of a train/test split (`sample.py`)
- **No split** because nothing is learned. The baseline (Semgrep alone) runs on all
  2,740 cases. LLM triage costs money per call, so it runs on **450 cases**.
- **Stratified** means the 450 keep the right mix: equal numbers per vulnerability
  category, half real and half fake in each. Random picking would let big categories
  (sqli: 504) swamp small ones (xpathi: 35).
- **Fixed seed (42):** the random picker starts from the same number every time, so it
  chooses the same cases. The IDs are saved in `results/sample_ids.csv`, and a test
  checks that regenerating gives the same list.
- **Small-category cap:** xpathi has only 15 real cases, so it gets 15+15; the other
  ten categories get 21+21. Total is exactly 450.

## Step 4: Data report (`results/data_report.md`)
Counts, class balance (real vs fake), sample records, quality problems, licences.
Regenerate with `python -m sentinel.bench.build_data`. Output is deterministic.
**Why:** claims like "the scanner has X% recall" are only as trustworthy as the data
behind them; the report states that data's weaknesses up front (e.g. Juice Shop has
challenges, not file/line labels, so it needs manual labelling before it can be scored).

## Licences (checked against the LICENSE files in the pinned checkouts)
| Dataset | Licence | Consequence |
|---|---|---|
| OWASP Benchmark | GPL-2.0 | Fetch, don't copy source. IDs/labels only are stored. |
| Juice Shop | MIT | Permissive; still fetched, not vendored. |
| DVWA / WebGoat | not fetched | Not in PLAN.md scope (DVWA optional, late). Check licence if added. |

## Run it
```powershell
python targets/fetch.py
python -m sentinel.bench.build_data
pytest
```

# Step 4: Multi-language scanning

## What was built
- `sentinel/scanners/runner.py` runs Semgrep (or Opengrep) as a subprocess for
  Java, JS/TS, Python and PHP, plus Bandit when Python files are present. Both only
  read code; nothing scanned is ever executed.
- `sentinel/core/sarif.py` turns each tool's SARIF output into one `Finding` record
  (`models.py`): file, lines, rule, CWEs, OWASP categories, language, snippet.
- `sentinel/core/owasp_map.py` + `owasp_2025.yaml` map CWE numbers to OWASP Top 10
  2025 (A01 to A10) in one auditable file.
- Fixtures: one tiny hand-written vulnerable file each for Java, JS, Python and PHP,
  plus a sample SARIF file, under `tests/fixtures/`.

## Why it matters
Different tools speak different formats. Normalising once means triage, auto-fix and
the benchmark all work on the same `Finding` shape, whatever language it came from.
Scope note: PLAN.md makes Java and JS/TS the measured languages; Python is fixtures
only and PHP is optional, so no benchmark claims are made for them.

## Concepts, with one reading each
- **SARIF** (a standard JSON format for static-analysis results). Read: the SARIF
  2.1.0 overview at sarifweb.azurewebsites.net.
- **CWE** (a catalogue of weakness types, e.g. CWE-89 is SQL injection). Read: the
  "About CWE" page at cwe.mitre.org.
- **OWASP Top 10 2025** (the category list we report against). Read: owasp.org/Top10/2025.
- **SAST** (reading code for bugs without running it). Read: the Semgrep docs
  "Writing rules" tutorial.

## How to run and check
```powershell
pytest tests/test_scanning.py     # parser, mapper and runner (scanner calls mocked)
pip install -e ".[scan]"          # Semgrep is not supported on native Windows: use WSL or Docker
python -c "from pathlib import Path; from sentinel.scanners.runner import scan; print(scan(Path('tests/fixtures/java'), 'p/java'))"
```
- Unit tests mock the scanners, so they pass without Semgrep installed. The real
  scan was **not** run on this machine (Semgrep is not installed here), so end-to-end
  output is unverified.
- `owasp_2025.yaml` is a draft mapping written from memory. Check it against OWASP's
  published lists before quoting any per-category number.
- The rule set (`config`) is a parameter: the Registry vs Opengrep decision in the
  README is still open.
