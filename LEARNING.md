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
