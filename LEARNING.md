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

## Step 4 addendum: real scans through Docker
- Rules switched to Opengrep + MIT-licensed GitLab sast-rules (see README for why
  the Semgrep Registry and `opengrep-rules` were rejected).
- Semgrep/Opengrep do not run natively on Windows, so the scanner is a Docker stage:
  `docker compose --profile scan run --rm scanner <target> --config <rules>`.
- First real results are in `results/scan_smoke.md`: 32 findings on Juice Shop and 65
  on 100 Benchmark files. These are counts only; scoring against the answer key is
  the next piece of work.
- Windows tip: in Git Bash set `MSYS_NO_PATHCONV=1` or `/targets/...` paths get rewritten.

# Step 5: Remaining features

Scope note: PLAN.md wins over BUILD_STEPS.md. The **GitHub App / PR commenting is
out of scope in PLAN.md** (and CLAUDE.md says no features beyond PLAN.md), so it was
not built. The benchmark page covers the Benchmark and Juice Shop, not WebGoat/DVWA,
for the same reason.

## Scoring the baseline (no LLM)
- **What:** `sentinel/bench/metrics.py` compares the scanner's findings with the
  Benchmark answer key. A test case is "flagged" if a finding in its file has a CWE
  that belongs to the case's category. Real + flagged = TP, fake + flagged = FP,
  real + not flagged = FN, fake + not flagged = TN.
- **Why it matters:** a scanner that flags everything has perfect recall and is
  useless. The Benchmark's own score, **Youden = recall - false-positive rate**, is 0
  for random guessing and 1 for perfect. It stops us fooling ourselves.
- **A judgement call to know about:** GitLab tags its weak-hash rule CWE-327, the
  Benchmark's `hash` category is CWE-328. Without an alias the scorer would call
  every hash case "missed". `CATEGORY_ALIASES` accepts 327 for `hash` and nothing else.
- **Coverage:** a category is "no rule coverage" if no finding anywhere in it
  has a matching CWE. OWASP Top 10 categories with no ground truth show as "Not covered".
- Concepts: precision/recall (Google ML Crash Course, "Classification"), Youden's J
  (the Wikipedia article "Youden's J statistic"), the Benchmark scorecards (OWASP Benchmark project page).

## LLM layer: provider interface and cache
- Every LLM call goes through `LLMClient` (`sentinel/llm/client.py`) and can be
  wrapped by `CachedClient`, which stores each reply on disk by hash of
  (model, run number, prompt). Reruns are free and reproducible; a different `run`
  number gives independent repeats for variance.
- `FakeClient` lets all tests run with no network or key. **No real model was called
  while building this step**, so there are no with-triage numbers yet.

## LLM triage
- For each finding the model sees the rule, message, CWE and numbered code around the
  flagged lines, and must answer in JSON: true/false positive, confidence, explanation.
- Safe by default: an unparseable reply becomes "uncertain" and the finding is kept;
  only a *confident* false positive (confidence >= 0.5) is dropped. Code is placed in a
  `<code>` block and the system prompt says to ignore instructions inside it (prompt
  injection defence; not a guarantee).
- Read: Li et al. 2024, "IRIS: LLM-Assisted Static Analysis" (arXiv).

## Auto-fix verified by re-scan
- The model returns a unified diff. `verify/apply_patch.py` applies it in memory
  (context lines must match; line numbers may drift). `verify/rescan.py` scans a temp
  copy before and after. A fix counts only if the finding's rule no longer fires,
  no rule appears that did not before, and the file still parses.
- Limit: "still parses" is a real parse only for Python; for Java/JS it is a bracket-balance
  check, which is weak. A stronger check needs a real parser (tree-sitter), not added
  because it is outside PLAN.md.
- Nothing is executed; the patched copy is only read by the scanner.

## Benchmark page
- `/benchmark` renders `results/benchmark.json` (written by
  `python -m sentinel.bench.run_bench`): full-Benchmark table, 450-sample table,
  rule-coverage gaps and the OWASP 2025 coverage matrix.
- Run: `uvicorn sentinel.api.main:app` then open http://localhost:8000/benchmark.

## Step 5 results and a faster full scan
- Baseline (Opengrep + GitLab rules, full Benchmark, 2,740 cases): precision 0.64,
  recall 0.49, false-positive rate 0.29, Youden 0.20. Full table: `results/baseline_full.md`.
- **Four Benchmark categories are not covered by the rules at all** (no matching
  finding anywhere): `sqli`, `trustbound`, `weakrand`, `xpathi`. This matches the rule
  files: none carries CWE-89, 501, 330 or 643. Those cases score recall 0 by
  construction, which drags the overall recall down. The open-source GitLab set has
  no SQL-injection rule for Java, which is worth knowing before blaming "SAST".
- Benchmark-category gaps and the OWASP 2025 view differ: the Benchmark gives ground
  truth for A01, A02, A04, A05, A06 only; A03, A07, A08, A09, A10 are "Not covered".
  The CWE-to-category file is still a draft, so check it before quoting per-category numbers.
- Why the scan was slow: Docker on Windows reads bind-mounted folders through a slow
  file-sharing layer, and 2,740 files made one run take ~14 min (and exceeded the
  5-minute default timeout once). The fast path copies sources into a Docker volume
  (native Linux disk) and scans in batches with progress: ~5 min, identical findings
  (1,579) and identical scores.

## Step 6 (in progress): custom rules, Gemini triage, preliminary results
- The GitLab rule pack has no Java rules for SQL injection, trust boundary, weak random
  or XPath injection. `rules/java/sentinel-java.yml` (MIT) adds taint rules for the first,
  second and fourth and a pattern rule for weak random. Overall recall on the 450 sample
  went 0.600 -> 0.889.
- **Custom rules raised the false-positive rate (0.289 -> 0.427) while precision stayed
  at 0.676.** The new rules are broad: they flag any request data reaching a SQL string,
  session call or XPath call, and any `java.util.Random`, even where the Benchmark's
  "fake" cases neutralise the value or use `SecureRandom` through a `Random`-typed
  variable. **To tune later:** add sanitiser patterns, handle collections and ternaries
  in taint flow, and exclude `Random` variables assigned from `SecureRandom`. The LLM
  triage step exists partly to absorb this noise, but it should not be the only fix.
- Triage with Gemini is a **single run so far**: FPR 0.427 -> 0.360 with recall
  unchanged. Treat it as preliminary until runs 2 and 3 give a spread
  (`results/PRELIMINARY_triage_run1.md`, `PROGRESS.md`).
- Free-tier LLM APIs have per-day request caps (500/day here), so an experiment of
  ~1,160 calls needs planning. The cache makes runs resumable and re-scoring free.
- Secrets: `scripts/check_secrets.py` is a pre-commit hook that blocks API-key-shaped
  strings and `.env` files; `.env.example` must keep empty values.

## Step 7: Demo and deploy

**What was built.** A public web demo (`/`): click an example or paste Java,
JavaScript or Python, get findings mapped to the OWASP Top 10 2025, optionally with an
LLM "likely real / likely false positive" verdict on each. `/benchmark` shows the
measured results. One Docker image (`docker build --target demo`) holds the web app,
Opengrep and Bandit. `DEPLOY.md` has the steps for Hugging Face Spaces.

**Why Hugging Face Spaces (Docker).** The demo has to *run the scanner*, which is a
native Opengrep binary. Streamlit Community Cloud and Vercel run Python or JavaScript
only, so they cannot host it without dropping live scanning. Render's free web service
can run Docker but has far less memory (512 MB) and spins down when idle. A Docker
Space is free, gives 2 vCPU and 16 GB RAM, and visitors need no account. (Free-tier
limits change; check each host's current terms before relying on them.)

**Honest numbers.** The page loads in about 0.1 s and the four bundled examples answer
instantly, because their scans are done once while the image is built. Scanning new
code takes about 5 to 15 s: Opengrep spends roughly 4 s just starting and loading rules
(measured: `opengrep --version` alone takes that long here), and the scan itself is
under a second. Two things cut it: all rules for a language are merged into one file
(13 s down to about 7 s for Java in my test), and Opengrep's temp files go to a private
folder that is deleted. I did not manage to get live scans under 10 s on every machine,
so the page says "about 5-15 s" instead of promising less.

**Safety, in plain words.** A demo that takes strangers' code is an attack surface, so:
the code is only ever read (never run), written to a file whose name the visitor cannot
choose, and deleted; input is capped at 20 KB; each visitor gets 10 scans a minute;
pages contain no JavaScript and are HTML-escaped; and the LLM is off unless the host
adds a secret, with its own hourly and daily limits. The model's verdict only labels a
finding. It never hides one, because a model can be talked into saying "false positive"
by text inside the code.

**Preliminary results are labelled, automatically.** The benchmark page reads
`results/triage_eval.json` and shows a yellow PRELIMINARY banner while fewer than 3
triage runs are recorded. When Step 6 finishes, the banner disappears by itself. The
per-category table has an "OWASP 2025" column that comes from `owasp_2025.yaml`.

**OWASP CWE map re-verified.** Before showing per-category numbers I compared
`owasp_2025.yaml` with the raw HTML of all ten official 2025 category pages. All 249
CWEs match (no missing, no extra); a test now pins the per-category counts.

**Read.** Hugging Face docs, "Docker Spaces"; OWASP Cheat Sheet Series, "File Upload"
(the same ideas apply to untrusted snippets).

**Run and check.**

```powershell
docker build --target demo -t sentinel-demo .
docker run --rm -p 7860:7860 sentinel-demo   # open http://localhost:7860
pytest tests/test_demo.py
```

### Step 7 update: what actually got deployed

Hugging Face refused to create a free Docker Space (HTTP 402, PRO needed), so the public
demo is a **static Space**: two HTML pages rendered from `results/*.json` by
`scripts/build_static.py`. This is the safest possible deployment (no server, no code
execution, no key) at the cost of no live scanning, which stays available locally via
Docker. Free-tier terms change, so check them before planning a deployment. The static
page reads the same data as the app, so the PRELIMINARY banner disappears when the
final three-run numbers are rendered and re-uploaded.

## Step 8: README and write-up

**What I made.** A polished README (purpose, architecture diagram, results table,
limitations, future work), a 120-word portfolio card (`PORTFOLIO.md`) and a short
technical write-up (`docs/WRITEUP.md`). The demo pages now carry a "Built by" footer, a
plain-English definition of precision/recall/false-positive rate, a bar chart of
configurations A/B/C, and a "What I built" section.

**Why it matters.** A reviewer will read the README and write-up before any code. They
need to see the question, the method, honest numbers and the limits. Preliminary results
are labelled and the final three-run cells say `TBD`, so nothing is overstated.

**One-line research connection (for emails to professors).** "OWASP Sentinel is a small,
reproducible study of whether LLM triage can reduce false positives in static analysis
on a ground-truth benchmark, which connects directly to work on LLMs for vulnerability
detection, AI-assisted security testing and the correctness of LLM-generated code
fixes."

**Small fix.** The table label said "(1 runs)"; it now says "(1 run)" and "(3 runs)".

**To finish later.** After triage runs 2 and 3: re-run `--eval-only`, rebuild the static
pages, re-upload, then replace the `TBD` cells in README.md, docs/WRITEUP.md and the
numbers in PORTFOLIO.md.
