# PROGRESS

## Where Step 6 (Evaluation) stands

**Not done. Step 6 stays unticked in BUILD_STEPS.md until triage runs 2 and 3 finish.**

Done: custom rule pack (`rules/java`), Gemini provider, OWASP 2025 map verified
(`results/owasp_map_check.md`), triage runner, baseline with/without custom rules
(`results/baseline_custom_full.md`), triage **run 1 of 3**
(`results/PRELIMINARY_triage_run1.md`, a single run, no variance).

Left: triage runs 2 and 3, then charts, the final results table, a limitations
section in `results/`, the finished LEARNING.md entry, and ticking Step 6.

Model: `gemini-3.1-flash-lite` (set in `.env` as `LLM_MODEL`; code default is the same).
`gemini-3.5-flash` and newer Flash models returned "high demand" 503s on 2026-10-15.

## Why it stopped

The free tier allows **500 requests/day per model** (`GenerateRequestsPerDayPerProject
PerModel-FreeTier`; resets at midnight Pacific). Run 1 plus part of run 2 used all 500.
Still needed: about 682 calls (294 to finish run 2, 388 for run 3), so **two quota days**.

## Resume (PowerShell, repo root)

Keep `.llm_cache/` (git-ignored, 482 saved responses) and `.env`; the cache is what
makes this a resume. Also needs `results/scan_benchmark_full.json` and
`results/scan_benchmark_custom.json` (git-ignored; regenerate with the Docker commands
in README.md if missing).

```powershell
.\.venv\Scripts\python -m sentinel.bench.run_triage --runs 3 --max-calls 450 --min-interval 4.5
```

Run it once per day until it prints `run 3 done`. It skips finished runs (the
`results/triage_run{n}.json` files), reuses cached answers, stops cleanly at
`--max-calls` or on a 429, and writes `results/triage_eval.md/.json` (mean ± sd).
`--estimate` prints the call count without calling the API. Do not change the model or
temperature between days: the cache key includes the model, so a change restarts it.

Then: `pip install .[charts]`, `python -m sentinel.bench.charts`, delete
`results/PRELIMINARY_triage_run1.md` (or replace it with the final write-up), tick Step 6.

## Step 7 (Demo & deploy): done

Static demo live at https://ankomahaidoo-owasp-sentinel.static.hf.space/ (home +
benchmark pages, PRELIMINARY banner). Hugging Face free tier refused a Docker Space
(402), so the live scanner is local-only via Docker; the image is built and tested.
After Step 6 finishes: re-run `run_triage --eval-only`, `scripts/build_static.py`, and
re-upload (commands in DEPLOY.md) so the page shows the three-run numbers.

## Step 8 (README & write-up): drafted, final numbers pending

Written: README.md, PORTFOLIO.md, docs/WRITEUP.md, LEARNING.md entry. Step 8 stays
unticked until these placeholders are replaced with the 3-run numbers:
- README.md: results table row "C ... final (3 runs, mean ± sd)" (TBD), PRELIMINARY note
- docs/WRITEUP.md: status line, results table row (TBD), run-1 wording in section 3
- PORTFOLIO.md: the 0.43 -> 0.36 FPR claim and "preliminary" wording
- README.md demo GIF placeholder
