# PRELIMINARY: single triage run, no variance measured

> **Status: preliminary.** Triage was run **once** (run 1 of 3 planned). Runs 2 and 3
> stopped at Gemini's free-tier daily cap (500 requests/day for this model), so the
> mean ± spread required by PLAN.md is **not available yet**. Treat the "C" row as one
> sample from a model sampled at temperature 0.3: differences of a few points between
> C and B may be noise. See `PROGRESS.md` for how to finish.


Model: `gemini:gemini-3.1-flash-lite` (temperature 0.3). Runs: 1. Findings triaged per run: 388; dropped per run: [19]; unparseable/uncertain per run: [0].

Mean ± sd over runs (A and B are deterministic).

| Configuration | Precision | Recall | FPR | Youden |
|---|--:|--:|--:|--:|
| A. Opengrep (sast-rules) | 0.675 | 0.600 | 0.289 | 0.311 |
| B. A + custom rules | 0.676 | 0.889 | 0.427 | 0.462 |
| C. B + LLM triage (1 runs) | 0.712 | 0.889 | 0.360 | 0.529 |

## Per category (precision / recall / FPR)

| Category | A. Opengrep (sast-rules) P / R / FPR | B. A + custom rules P / R / FPR | C. B + LLM triage (1 runs) P / R / FPR |
|---|---|---|---|
| cmdi | 0.600 / 1.000 / 0.667 | 0.600 / 1.000 / 0.667 | 0.618 / 1.000 / 0.619 |
| crypto | 0.818 / 0.857 / 0.190 | 0.818 / 0.857 / 0.190 | 0.818 / 0.857 / 0.190 |
| hash | 1.000 / 0.762 / 0.000 | 1.000 / 0.762 / 0.000 | 1.000 / 0.762 / 0.000 |
| ldapi | 0.538 / 1.000 / 0.857 | 0.538 / 1.000 / 0.857 | 0.538 / 1.000 / 0.857 |
| pathtraver | 0.568 / 1.000 / 0.762 | 0.568 / 1.000 / 0.762 | 0.583 / 1.000 / 0.714 |
| securecookie | 1.000 / 1.000 / 0.000 | 1.000 / 1.000 / 0.000 | 1.000 / 1.000 / 0.000 |
| sqli | n/a / 0.000 / 0.000 | 0.611 / 0.524 / 0.333 | 0.688 / 0.524 / 0.238 |
| trustbound | n/a / 0.000 / 0.000 | 0.576 / 0.905 / 0.667 | 0.633 / 0.905 / 0.524 |
| weakrand | n/a / 0.000 / 0.000 | 0.875 / 1.000 / 0.143 | 0.955 / 1.000 / 0.048 |
| xpathi | n/a / 0.000 / 0.000 | 0.667 / 0.933 / 0.467 | 0.667 / 0.933 / 0.467 |
| xss | 0.567 / 0.810 / 0.619 | 0.567 / 0.810 / 0.619 | 0.708 / 0.810 / 0.333 |
| overall | 0.675 / 0.600 / 0.289 | 0.676 / 0.889 / 0.427 | 0.712 / 0.889 / 0.360 |

## Reading these numbers

- **Custom rules (B vs A):** recall rises 0.600 -> 0.889 because the four categories
  with no rules (sqli, trustbound, weakrand, xpathi) now produce findings, but the
  false-positive rate also rises, 0.289 -> 0.427 (precision unchanged at 0.676). The
  new rules are broad and flag many of the Benchmark's "fake" vulnerabilities.
  Tuning them is future work.
- **Triage (C vs B), single run:** 19 of 388 findings dropped; FPR 0.427 -> 0.360,
  recall unchanged at 0.889, precision 0.676 -> 0.712. Gains are in xss, weakrand,
  sqli, trustbound and pathtraver; ldapi, hash, crypto, securecookie, xpathi did not move.
- The sample has 450 cases: one case is about 0.2 points of overall recall/FPR, and
  a per-category cell rests on about 20 real and 20 fake cases.
- Model: the LLM may have seen the public OWASP Benchmark in training, which could
  flatter triage.
