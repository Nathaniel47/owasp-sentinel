# Check of `owasp_2025.yaml` against the official OWASP Top 10 2025

Date: 2026-10-15. Source: the "List of Mapped CWEs" section of each category page at
<https://top10.owasp.org/2025/> (A01 to A10). Category names and IDs matched the
draft exactly. The CWE lists were read through a summarising page fetch, not
downloaded as raw HTML, so re-check any single CWE you plan to quote.

## What the draft got wrong

The draft file was written from memory and listed 74 CWEs; the official lists hold
249. Four draft entries were in the wrong place and the rest of the draft was
incomplete (per-category counts now match the page totals: A01 40, A02 16, A03 6, A04 32, A05 37, A06 39, A07 36, A08 14, A09 5, A10 24):

| CWE | Draft | Official |
|---|---|---|
| 35 (Path Traversal: `.../...//`) | A01 | not in any 2025 list (removed) |
| 1275 (SameSite cookie) | A02 | A01 |
| 829 (Untrusted control sphere) | A03 | A08 |
| 209 (Error message with sensitive info) | A06 | A10 |

Missing entries (not wrong, just absent): A01 26, A02 12, A03 5, A04 21, A05 24,
A06 36, A07 30, A08 7, A09 1, A10 17. The file is now the full official set, and a
unit test (`tests/test_evaluation.py`) checks spot values and that no CWE appears in
two categories.

## Effect on the Benchmark numbers

None. The eleven CWEs the OWASP Benchmark uses map the same way before and after:

| Benchmark category | CWE | OWASP 2025 |
|---|---|---|
| pathtraver | 22 | A01 |
| securecookie | 614 | A02 |
| crypto / hash / weakrand | 327 / 328 / 330 | A04 |
| cmdi / ldapi / sqli / xpathi / xss | 78 / 90 / 89 / 643 / 79 | A05 |
| trustbound | 501 | A06 |

So `results/coverage.md` is unchanged: A01, A02, A04, A05, A06 are Measured, and
A03, A07, A08, A09, A10 are Not covered (the Benchmark has no cases for them).
A mapped list is not a test: "Measured" only means ground truth exists for at least
one CWE in that category, mostly 1 to 5 CWEs out of 14 to 40 per category.
