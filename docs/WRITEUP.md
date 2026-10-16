# OWASP Sentinel: can an LLM cut the false positives of static analysis?

Nathaniel Ankomah Aidoo. **Status: preliminary.** LLM triage results come from one run
of three planned; final numbers are marked `TBD`.

## 1. Problem

Static application security testing (SAST) tools find real vulnerabilities but bury them
in false positives, so developers stop reading the output. Large language models can
read the code around a finding and judge whether it is exploitable, but they are
non-deterministic, cost money per call, and are rarely measured against ground truth.
OWASP Sentinel asks a narrow, measurable question: **does an LLM second opinion lower
the false-positive rate of an open-source SAST pipeline without losing real findings?**

## 2. Method

**Scanning.** Opengrep (an open fork of Semgrep) runs GitLab's MIT-licensed `sast-rules`
at a pinned commit; Bandit covers Python. Rules licences were checked, and rule sets that
forbid hosted use were rejected. Findings are normalised from SARIF into one `Finding`
model and mapped from CWE to OWASP Top 10 2025 using a YAML map verified against all ten
official category pages (249 CWEs, no mismatches).

**Custom rules.** The open Java rules had no coverage for four Benchmark categories (SQL
injection, trust boundary, weak randomness, XPath injection). I wrote a rule pack in
`rules/java/` (631 findings on the full Benchmark).

**Triage.** Each finding plus surrounding code goes to an LLM (`gemini-3.1-flash-lite`,
temperature 0.3) through a provider interface and an on-disk cache keyed by prompt, model
and run. It returns a structured verdict. Only confident false positives are dropped; an
uncertain or unparseable answer keeps the finding. Fixes are verified by applying the
patch to a temporary copy and re-scanning.

**Evaluation.** Ground truth is the OWASP Benchmark v1.2 expected-results file (Java).
Baselines run on all 2,740 cases; LLM triage runs on a fixed-seed 450-case sample
stratified over 11 categories, balanced between real and fake vulnerabilities. Metrics are
precision, recall and false-positive rate (FPR); a category with no ground truth gets no
metric and is shown as "Not covered". Three triage runs per model are planned to report
mean and spread.

## 3. Results

450-case sample, Java:

| Configuration | Precision | Recall | FPR |
|---|--:|--:|--:|
| A. Opengrep + sast-rules | 0.675 | 0.600 | 0.289 |
| B. A + custom rules | 0.676 | 0.889 | 0.427 |
| C. B + LLM triage, **run 1 only (preliminary)** | 0.712 | 0.889 | 0.360 |
| C. B + LLM triage, **3-run mean ± sd** | TBD | TBD | TBD |

- Custom rules (A to B) lift recall by 29 points because four categories go from zero
  detections to most of them, but FPR rises 14 points: the new rules are broad.
- Triage (B to C, single run) dropped 19 of 388 findings, lowered FPR 0.427 to 0.360 and
  kept recall unchanged. Gains concentrate in xss, weakrand, sqli, trustbound and
  pathtraver; ldapi, crypto, hash, securecookie and xpathi did not move.
- One case is about 0.2 points of overall recall or FPR, and a per-category cell rests on
  about 20 real and 20 fake cases, so small per-category differences are not meaningful.

## 4. Lessons learned

1. **Ground truth first.** Scoring against the Benchmark exposed that adding rules
   trades recall for FPR; without labels that trade would have looked like progress.
2. **A conservative triage policy is safe but weak.** Dropping only confident false
   positives never hurt recall, yet removed only 5% of findings; the rest of the FPR
   problem is the rules' fault, not the model's.
3. **Free-tier quotas shape experiments.** A 500 requests/day cap forced a cache-backed,
   resumable runner and is why three-run variance is still pending.
4. **Report what is not measured.** Five of ten OWASP 2025 categories have no ground
   truth here and are labelled "Not covered".

## 5. Limitations and threats to validity

Single benchmark and language; the Benchmark is public and may be in the model's training
data, which could flatter triage; the Benchmark's "vulnerabilities" are synthetic;
temperature 0.3 makes single runs noisy; the public demo is static because free hosting
no longer offers Docker Spaces.

## 6. Future work

Finish three runs and report spread; tune custom rules; compare an open-weights model;
score Juice Shop with a hand-labelled set; evaluate on newly written, contamination-free
code.
