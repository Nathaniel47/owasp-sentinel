# Real scan smoke test (Opengrep v1.31.0 in Docker, GitLab sast-rules @ 53bf5cf6df)

| Target | Rules | Findings |
|---|---|---|
| Juice Shop @ e39a3bdb8c (whole repo) | sast-rules/javascript | 32 (26 path traversal, A01) |
| OWASP Benchmark, first 100 test files (BenchmarkTest00001-00100) | sast-rules/java | 65 (A04: 24, A05: 18, A01: 15, A02: 1) |

Unscored: raw counts only. No ground-truth comparison yet, so no precision/recall claim.
Juice Shop: 4 findings are in files with an extension outside our language map ("unknown").
Raw findings JSON is git-ignored (it embeds Benchmark snippets, GPL).
