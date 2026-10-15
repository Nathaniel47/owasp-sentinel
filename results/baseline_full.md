# Opengrep + GitLab sast-rules baseline, full OWASP Benchmark v1.2

2740 test cases, 1579 findings. A case is flagged when a finding in its file carries the category's CWE (`hash` also accepts CWE-327). Youden = recall - FPR (the Benchmark's own score).

| Category | TP | FP | TN | FN | Precision | Recall | FPR | Youden |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| cmdi | 126 | 94 | 31 | 0 | 0.57 | 1.00 | 0.75 | 0.25 |
| crypto | 105 | 27 | 89 | 25 | 0.80 | 0.81 | 0.23 | 0.57 |
| hash | 89 | 0 | 107 | 40 | 1.00 | 0.69 | 0.00 | 0.69 |
| ldapi | 27 | 27 | 5 | 0 | 0.50 | 1.00 | 0.84 | 0.16 |
| pathtraver | 127 | 115 | 20 | 6 | 0.52 | 0.95 | 0.85 | 0.10 |
| securecookie | 36 | 0 | 31 | 0 | 1.00 | 1.00 | 0.00 | 1.00 |
| sqli | 0 | 0 | 232 | 272 | n/a | 0.00 | 0.00 | 0.00 |
| trustbound | 0 | 0 | 43 | 83 | n/a | 0.00 | 0.00 | 0.00 |
| weakrand | 0 | 0 | 275 | 218 | n/a | 0.00 | 0.00 | 0.00 |
| xpathi | 0 | 0 | 20 | 15 | n/a | 0.00 | 0.00 | 0.00 |
| xss | 182 | 118 | 91 | 64 | 0.61 | 0.74 | 0.56 | 0.18 |
| overall | 692 | 381 | 944 | 723 | 0.64 | 0.49 | 0.29 | 0.20 |

## Same baseline on the 450-case stratified sample

| Category | TP | FP | TN | FN | Precision | Recall | FPR | Youden |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| cmdi | 21 | 14 | 7 | 0 | 0.60 | 1.00 | 0.67 | 0.33 |
| crypto | 18 | 4 | 17 | 3 | 0.82 | 0.86 | 0.19 | 0.67 |
| hash | 16 | 0 | 21 | 5 | 1.00 | 0.76 | 0.00 | 0.76 |
| ldapi | 21 | 18 | 3 | 0 | 0.54 | 1.00 | 0.86 | 0.14 |
| pathtraver | 21 | 16 | 5 | 0 | 0.57 | 1.00 | 0.76 | 0.24 |
| securecookie | 21 | 0 | 21 | 0 | 1.00 | 1.00 | 0.00 | 1.00 |
| sqli | 0 | 0 | 21 | 21 | n/a | 0.00 | 0.00 | 0.00 |
| trustbound | 0 | 0 | 21 | 21 | n/a | 0.00 | 0.00 | 0.00 |
| weakrand | 0 | 0 | 21 | 21 | n/a | 0.00 | 0.00 | 0.00 |
| xpathi | 0 | 0 | 15 | 15 | n/a | 0.00 | 0.00 | 0.00 |
| xss | 17 | 13 | 8 | 4 | 0.57 | 0.81 | 0.62 | 0.19 |
| overall | 135 | 65 | 160 | 90 | 0.68 | 0.60 | 0.29 | 0.31 |

## Benchmark categories the rules never flag

- sqli
- trustbound
- weakrand
- xpathi
