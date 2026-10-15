# Opengrep + sast-rules + Sentinel custom rules, full OWASP Benchmark

Adds `rules/java` (631 findings) for SQL injection, trust boundary, weak random and XPath injection. Same scoring as the baseline.

| Category | TP | FP | TN | FN | Precision | Recall | FPR | Youden |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| cmdi | 126 | 94 | 31 | 0 | 0.57 | 1.00 | 0.75 | 0.25 |
| crypto | 105 | 27 | 89 | 25 | 0.80 | 0.81 | 0.23 | 0.57 |
| hash | 89 | 0 | 107 | 40 | 1.00 | 0.69 | 0.00 | 0.69 |
| ldapi | 27 | 27 | 5 | 0 | 0.50 | 1.00 | 0.84 | 0.16 |
| pathtraver | 127 | 115 | 20 | 6 | 0.52 | 0.95 | 0.85 | 0.10 |
| securecookie | 36 | 0 | 31 | 0 | 1.00 | 1.00 | 0.00 | 1.00 |
| sqli | 156 | 86 | 146 | 116 | 0.64 | 0.57 | 0.37 | 0.20 |
| trustbound | 72 | 23 | 20 | 11 | 0.76 | 0.87 | 0.53 | 0.33 |
| weakrand | 218 | 52 | 223 | 0 | 0.81 | 1.00 | 0.19 | 0.81 |
| xpathi | 14 | 10 | 10 | 1 | 0.58 | 0.93 | 0.50 | 0.43 |
| xss | 182 | 118 | 91 | 64 | 0.61 | 0.74 | 0.56 | 0.18 |
| overall | 1152 | 552 | 773 | 263 | 0.68 | 0.81 | 0.42 | 0.40 |

## 450-case sample

| Category | TP | FP | TN | FN | Precision | Recall | FPR | Youden |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| cmdi | 21 | 14 | 7 | 0 | 0.60 | 1.00 | 0.67 | 0.33 |
| crypto | 18 | 4 | 17 | 3 | 0.82 | 0.86 | 0.19 | 0.67 |
| hash | 16 | 0 | 21 | 5 | 1.00 | 0.76 | 0.00 | 0.76 |
| ldapi | 21 | 18 | 3 | 0 | 0.54 | 1.00 | 0.86 | 0.14 |
| pathtraver | 21 | 16 | 5 | 0 | 0.57 | 1.00 | 0.76 | 0.24 |
| securecookie | 21 | 0 | 21 | 0 | 1.00 | 1.00 | 0.00 | 1.00 |
| sqli | 11 | 7 | 14 | 10 | 0.61 | 0.52 | 0.33 | 0.19 |
| trustbound | 19 | 14 | 7 | 2 | 0.58 | 0.90 | 0.67 | 0.24 |
| weakrand | 21 | 3 | 18 | 0 | 0.88 | 1.00 | 0.14 | 0.86 |
| xpathi | 14 | 7 | 8 | 1 | 0.67 | 0.93 | 0.47 | 0.47 |
| xss | 17 | 13 | 8 | 4 | 0.57 | 0.81 | 0.62 | 0.19 |
| overall | 200 | 96 | 129 | 25 | 0.68 | 0.89 | 0.43 | 0.46 |
