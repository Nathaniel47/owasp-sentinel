# Portfolio card: OWASP Sentinel

**OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner**

OWASP Sentinel finds security flaws in Java, JavaScript and Python code. It combines open-source static analysis with a custom Java rule pack, then asks an LLM to separate real vulnerabilities from false alarms, with every model call cached for reproducibility. Findings map to the OWASP Top 10 (2025), and suggested fixes are accepted only if a re-scan confirms them. I measured it on the OWASP Benchmark with known answers: custom rules lifted recall from 0.60 to 0.89, and triage on a first run cut the false-positive rate from 0.43 to 0.36 (preliminary: three-run results pending). Categories without ground truth are reported as "Not covered" rather than guessed. Built with Python, FastAPI, Docker, Opengrep and Gemini; scanned code is never executed.

Links: [GitHub](https://github.com/Nathaniel47/owasp-sentinel) · [Live demo](https://ankomahaidoo-owasp-sentinel.static.hf.space/)

<!-- Update the numbers after triage runs 2 and 3 finish. -->
