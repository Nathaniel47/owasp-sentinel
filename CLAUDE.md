# CLAUDE.md

Project: OWASP Sentinel. Scope and layout are defined in PLAN.md; follow them.

## Coding rules
- Python 3.11, type hints on all functions. Format with black, lint with ruff (line length 88).
- Use Pydantic models for data crossing module boundaries (e.g. `Finding`).
- Scanners only read code. Never execute scanned or user-supplied code.
- Every LLM call goes through the provider interface in `sentinel/llm/` and the cache.
- Never commit secrets or vendored benchmark source; targets are fetched at pinned commits.
- Each module gets tests; language fixtures live in `tests/fixtures/<language>/`.
- Report metrics only where ground truth exists; unmeasured OWASP categories are "Not covered".
- Keep to PLAN.md scope: no new features beyond it without asking.
