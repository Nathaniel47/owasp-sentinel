# Deploying the demo

**Live (static, preliminary results):**
<https://ankomahaidoo-owasp-sentinel.static.hf.space/> (Space page:
<https://huggingface.co/spaces/ankomahaidoo/owasp-sentinel>)

## What is deployed, and why static

The public demo is a **static Hugging Face Space**: two plain HTML pages (home and
benchmark results) with a PRELIMINARY banner. There is no server, no scanner, no
JavaScript and no API key, so nothing can be abused and nothing costs money.

The live scanner (paste code, get findings, optional LLM triage) is built and tested,
but it needs a Docker host. Hugging Face now answers `402 Payment Required` for Docker
Spaces on free CPU (they need a PRO subscription), so the live scanner runs locally:

```powershell
docker build --target demo -t sentinel-demo .
docker run --rm -p 7860:7860 sentinel-demo   # http://localhost:7860
```

## Update the static Space

The pages are rendered from `results/benchmark.json` and `results/triage_eval.json`.
When Step 6 finishes (3 triage runs), the PRELIMINARY banner disappears by itself.

```powershell
python -m sentinel.bench.run_triage --runs 3 --eval-only   # refresh triage_eval.json
$env:PYTHONPATH = "."
python scripts/build_static.py                              # writes build/static/
```

Then upload (uses the Hugging Face login already on this machine; the token is never
printed or stored in the repo):

```powershell
.\.venv\Scripts\python -c "from huggingface_hub import HfApi; HfApi().upload_folder(folder_path='build/static', repo_id='ankomahaidoo/owasp-sentinel', repo_type='space', commit_message='Update results')"
```

Or log in with `huggingface-cli login` and use any other upload method. Static Spaces
update in seconds.

## If you later get a Docker host (PRO Space, Render, Fly.io, Cloud Run)

The `demo` stage of the `Dockerfile` is a complete image: web app, Opengrep, Bandit,
the MIT sast-rules at the pinned commit, merged rules and precomputed example scans.
For a Hugging Face PRO Docker Space, run `python scripts/build_space.py` and push
`build/space/` to a Space created with SDK Docker (its README card is
`deploy/space_card.md`). Secrets, if you want AI triage, go in the host's secrets
screen, never in code: `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`. **Use a different
key from the Step 6 evaluation key**; Gemini's free daily quota is per project and
the demo would use up what triage runs 2 and 3 need.

What protects the live version: the snippet is never executed (a fixed-name temp file
only the scanner reads); 20 KB input cap; 10 scans/minute/visitor and 2 at a time; a
60 s scanner timeout; LLM off unless a secret exists, with hourly and daily caps; no
JavaScript, HTML-escaped output and a strict Content-Security-Policy; the LLM verdict
only labels a finding and never hides it.
