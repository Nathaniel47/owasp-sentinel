# Deploying the demo (Hugging Face Spaces, free tier)

The demo is a Docker Space: one container with the web app, Opengrep and Bandit.
Visitors need no account. The only steps that need **your** login are 1 and 4.

Why Spaces and not Streamlit Cloud, Render or Vercel: see "Demo and deploy" in
[LEARNING.md](LEARNING.md). Short version: the app must run the Opengrep binary,
which only a Docker-based host gives us for free without a credit card.

## Before you start

- Results shown are **preliminary** (triage run 1 of 3) and the pages say so. When
  Step 6 finishes, `results/triage_eval.json` will report 3 runs and the banner
  disappears on its own; redeploy to publish the final numbers (step 6 below).
- The LLM key is optional. Without it the demo still scans; the "AI triage" checkbox
  just does not appear.
- **Do not reuse the key that Step 6 uses for evaluation.** Gemini's free tier caps
  requests per day per project; a shared key lets the demo use up the quota that
  triage runs 2 and 3 need. Make a second key in a different Google project, or
  leave the key out until Step 6 is done.

## 1. Create the Space (needs your login)

1. Sign up or log in at <https://huggingface.co>.
2. **New Space** -> name `owasp-sentinel` -> SDK **Docker** -> template **Blank** ->
   hardware **CPU basic (free)** -> visibility **Public** -> Create.

## 2. Add secrets (optional, needs your login)

Space -> **Settings** -> **Variables and secrets**. Add as **Secrets** (never in code):

| Name | Value |
|---|---|
| `LLM_PROVIDER` | `gemini` |
| `LLM_API_KEY` | the separate demo key |
| `LLM_MODEL` | `gemini-3.1-flash-lite` (or leave out for the default) |

Optional **Variable**: `DEMO_LLM_DAILY_CAP` (default 100 LLM calls per day, shared by
all visitors; each visitor is also limited to 6 AI-triaged scans per hour).

## 3. Build the Space folder

From the repo root (PowerShell):

```powershell
python scripts/build_space.py
```

This writes `build/space/` (git-ignored): the app, rules we own, the precomputed
results, the Dockerfile and the Space card (`deploy/space_card.md` as `README.md`).
It contains no secrets, no `targets/` source and no benchmark code. The MIT-licensed
sast-rules are downloaded at the pinned commit while the image builds.

## 4. Push it (needs your login and an access token)

Create a token at <https://huggingface.co/settings/tokens> with **Write** access.

```powershell
cd build/space
git init -b main
git remote add space https://huggingface.co/spaces/YOUR-USERNAME/owasp-sentinel
git add -A
git commit -m "Deploy demo"
git push space main --force
```

Git asks for a username (your Hugging Face name) and a password (paste the token).
`--force` is fine here: `build/space` is generated and the Space repo only holds
what this script produces.

## 5. Check it

The Space page shows "Building" for about 3 to 5 minutes, then the app. Then:

- `https://YOUR-USERNAME-owasp-sentinel.hf.space/health` returns `{"status":"ok",...}`.
- Click each example: results should appear instantly (they are precomputed at build).
- Paste something new and press Scan: expect about 5 to 15 seconds.
- `/benchmark` shows the yellow PRELIMINARY banner.

Free Spaces sleep after a period of inactivity and take a minute or so to wake, so
the first visit after a quiet spell is slower. Open the link yourself before sharing it.

## 6. Updating later

Rerun steps 3 and 4 (the script deletes and recreates `build/space`, so `git init` and
`git remote add` are needed again). Do this after Step 6 finishes so the demo shows the
final three-run numbers.

## Run the same image locally

```powershell
docker build --target demo -t sentinel-demo .
docker run --rm -p 7860:7860 sentinel-demo
```

Open <http://localhost:7860>. Add `-e LLM_PROVIDER=gemini -e LLM_API_KEY=...` to try
AI triage (use a throwaway key; it stays in your terminal history).

## What protects the demo

| Risk | Control |
|---|---|
| Running visitor code | Never executed. The snippet is written to a temp file with a fixed name and only read by the scanner, then deleted. |
| Huge input | Capped at 20,000 bytes (`MAX_SNIPPET_BYTES`), checked while the request body streams in. |
| Scan flooding | 10 scans per minute per visitor, 2 scans at a time, 60 s scanner timeout. |
| LLM cost | Off unless the secret exists; 6 triaged scans/hour/visitor, 8 findings per scan, shared daily cap. |
| API key leakage | Key lives only in Space secrets and the `x-goog-api-key` header; never in code, URLs, logs or error text. |
| Script injection | Pages use no JavaScript; output is HTML-escaped; a strict Content-Security-Policy is sent. |
| Prompt injection | Code is sent inside a `<code>` block with an instruction to ignore text in it; the verdict only labels a finding and never deletes it. |
