# Build steps: OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner

How to use: in Claude Code, just say **"Do the next step in BUILD_STEPS.md"**.

Rules for Claude when running a step:
1. Find the first step below whose box is unticked `- [ ]` and do only that step.
2. When it is complete, tick its box (`- [x]`), commit with the step name in the message, and push.
3. Then stop and give a short summary: what was built, key numbers, and any decision needed.

Step 1 (Kickoff & plan) happens in the Portfolio Builds Project; its output is PLAN.md.

## - [x] Step 2: Repo setup

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Set up the repository for "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner" following the folder structure in PLAN.md:
- Dependency files (requirements.txt or pyproject, plus package.json if there's a frontend) and a Dockerfile/docker-compose
- .gitignore, .env.example, pre-commit with formatting and linting
- A GitHub Actions workflow that runs the tests
- A README skeleton with the commands to run it locally on [Windows/macOS/Linux]
- A short CLAUDE.md with the project's coding rules
Create the files directly, run the tests to confirm the setup works, then commit and push.

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.

## - [x] Step 3: Data pipeline

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Build the data pipeline for "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner". Data / resources: OWASP Juice Shop, WebGoat, DVWA source and their documented vulnerability lists.
- Script(s) to download or load, clean, and split or sample the data, reproducibly (fixed seeds, saved splits)
- A short data report in /results: counts, class balance or distributions, sample records, and quality problems found
- Check each dataset's licence or terms and record them in the README

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.

## - [x] Step 4: Core feature

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Implement the first core feature of "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner":
Multi-language scanning (JS/TS, Python, PHP, Java)

Include unit tests. In LEARNING.md, cover the key ML or security concepts this feature relies on, with one short reading suggestion per concept, and how to run and check the feature.

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.

## - [ ] Step 5: Remaining features

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Implement the remaining features of "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner", in this order:
1. LLM triage that removes false positives from Semgrep output
2. Auto-fix suggestions verified by re-scanning
3. Benchmark page: precision/recall per OWASP category on Juice Shop, WebGoat, DVWA
4. GitHub App that comments on pull requests

Build them all without waiting for me between features. After each one: write its tests, run the full test suite, add its LEARNING.md entry, then commit and push before starting the next.

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.

## - [ ] Step 6: Evaluation

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Design and run the evaluation for "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner".
- Choose metrics that fit the project (record the reasons in LEARNING.md)
- Compare against at least one simple baseline
- Produce a results table and 2–3 clear charts, saved to /results
- Run each experiment with a fixed seed (and several seeds where it matters) and report variance
- Write an honest limitations section in /results: where results are weak and what would improve them

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.

## - [ ] Step 7: Demo & deploy

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Build the public demo for "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner" and prepare it for a free tier (Hugging Face Spaces, Streamlit Community Cloud, Render or Vercel — pick the best fit and note why in LEARNING.md).
- It must work without sign-up and load in under 10 seconds where possible
- Add example inputs so a visitor can try it in one click
- Keep API keys out of the code (use secrets)
- Put step-by-step deployment instructions in DEPLOY.md, and only stop for steps that need my own account login

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.

## - [ ] Step 8: README & write-up

Read PLAN.md and CLAUDE.md first, and follow them. If anything below conflicts with PLAN.md, PLAN.md wins. Commit and push after each completed task.

Write the finishing materials for "OWASP Sentinel: Hybrid LLM + SAST Vulnerability Scanner":
1. A polished README: one-line purpose, demo link and GIF placeholder, architecture diagram, results table, how to run, limitations, future work
2. A 120-word portfolio card description for my website (save as PORTFOLIO.md)
3. A 2–4 page technical write-up (problem, method, results, lessons learned) in docs/
4. One sentence connecting this project to current research in GenAI for Cybersecurity, which I can use when emailing professors such as those at: Finland GenAI-for-cyber PhD, BTU Cottbus (AI pentesting), UWE Bristol, TU Delft AI4SE, Leeds (LLM code correctness).

Don't explain steps in chat. Put plain-English explanations of what you built and why it matters in LEARNING.md. In chat, give me only a short summary at the end: what was built, key numbers, and any decision you need from me.
