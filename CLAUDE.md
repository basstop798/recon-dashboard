@AGENTS.md

# Hackathon context — read this first

## Who you are working with
- Solo participant in the GOMYCODE × NVIDIA "Come Build with AI" hackathon, **27 Sep 2026**.
- Talk to the user in **Arabic** (English technical terms are fine inline).
- The user knows TypeScript/Next.js and reads code, but relies on the assistant to write it.
  Explain simply, step by step, one idea at a time. Call out risks honestly and early.

## DECISION: fair play — brand-new project, NOT built on BulletRecon
The user decided (26 Sep) **not** to use BulletRecon or this repo for the hackathon, to keep
the competition fair. The hackathon project is a **new repo, created and coded on 27 Sep**.

- This repo (`recon-dashboard` / BulletRecon) is the user's earlier project. Do not submit it.
- The `feat/ai-copilot` branch here (`lib/ai`, `app/copilot`, `app/api/analyze`) was a
  pre-event prototype. Treat it as **reference only** — do not copy its code files into the
  hackathon repo. Write the hackathon code fresh on the day.
- Fair pre-event preparation (OK to reuse): the idea, the plan, the knowledge-base DATA
  (`lib/ai/cve-kb.json` — public CVE/CWE facts), sample scan logs for the demo, prompt drafts,
  the demo script and the project card. Declare these on the project card.
- The old A/B question for the mentor is obsolete: it is always the new repo.

## The hackathon project
**AI Security Co-pilot** — pitch: *an AI security co-pilot for small businesses and startups
in Africa that can't afford a security team. Paste a raw security scan (e.g. Nmap output) and
get a ranked, plain-language report with cited, human-reviewed fixes.*

Pipeline: paste raw log → redact sensitive data (IPs, emails, secrets) → extract findings
(open ports / services / versions) → ground each finding against the local CVE/CWE knowledge
base (real citations, no invented CVEs) → LLM writes plain-language impact + fixes → Zod
validation + one repair retry → provider fallback Claude → Gemini → deterministic local
advisor (the demo never breaks, even offline).

Stack: Next.js (App Router) + TypeScript + Tailwind, `@anthropic-ai/sdk`,
`@google/generative-ai`, `zod`, Vitest. Check `node_modules/next/dist/docs/` for the
installed Next.js version before writing framework code.

## Rules
- The model writes prose only. Citations and severity come from the knowledge base — never
  let the model invent CVE ids. Grounding must never downgrade severity.
- Keep a deterministic no-key fallback: it is the demo safety net.
- API keys live only in `.env.local` (gitignored). Never commit, print or paste keys.
- Build the smallest end-to-end slice first, then improve. Commit after each working step.
- Before saying anything is done: tests, lint and build must pass.
- Submission closes **17:30 Tunis time**, not 20:00. Stop coding by ~16:15.
