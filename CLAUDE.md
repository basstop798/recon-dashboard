@AGENTS.md

# Hackathon context — read this first

## Who you are working with
- Solo participant in the GOMYCODE × NVIDIA "Come Build with AI" hackathon, **27 Sep 2026**.
- Talk to the user in **Arabic** (English technical terms are fine inline).
- The user knows TypeScript/Next.js and reads code, but relies on the assistant to write it.
  Explain simply, step by step, one idea at a time. Call out risks honestly and early.

## The project
**AI Security Co-pilot** built on top of BulletRecon (this repo, a passive-recon OSINT tool).
Pitch: *an AI security co-pilot for small businesses and startups in Africa that can't afford a
security team — it turns raw recon findings into a ranked, plain-language report with cited,
human-reviewed fixes.*

## Where everything is
- `BUILD_DAY.md` — **the build-day playbook**: schedule, A/B decision, exact code for the
  remaining work, 90-second demo script, project card, rubric check. Follow it.
- `lib/ai/` — the co-pilot layer (types, grounding, redaction, Zod schema, advisor, KB, tests).
- `app/api/analyze/route.ts` — endpoint: redact → ground → advise → validate.
- `app/copilot/` — the UI at `/copilot` (has a "Load demo scan" offline demo mode).
- Branch: `feat/ai-copilot`. Do not touch `master`.

## Status
- Phase 0 is done and committed: the pipeline runs end-to-end with **no API key** via
  `mockAdvisor`. 120 tests pass; build and lint are clean.
- **Remaining build-day work:** add live Claude (`@anthropic-ai/sdk`) and Gemini
  (`@google/generative-ai`) advisors in `lib/ai/advisor.ts` behind the existing `Advisor`
  interface, with the Claude → Gemini → mock fallback chain and the one-shot repair retry
  using `parseReport()` from `lib/ai/schema.ts`. See BUILD_DAY.md "Sprint 1" and "Sprint 2".
- Open question for the mentor at 11:30: is building on pre-existing own open-source code
  allowed? Yes → Plan A (wire the live scan). No → Plan B (copy `lib/ai`, `app/copilot`,
  `app/api/analyze` into a fresh repo).

## Rules
- The model writes prose only. Citations and severity come from `lib/ai/cve-kb.json` via
  `lib/ai/grounding.ts` — never let the model invent CVE ids.
- Grounding must never downgrade severity (`worstOf` in advisor.ts).
- Keep the mock advisor: it is the final fallback and the demo safety net.
- API keys live only in `.env.local` (gitignored). Never commit, print or paste keys.
- Before saying anything is done: `npm test`, `npm run lint`, `npm run build` must pass.
- Submission closes **17:30 Tunis time**, not 20:00. Stop coding by ~16:15.
