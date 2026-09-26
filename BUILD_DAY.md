# BUILD_DAY.md — AI Security Co-pilot, 27 September 2026

**One-line pitch:** *An AI security co-pilot for small businesses and startups in
Africa that can't afford a security team — it turns raw recon findings into a
ranked, plain-language report with cited, human-reviewed fixes.*

All times are **Tunis time (UTC+1)**. Adjust for your country (e.g. Saudi = +2).
Real building only runs ~11:15–16:15; **submission closes 17:30**, not 20:00.

---

## The A/B decision (ask a mentor at the 11:30 checkpoint)

The whole layer consumes `Finding[]` and nothing else, so the source is swappable.

- **Plan A — build on BulletRecon (preferred).** The co-pilot reads findings from
  a live scan. In `app/copilot/page.tsx`, replace the demo/paste input with a call
  to the existing `/api/passive-recon` scan, run `buildFindings()` on the result,
  and pass that array to `/api/analyze`. **Everything else already works.**
  Be honest on the project card: "Built on my existing open-source passive-recon
  engine (MIT); the AI co-pilot layer was built during the hackathon."
- **Plan B — fresh AI-first repo.** If the mentor says pre-existing code is not
  allowed, copy `lib/ai/*`, `app/copilot/*`, and `app/api/analyze/*` into a new
  repo, plus the `Finding`/`Severity` types from `lib/passive-recon/types.ts`.
  Feed findings by pasting a scan log and parsing it (the paste box already exists).

Either way the co-pilot code is identical. **This is why Phase 0 targeted the
contract, not the plumbing.**

---

## What is ALREADY DONE (Phase 0 — pre-event, allowed scaffolding)

- `lib/ai/types.ts` — the contract (`Finding` in, `CopilotReport` out).
- `lib/ai/cve-kb.json` — 33-entry CVE/CWE knowledge base, every entry cited.
- `lib/ai/grounding.ts` — deterministic finding→advisory matching (anti-hallucination).
- `lib/ai/redact.ts` — masks IPs/emails/secrets before anything leaves the browser.
- `lib/ai/schema.ts` — Zod validation + `parseReport()` (fence/prose tolerant).
- `lib/ai/advisor.ts` — pipeline + **mock advisor** (works with no API key).
- `app/api/analyze/route.ts` — the endpoint (redact → ground → advise → validate).
- `app/copilot/page.tsx` + `components/report.tsx` — the UI (demo button, cards, risk gauge).
- `lib/ai/ai.test.ts` — 22 passing tests (grounding, redaction, ranking, schema).
- Demo data + demo mode: the 90-second demo runs offline, no network needed.

**Verified working:** `npm run build` ✓, `npm test` (119 tests) ✓, `npm run lint` ✓,
live `POST /api/analyze` returns a grounded report (riskScore 89, 10/10 grounded).

---

## What to BUILD ON BUILD DAY (this is the "built today" work that scores)

The only real gap is the **live LLM providers**. Right now `getAdvisor()` returns
the mock. On build day you add two providers behind the same `Advisor` interface.

### Sprint 1 (11:15–11:30) — smallest end-to-end LLM call
Goal: one real model call returns something the UI shows. Add to `lib/ai/advisor.ts`:

```ts
// Build a compact prompt from grounded findings and ask the model to write ONLY
// the business-impact + remediation prose. Grounding/citations stay in our code.
function buildPrompt(grounded: GroundedFinding[]): string {
  const items = grounded.map((g) => ({
    findingId: g.finding.id,
    title: g.finding.title,
    severity: g.match ? g.match.severity : g.finding.severity,
    detail: g.finding.detail,
    knownAdvisory: g.match
      ? { id: g.match.id, summary: g.match.summary, remediation: g.match.remediation }
      : null,
  }));
  return [
    'You are a security advisor for a small business owner with no security team.',
    'For each finding, write a plain-language businessImpact (no jargon) and 2-4',
    'remediation steps phrased as advice a human reviews before running.',
    'When knownAdvisory is present, base your remediation on it. Do NOT invent CVEs.',
    'Return STRICT JSON: {riskScore:0-100, executiveSummary, assessments:[{findingId,title,severity,businessImpact,remediation[]}]}',
    'FINDINGS:', JSON.stringify(items, null, 2),
  ].join('\n');
}
```

### Sprint 2 (11:45–13:00) — the real pipeline + repair retry (the core)
Add the two providers and the fallback chain:

```ts
import Anthropic from '@anthropic-ai/sdk';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { parseReport } from './schema';

// Each provider calls the model, then parseReport(). On a schema failure, re-ask
// ONCE with the error appended (the "repair retry" = the reliability story).
async function callWithRepair(
  send: (prompt: string) => Promise<string>,
  prompt: string,
): Promise<RawReport> {
  const first = parseReport(await send(prompt));
  if (first.ok) return first.report;
  const repair = parseReport(
    await send(prompt + `\n\nYour previous reply was invalid: ${first.error}\nReturn ONLY valid JSON matching the schema.`),
  );
  if (repair.ok) return repair.report;
  throw new Error('Model output failed validation twice: ' + repair.error);
}

// anthropicAdvisor + googleAdvisor: implement Advisor.assess() by calling
// callWithRepair, then MERGE our grounding (grounded flag + reference) onto the
// model's assessments by findingId. Model writes prose; we own the citations.
```

Then make `getAdvisor()` a chain and set `usedFallback` when Claude fails:

```ts
export async function analyze(findings, ...) {
  const grounded = groundFindings(findings);
  let assessments, provider = 'mock', usedFallback = false;
  for (const advisor of [anthropicAdvisor, googleAdvisor, mockAdvisor]) {
    try { assessments = await advisor.assess(grounded); provider = advisor.name; break; }
    catch { usedFallback = true; }  // try the next provider
  }
  // ...assemble report, set meta.provider + meta.usedFallback
}
```

**Test the fallback live in the demo:** unset `ANTHROPIC_API_KEY` for one run and
show it dropping to Gemini, then to mock. That visible resilience is rare and scores.

### Sprint 3 (14:00–15:30) — polish the "wow" moments
- Make the redaction banner **animate** (findings visibly scrub before "Analyze").
- If Plan A: wire the live scan → `buildFindings()` → co-pilot in `page.tsx`.
- Tighten the executive summary and risk gauge for the 90-second read.

### Final sprint (15:45–16:15) — freeze code, deploy, smoke-test
- `npm run build && npm test && npm run lint` must all pass.
- Deploy to Vercel; set `ANTHROPIC_API_KEY` + `GEMINI_API_KEY` in env vars.
- Curl `/api/analyze` on the live URL to confirm it works before recording.

---

## 90-second demo script (problem → product → proof → next)

1. **Problem (0:00–0:15):** "A small business runs a security scan and gets 200
   raw findings. No security team. They have no idea what's actually dangerous."
2. **Product (0:15–0:55):** Click **Analyze**. Watch the redaction banner scrub
   sensitive data. The ranked report appears: risk score, plain-language impact,
   numbered fixes, each with a "✓ Grounded in advisory" badge + real link.
3. **Proof (0:55–1:20):** "Every fix is matched to a real published advisory — the
   AI can't invent a CVE. And if the model provider goes down…" (show fallback).
4. **Next (1:20–1:30):** "Next: live scan integration and a bigger advisory base."

---

## Project card (fill in on the day)

- **Name:** BulletRecon AI Co-pilot
- **One-line:** AI security co-pilot that turns recon findings into cited, plain-language fixes for teams with no security staff.
- **AI tools used:** Anthropic Claude (primary), Google Gemini (fallback), a local
  CVE/CWE knowledge base for grounding, Zod for output validation.
- **AI contribution:** Model writes the business-impact + remediation prose;
  citations and severity come from our grounded knowledge base, not the model.
- **Fallback:** Claude → Gemini → deterministic local advisor, so the product
  works even with no network or a rate-limited key.
- **NVIDIA Brev:** Not used (solo participant; no strong-compute need).
- **Honesty note:** Built on my existing open-source passive-recon engine (MIT
  licensed); the AI co-pilot layer was built during the hackathon.

---

## Rubric self-check (100 pts)

| Criterion | Pts | How this build earns it |
|---|---|---|
| Problem + user value | 20 | Real, underserved audience (SMBs, no security team); reframed for impact. |
| Functional execution | 20 | Works live end-to-end; verified build + runtime. |
| Quality of AI use | 20 | Grounded pipeline, not a bare call; clear model/tool/workflow choices. |
| Testing + reliability | 15 | 22 tests, Zod + repair-retry, provider fallback, offline demo mode. |
| Experience + demo | 15 | Clean UI, 90-sec script, visible redaction + fallback moments. |
| Responsible AI + data | 10 | Redaction before send, human-review labels, real citations, no auto-run scripts. |
