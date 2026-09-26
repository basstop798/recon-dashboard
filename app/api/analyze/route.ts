/**
 * AI Security Co-pilot endpoint.
 *
 * POST { findings: Finding[], target?: string } -> CopilotReport (JSON).
 *
 * ── Source-agnostic by design ────────────────────────────────────────────────
 * This route accepts `Finding[]` and does not care where they came from:
 *   • Plan A: the BulletRecon scan's derived findings (buildFindings()).
 *   • Plan B: findings parsed from a pasted/mock log in a fresh repo.
 * The whole co-pilot pipeline depends only on that shape, which is what makes the
 * hackathon A/B decision a 2-minute change on the day.
 *
 * ── Pipeline (Phase 0) ───────────────────────────────────────────────────────
 *   1. Validate the request body with Zod.
 *   2. Redact sensitive infra data from the findings (privacy before any API).
 *   3. Ground each finding against the local CVE KB (real citations, no hallucination).
 *   4. Run the advisor (mock today; Claude->Gemini->mock on build day).
 *   5. Return a validated CopilotReport.
 *
 * On build day only step 4's provider changes (inside lib/ai/advisor.ts). This
 * file stays essentially as-is. See BUILD_DAY.md.
 */

import type { NextRequest } from 'next/server';
import { z } from 'zod';

import { SEVERITIES, type Finding } from '@/lib/passive-recon/types';
import { analyze } from '@/lib/ai/advisor';
import { redactFindings } from '@/lib/ai/redact';

// This route calls out to a model API on build day, so it must run per-request.
export const dynamic = 'force-dynamic';
// Comfortable headroom for a model round-trip + one repair retry on build day.
export const maxDuration = 60;

/** Request validation. Mirrors the `Finding` shape from the engine. */
const findingSchema = z.object({
  id: z.string().min(1),
  module: z.string().min(1),
  severity: z.enum(SEVERITIES),
  title: z.string().min(1),
  detail: z.string().min(1),
  evidence: z.string().optional(),
});

const requestSchema = z.object({
  findings: z.array(findingSchema).min(1).max(200),
  target: z.string().max(255).optional(),
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function POST(request: NextRequest): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }

  const parsed = requestSchema.safeParse(body);
  if (!parsed.success) {
    return json(
      { error: 'Invalid request.', detail: z.prettifyError(parsed.error) },
      400,
    );
  }

  // Cast is safe: findingSchema is a structural subset of Finding, and module is
  // validated as a non-empty string (the engine's ModuleId is a string union).
  const findings = parsed.data.findings as Finding[];

  // Step 2: redact BEFORE anything leaves this process on build day.
  const redacted = redactFindings(findings);

  try {
    // Steps 3–5: ground + advise + assemble. Provider chosen inside analyze().
    const report = await analyze(redacted.value);

    return json({
      report,
      redaction: { total: redacted.total, counts: redacted.counts },
      target: parsed.data.target ?? null,
    });
  } catch (error) {
    // On build day this is where a total provider failure surfaces; the advisor
    // itself falls back to mock first, so reaching here should be rare.
    return json(
      {
        error: 'Analysis failed.',
        detail: error instanceof Error ? error.message : String(error),
      },
      502,
    );
  }
}
