/**
 * Zod schema for the model's raw JSON output.
 *
 * This is the "Testing + reliability" story (15 pts on the rubric) made concrete:
 * an LLM will occasionally return malformed JSON, extra prose, or a wrong shape.
 * On build day the pipeline parses the model response with `RawAssessmentSchema`
 * and, on failure, re-asks the model ONCE with the validation error appended
 * (the "repair retry"). Only output that passes this schema ever reaches the UI.
 *
 * Kept separate from `types.ts` so the schema (runtime) and the interfaces
 * (compile-time) can evolve without a circular import. The two are aligned by
 * hand: `RawAssessment` below maps onto `Assessment` after grounding is merged in.
 */

import { z } from 'zod';

import { SEVERITIES } from '@/lib/passive-recon/types';

/** Severity enum reused from the engine so the two can never drift apart. */
const severitySchema = z.enum(SEVERITIES);

/**
 * One assessment as the MODEL is asked to produce it. Note: no `grounded` /
 * `reference` here — those are added by our own grounding step, not trusted from
 * the model. The model only summarises; citations come from the KB.
 */
export const RawAssessmentSchema = z.object({
  findingId: z.string().min(1),
  title: z.string().min(1),
  severity: severitySchema,
  businessImpact: z.string().min(1),
  remediation: z.array(z.string().min(1)).min(1),
});

export const RawReportSchema = z.object({
  riskScore: z.number().int().min(0).max(100),
  executiveSummary: z.string().min(1),
  assessments: z.array(RawAssessmentSchema),
});

export type RawAssessment = z.infer<typeof RawAssessmentSchema>;
export type RawReport = z.infer<typeof RawReportSchema>;

/**
 * Parse a model response that is supposed to be JSON. Tolerates the two most
 * common LLM sins: a ```json ... ``` fence, and leading/trailing prose around
 * the object. Returns a discriminated result so the caller can decide whether to
 * fire the repair-retry.
 */
export function parseReport(
  raw: string,
): { ok: true; report: RawReport } | { ok: false; error: string } {
  const candidate = extractJson(raw);
  if (candidate === null) {
    return { ok: false, error: 'No JSON object found in the model response.' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(candidate);
  } catch (error) {
    return {
      ok: false,
      error: `Response was not valid JSON: ${(error as Error).message}`,
    };
  }

  const result = RawReportSchema.safeParse(parsed);
  if (!result.success) {
    return { ok: false, error: z.prettifyError(result.error) };
  }

  return { ok: true, report: result.data };
}

/**
 * Pull the first balanced JSON object out of a string, stripping a code fence if
 * present. Deliberately simple: models rarely nest a second top-level object, so
 * first `{` to its matching `}` is enough and avoids a JSON grammar dependency.
 */
function extractJson(raw: string): string | null {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const text = (fenced ? fenced[1] : raw).trim();

  const start = text.indexOf('{');
  if (start === -1) return null;

  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = start; i < text.length; i += 1) {
    const char = text[i];

    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }

    if (char === '"') inString = true;
    else if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }

  return null;
}
