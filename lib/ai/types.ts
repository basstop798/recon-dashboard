/**
 * Contract for the AI Security Co-pilot layer.
 *
 * ── Why this file is the whole game ────────────────────────────────────────────
 * The co-pilot consumes `Finding[]` (defined in the passive-recon engine) and
 * NOTHING ELSE. It does not know — or care — whether those findings came from a
 * live BulletRecon scan (hackathon plan A) or from a pasted/mock log in a fresh
 * repo (plan B). One input shape, one output shape. That is what makes the whole
 * layer portable between the two plans in seconds on build day.
 *
 * The engine already gives us `Finding` (id, module, severity, title, detail,
 * evidence) and `buildFindings(report)` to derive them. We reuse both verbatim.
 *
 * ── What Phase 0 builds vs. what build day builds ─────────────────────────────
 * Phase 0 (pre-event, allowed): these types, the Zod schema, the mock advisor,
 * the empty route shell, the CVE knowledge base, and demo data.
 * BUILD DAY (27 Sep, scored as "built today"): the real grounding pipeline and
 * the live Claude/Gemini calls in `lib/ai/advise.ts`. See BUILD_DAY.md.
 */

import type { Finding, Severity } from '@/lib/passive-recon/types';

export type { Finding, Severity };

/**
 * A single CVE / weakness entry the co-pilot can ground a finding against.
 * Populated from `lib/ai/cve-kb.json`. Grounding = matching a finding to one of
 * these by service + version, so a remediation cites a REAL advisory rather than
 * whatever the model invented. This is the reliability + responsible-AI story.
 */
export interface KnowledgeEntry {
  /** CVE id, CWE id, or a stable internal id for a config-class weakness. */
  id: string;
  /** Human title of the weakness. */
  title: string;
  /** Service / technology this applies to, lowercased (e.g. "openssh"). */
  service: string;
  /** Affected version range in plain text, for display + prompt context. */
  affected: string;
  /**
   * Lowercased match tokens used by the build-day grounding step to link a
   * `Finding` to this entry — service names, finding-id prefixes, header names.
   * Grounding is a scored keyword match, never a fuzzy model guess.
   */
  keywords: string[];
  severity: Severity;
  /** One-sentence, non-technical explanation of the business risk. */
  summary: string;
  /** Ordered, safe remediation steps. Advisory, never auto-run. */
  remediation: string[];
  /** Authoritative source URL, shown as the citation on the card. */
  reference: string;
}

/**
 * The co-pilot's verdict for a single finding, after grounding + summarisation.
 * `grounded` is the trust signal the UI leans on: true = matched to a KB entry,
 * false = the model reasoned about it without a citation (shown more cautiously).
 */
export interface Assessment {
  /** Mirrors the source finding id, so the UI can line them up. */
  findingId: string;
  title: string;
  severity: Severity;
  /** Plain-language "what this means for your business" for a non-expert owner. */
  businessImpact: string;
  /** Ordered remediation steps, each phrased as advice a human reviews first. */
  remediation: string[];
  /** True when this was matched to a KB entry (a real citation exists). */
  grounded: boolean;
  /** KB reference URL when grounded; null otherwise. */
  reference: string | null;
  /** Which provider produced this ("anthropic" | "google" | "mock"). */
  source: string;
}

/**
 * The full co-pilot report the UI renders. `priority` re-ranks findings for a
 * non-expert (what to fix first), which is not the same as raw severity order.
 */
export interface CopilotReport {
  /** 0–100. Higher = more exposed. Derived from the assessment mix. */
  riskScore: number;
  /** One-paragraph executive summary for a founder with no security team. */
  executiveSummary: string;
  /** Assessments, already ordered worst-first / fix-first. */
  assessments: Assessment[];
  /** Provider that produced the report, plus whether a fallback fired. */
  meta: {
    provider: string;
    usedFallback: boolean;
    /** Count of findings that matched a KB entry — the grounding rate. */
    groundedCount: number;
    totalFindings: number;
  };
}

/** Request body accepted by POST /api/analyze. */
export interface AnalyzeRequest {
  /** The findings to assess. Source-agnostic by design (plan A or B). */
  findings: Finding[];
  /** Optional target label, purely for the report header. */
  target?: string;
}
