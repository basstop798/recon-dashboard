/**
 * The advisor: turns findings into a `CopilotReport` for a non-expert owner.
 *
 * ── Provider abstraction (why this shape) ─────────────────────────────────────
 * Everything downstream depends on the `Advisor` interface, not on a concrete
 * provider. Phase 0 ships ONE implementation — `mockAdvisor` — which is
 * deterministic, needs no API key, and lets the entire UI + route work today.
 *
 * BUILD DAY (scored as "built today"): add `anthropicAdvisor` and `googleAdvisor`
 * in this file (or siblings) implementing the same `Advisor` interface, then have
 * `getAdvisor()` prefer Claude, fall back to Gemini, and fall back to mock. The
 * grounding step and the whole report shape stay exactly as they are here, so the
 * swap is additive, not a rewrite. See BUILD_DAY.md for the precise steps.
 *
 * The mock is not throwaway: on build day it stays as the final fallback and as
 * "demo mode", so a dead network or a rate-limited key never breaks the demo.
 */

import { groundFindings, type GroundedFinding } from './grounding';
import { SEVERITY_ORDER } from '@/lib/passive-recon/types';
import type {
  Assessment,
  CopilotReport,
  Finding,
  Severity,
} from './types';

/** Weights used to turn a severity mix into a single 0–100 risk score. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
  info: 1,
};

/**
 * The more severe of two severities (lower SEVERITY_ORDER = worse). Grounding
 * must never DOWNGRADE a finding: if the engine flagged something critical, a KB
 * entry rated "high" should not soften it. We keep the worse of the two.
 */
function worstOf(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] ? a : b;
}

/**
 * Every provider (mock, Claude, Gemini) implements this. `assess` receives the
 * findings ALREADY grounded, so a provider's only job is to write the
 * business-impact prose and remediation wording — never to invent citations.
 */
export interface Advisor {
  readonly name: string;
  assess(grounded: GroundedFinding[]): Promise<Assessment[]>;
}

/**
 * Deterministic advisor. Produces genuinely useful, grounded output with no
 * model call: grounded findings get the KB's summary + remediation verbatim,
 * ungrounded ones get a sensible generic write-up derived from the finding.
 */
export const mockAdvisor: Advisor = {
  name: 'mock',
  async assess(grounded: GroundedFinding[]): Promise<Assessment[]> {
    return grounded.map(({ finding, match }): Assessment => {
      if (match) {
        return {
          findingId: finding.id,
          title: finding.title,
          severity: worstOf(finding.severity, match.severity),
          businessImpact: match.summary,
          remediation: match.remediation,
          grounded: true,
          reference: match.reference,
          source: 'mock',
        };
      }

      return {
        findingId: finding.id,
        title: finding.title,
        severity: finding.severity,
        businessImpact: genericImpact(finding),
        remediation: [
          'Review the evidence below with whoever manages this system.',
          'Confirm whether the exposure is real in your environment before acting.',
          'Apply the vendor-recommended fix or restrict access to the affected service.',
        ],
        grounded: false,
        reference: null,
        source: 'mock',
      };
    });
  },
};

function genericImpact(finding: Finding): string {
  const noun =
    finding.severity === 'critical' || finding.severity === 'high'
      ? 'a serious weakness'
      : 'a weakness';
  return `This is ${noun} an attacker could use against your systems. ${finding.detail}`;
}

/**
 * Phase 0 selector: always the mock. On build day this becomes the fallback
 * chain (Claude -> Gemini -> mock). Kept as a function so the route never
 * hard-codes a provider.
 */
export function getAdvisor(): Advisor {
  return mockAdvisor;
}

/**
 * The one entry point the route calls. Grounds the findings, runs the advisor,
 * then assembles the ranked `CopilotReport`. Provider-agnostic on purpose.
 */
export async function analyze(
  findings: Finding[],
  advisor: Advisor = getAdvisor(),
): Promise<CopilotReport> {
  const grounded = groundFindings(findings);
  const assessments = await advisor.assess(grounded);

  const ranked = rankAssessments(assessments);
  const groundedCount = grounded.filter((g) => g.match !== null).length;

  return {
    riskScore: computeRiskScore(ranked),
    executiveSummary: summarise(ranked, groundedCount),
    assessments: ranked,
    meta: {
      provider: advisor.name,
      usedFallback: false,
      groundedCount,
      totalFindings: findings.length,
    },
  };
}

/** Worst-first, with grounded findings ahead of ungrounded at equal severity. */
function rankAssessments(assessments: Assessment[]): Assessment[] {
  return [...assessments].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      Number(b.grounded) - Number(a.grounded) ||
      a.title.localeCompare(b.title),
  );
}

/**
 * Risk score 0–100. Diminishing returns so ten mediums do not read as ten
 * criticals, and a single critical still lands high. Tuned for a legible demo.
 */
function computeRiskScore(assessments: Assessment[]): number {
  let raw = 0;
  for (const a of assessments) raw += SEVERITY_WEIGHT[a.severity];
  // Squash with a curve that saturates near 100.
  const score = Math.round(100 * (1 - Math.exp(-raw / 60)));
  return Math.max(0, Math.min(100, score));
}

function summarise(assessments: Assessment[], groundedCount: number): string {
  const counts = assessments.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {});

  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const total = assessments.length;

  if (total === 0) {
    return 'No material security findings were identified in this data. Keep monitoring, but nothing here needs urgent action.';
  }

  const lead =
    critical > 0
      ? `We found ${critical} critical issue${critical === 1 ? '' : 's'} that should be fixed today`
      : high > 0
        ? `We found ${high} high-risk issue${high === 1 ? '' : 's'} worth fixing this week`
        : `We found ${total} issue${total === 1 ? '' : 's'}, none of them critical`;

  return `${lead}. ${groundedCount} of ${total} finding${total === 1 ? '' : 's'} were matched to a known, published advisory, so the fixes below are based on documented guidance rather than guesswork. Start at the top of the list and work down.`;
}
