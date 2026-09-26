/**
 * Grounding: link a `Finding` to a real CVE / weakness in the knowledge base.
 *
 * This is the anti-hallucination core and it is PURE, DETERMINISTIC CODE — no
 * model involved. A finding is matched to a KB entry by a scored keyword overlap
 * against the finding's id prefix, title, detail and evidence. Because the match
 * is code, every citation the UI shows is real: the model never gets to invent a
 * CVE number.
 *
 * Used by both the mock advisor (Phase 0) and the live pipeline (build day).
 * Keeping it here, provider-free, is what lets the Claude/Gemini swap on build
 * day be small: the providers only summarise; grounding stays identical.
 */

import kb from './cve-kb.json';
import type { Finding, KnowledgeEntry } from './types';

const KNOWLEDGE = kb as KnowledgeEntry[];

export function knowledgeBase(): KnowledgeEntry[] {
  return KNOWLEDGE;
}

/** A finding paired with its best KB match (or null when nothing scores). */
export interface GroundedFinding {
  finding: Finding;
  match: KnowledgeEntry | null;
  /** Match confidence 0..1, for debugging / display. */
  score: number;
}

/**
 * Score how well a KB entry explains a finding. Higher = better. The finding's
 * id prefix (e.g. "header:", "mail:spf-permissive", "secret:") is the strongest
 * signal because the engine's ids are stable, so it is weighted heaviest.
 */
function scoreMatch(finding: Finding, entry: KnowledgeEntry): number {
  const haystack = [
    finding.id,
    finding.title,
    finding.detail,
    finding.evidence ?? '',
    finding.module,
  ]
    .join(' ')
    .toLowerCase();

  let score = 0;
  for (const keyword of entry.keywords) {
    if (haystack.includes(keyword.toLowerCase())) {
      // Longer keywords are more specific, so they earn more.
      score += keyword.length >= 5 ? 2 : 1;
    }
  }

  // Service name appearing verbatim is a strong corroborating signal.
  if (entry.service.length >= 3 && haystack.includes(entry.service.toLowerCase())) {
    score += 2;
  }

  return score;
}

/** Ground one finding against the whole KB, returning the best match. */
export function groundFinding(finding: Finding): GroundedFinding {
  let best: KnowledgeEntry | null = null;
  let bestScore = 0;

  for (const entry of KNOWLEDGE) {
    const score = scoreMatch(finding, entry);
    if (score > bestScore) {
      bestScore = score;
      best = entry;
    }
  }

  // Require a minimum score so a single incidental word does not force a bogus
  // citation. Below the threshold we return no match and the finding is handled
  // ungrounded (the model reasons about it, shown with lower confidence).
  const MIN_SCORE = 3;
  if (bestScore < MIN_SCORE) {
    return { finding, match: null, score: bestScore };
  }

  // Normalise to a rough 0..1 for display.
  return { finding, match: best, score: Math.min(1, bestScore / 8) };
}

/** Ground a whole batch. */
export function groundFindings(findings: Finding[]): GroundedFinding[] {
  return findings.map(groundFinding);
}
