/**
 * Credential-pattern scanning for JavaScript bundles (SecretFinder-style).
 *
 * Pure and network-free: the route fetches, this file interprets. Every rule is
 * anchored on a vendor-specific prefix wherever one exists, because the generic
 * `apiKey = "..."` shape produces far more noise than signal on a minified
 * bundle — those looser rules exist too, but they are scored `medium` at best
 * so the dashboard never shouts about a build hash.
 *
 * Matches are redacted before they leave this module. A recon dashboard is a
 * thing operators screenshot and paste into reports; handing back a live,
 * copy-pasteable credential would turn a finding into an incident.
 */

import type { SecretMatch, Severity } from './types';

interface SecretRule {
  name: string;
  pattern: RegExp;
  severity: Severity;
  /**
   * Keeps a rule from firing on its own placeholder documentation — a bundle
   * that ships `AKIAIOSFODNN7EXAMPLE` is quoting the AWS docs, not leaking.
   */
  ignore?: RegExp;
}

/** Well-known dummy values that appear in vendor docs and test fixtures. */
const PLACEHOLDER_RE =
  /example|sample|dummy|placeholder|your[_-]?(?:api|key|token|secret)|xxxx|0{8,}|1234567890|test[_-]?key/i;

const RULES: readonly SecretRule[] = [
  {
    name: 'Private key block',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    name: 'AWS access key ID',
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    severity: 'critical',
  },
  {
    name: 'AWS secret access key',
    pattern:
      /aws_?secret_?access_?key["'\s:=]{1,10}["']([A-Za-z0-9/+=]{40})["']/gi,
    severity: 'critical',
  },
  {
    name: 'Stripe live secret key',
    pattern: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g,
    severity: 'critical',
  },
  {
    name: 'GitHub token',
    pattern: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g,
    severity: 'critical',
  },
  {
    name: 'GitLab personal access token',
    pattern: /\bglpat-[0-9A-Za-z_-]{20,}\b/g,
    severity: 'critical',
  },
  {
    name: 'Slack token',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,60}\b/g,
    severity: 'critical',
  },
  {
    name: 'Slack webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]+\/B[0-9A-Za-z]+\/[0-9A-Za-z]+/g,
    severity: 'high',
  },
  {
    name: 'SendGrid API key',
    pattern: /\bSG\.[0-9A-Za-z_-]{16,32}\.[0-9A-Za-z_-]{16,64}\b/g,
    severity: 'critical',
  },
  {
    name: 'Twilio API key',
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    severity: 'high',
  },
  {
    name: 'Shopify access token',
    pattern: /\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b/g,
    severity: 'critical',
  },
  {
    name: 'npm access token',
    pattern: /\bnpm_[0-9A-Za-z]{36}\b/g,
    severity: 'critical',
  },
  {
    name: 'Mailgun API key',
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/g,
    severity: 'high',
  },
  {
    name: 'Mailchimp API key',
    pattern: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
    severity: 'high',
  },
  {
    name: 'Cloudinary credentials URL',
    pattern: /cloudinary:\/\/[0-9]{12,}:[0-9A-Za-z_-]+@[0-9A-Za-z_-]+/g,
    severity: 'critical',
  },
  {
    name: 'Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    // Browser-restricted Maps/Firebase keys are shipped to clients by design,
    // so this is a lead to check for missing referrer restrictions, not a
    // guaranteed leak.
    severity: 'medium',
  },
  {
    name: 'Google OAuth client ID',
    pattern: /\b[0-9]+-[0-9a-z_]{20,}\.apps\.googleusercontent\.com\b/g,
    severity: 'low',
  },
  {
    name: 'Firebase database URL',
    pattern: /\bhttps:\/\/[a-z0-9-]+\.firebaseio\.com\b/g,
    severity: 'medium',
  },
  {
    name: 'Basic auth in URL',
    pattern: /\bhttps?:\/\/[A-Za-z0-9._~-]+:[^\s/"'@]{3,}@[A-Za-z0-9.-]+/g,
    severity: 'high',
  },
  {
    name: 'JSON Web Token',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    severity: 'medium',
  },
  {
    name: 'Hardcoded bearer token',
    pattern: /\b(?:bearer|authorization)["'\s:=]{1,10}["']([A-Za-z0-9._-]{20,})["']/gi,
    severity: 'medium',
  },
  {
    name: 'Generic API key assignment',
    pattern:
      /\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|app[_-]?secret|private[_-]?key)["'\s:=]{1,10}["']([A-Za-z0-9_\-/+=.]{16,80})["']/gi,
    severity: 'medium',
  },
  {
    name: 'Hardcoded password assignment',
    pattern: /\b(?:password|passwd|pwd)["'\s:=]{1,10}["']([^"'\s]{6,40})["']/gi,
    severity: 'medium',
  },
];

/**
 * Masks a match so the finding is recognisable but not usable.
 *
 * Long values keep their first 6 and last 4 characters — enough to locate the
 * string in the bundle and to tell two different keys apart.
 */
export function redactSecret(value: string): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  if (flat.length <= 12) return `${flat.slice(0, 3)}…`;
  return `${flat.slice(0, 6)}…${flat.slice(-4)} (${flat.length} chars)`;
}

/**
 * Scans one source file for credential patterns.
 *
 * @param text   File contents (already byte-capped by the caller).
 * @param source Where it came from, so a finding is traceable to a URL.
 */
export function scanSecrets(text: string, source: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  // Deduplicated by *value*, not by rule: `apiKey: "AIza…"` matches both the
  // Google rule and the generic assignment rule, and reporting one leaked key
  // twice under two severities is noise. RULES is ordered specific-first, so
  // the vendor rule wins — the same "first match wins" convention the
  // technology fingerprinter uses.
  const seen = new Set<string>();

  for (const rule of RULES) {
    // The rules are module-level and carry /g, so lastIndex must be reset or a
    // previous file's scan position leaks into this one.
    rule.pattern.lastIndex = 0;
    let hits = 0;

    for (const match of text.matchAll(rule.pattern)) {
      // Prefer the capture group (the value) over the whole assignment.
      const raw = (match[1] ?? match[0]).trim();
      if (!raw) continue;
      if (PLACEHOLDER_RE.test(raw)) continue;
      if (rule.ignore?.test(raw)) continue;

      if (seen.has(raw)) continue;
      seen.add(raw);

      out.push({
        rule: rule.name,
        severity: rule.severity,
        match: redactSecret(raw),
        source,
      });

      // A handful of examples per rule per file is enough to act on; a
      // minified bundle can otherwise emit hundreds of near-identical JWTs.
      hits += 1;
      if (hits >= 5) break;
    }
  }

  return out;
}

/** `//# sourceMappingURL=` references, resolved against the bundle's own URL. */
export function extractSourceMaps(text: string, baseUrl: string): string[] {
  const out = new Set<string>();

  for (const match of text.matchAll(/\/[/*]#\s*sourceMappingURL\s*=\s*(\S+?)(?:\s*\*\/|\s|$)/g)) {
    const raw = match[1]?.trim();
    if (!raw || raw.startsWith('data:')) continue;

    try {
      const resolved = new URL(raw, baseUrl);
      if (resolved.protocol === 'http:' || resolved.protocol === 'https:') {
        out.add(resolved.toString());
      }
    } catch {
      continue;
    }
  }

  return [...out];
}
