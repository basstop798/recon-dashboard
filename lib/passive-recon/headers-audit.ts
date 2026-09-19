/**
 * Response-header posture analysis.
 *
 * Reads only what the single shared homepage GET already returned, so it costs
 * the target nothing extra. The checks mirror what a hunter eyeballs first: is
 * anything framing-, sniffing- or transport-protected, does CSP actually
 * constrain anything, and is the stack announcing its version to the world.
 */

import type { CookieRecord, PageIdentity, SecurityHeaderCheck, Severity } from './types';

interface HeaderSpec {
  header: string;
  severity: Severity;
  advice: string;
  /** Extra scrutiny once the header is present — returns a problem, or null. */
  inspect?: (value: string) => { severity: Severity; advice: string } | null;
}

/** Six months, the value HSTS preload requires. */
const HSTS_MIN_AGE = 15_552_000;

const SPECS: readonly HeaderSpec[] = [
  {
    header: 'strict-transport-security',
    severity: 'medium',
    advice: 'No HSTS — a first visit over http:// can be intercepted and downgraded.',
    inspect: (value) => {
      const maxAge = Number(value.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? '0');
      if (maxAge === 0) {
        return { severity: 'medium', advice: 'HSTS present but max-age=0 disables it.' };
      }
      if (maxAge < HSTS_MIN_AGE) {
        return {
          severity: 'low',
          advice: `HSTS max-age is ${maxAge}s — under the 15552000s preload threshold.`,
        };
      }
      return null;
    },
  },
  {
    header: 'content-security-policy',
    severity: 'medium',
    advice: 'No CSP — nothing constrains where scripts may be loaded or sent from.',
    inspect: (value) => {
      const problems: string[] = [];
      if (/'unsafe-inline'/i.test(value)) problems.push("'unsafe-inline'");
      if (/'unsafe-eval'/i.test(value)) problems.push("'unsafe-eval'");
      if (/(?:default|script)-src[^;]*\*(?!\.)/i.test(value)) problems.push('wildcard script source');

      return problems.length > 0
        ? {
            severity: 'low',
            advice: `CSP present but weakened by ${problems.join(', ')}.`,
          }
        : null;
    },
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    advice: 'No X-Frame-Options — check for a CSP frame-ancestors directive before calling clickjacking.',
  },
  {
    header: 'x-content-type-options',
    severity: 'low',
    advice: 'Missing nosniff — the browser may MIME-sniff a response into script.',
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    advice: 'No Referrer-Policy — full URLs (and any token in them) leak to third parties.',
  },
  {
    header: 'permissions-policy',
    severity: 'low',
    advice: 'No Permissions-Policy — camera, mic and geolocation stay available to embeds.',
  },
  {
    header: 'cross-origin-opener-policy',
    severity: 'low',
    advice: 'No COOP — a popup opener keeps a cross-origin window reference.',
  },
];

/** Headers whose mere presence hands an attacker version intelligence. */
const DISCLOSURE_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
] as const;

export interface HeadersAudit {
  checks: SecurityHeaderCheck[];
  grade: string;
}

/**
 * Runs every check and grades the result.
 *
 * The grade is a triage aid, not a score to report: it weights each failure by
 * severity and maps the remainder onto A–F so a wall of green headers is
 * distinguishable at a glance from a bare one.
 */
export function auditSecurityHeaders(headers: Headers): HeadersAudit {
  const checks: SecurityHeaderCheck[] = [];
  let penalty = 0;

  const csp = headers.get('content-security-policy') ?? '';

  for (const spec of SPECS) {
    const value = headers.get(spec.header);

    if (!value) {
      // A CSP that sets frame-ancestors is the modern replacement for XFO, so
      // reporting both as missing would be double-counting one weakness.
      if (spec.header === 'x-frame-options' && /frame-ancestors/i.test(csp)) {
        checks.push({
          header: spec.header,
          present: false,
          value: null,
          severity: 'info',
          advice: 'Superseded by the CSP frame-ancestors directive.',
        });
        continue;
      }

      checks.push({
        header: spec.header,
        present: false,
        value: null,
        severity: spec.severity,
        advice: spec.advice,
      });
      penalty += spec.severity === 'medium' ? 2 : 1;
      continue;
    }

    const problem = spec.inspect?.(value);
    checks.push({
      header: spec.header,
      present: true,
      value: value.slice(0, 300),
      severity: problem?.severity ?? 'info',
      advice: problem?.advice ?? 'Present.',
    });
    if (problem) penalty += 1;
  }

  const cors = headers.get('access-control-allow-origin');
  if (cors) {
    const credentials = headers.get('access-control-allow-credentials');
    const permissive = cors.trim() === '*';
    const withCredentials = credentials?.toLowerCase() === 'true';

    checks.push({
      header: 'access-control-allow-origin',
      present: true,
      value: cors.slice(0, 300),
      // `*` with credentials is rejected by browsers, but seeing both means the
      // origin is echoed somewhere — worth a manual Origin test.
      severity: withCredentials ? 'high' : permissive ? 'low' : 'info',
      advice: withCredentials
        ? 'CORS allows credentials — verify the allowed origin is not reflected from the request.'
        : permissive
          ? 'Wildcard CORS: any origin can read responses from this endpoint.'
          : 'Scoped CORS policy.',
    });
    if (withCredentials) penalty += 3;
  }

  for (const header of DISCLOSURE_HEADERS) {
    const value = headers.get(header);
    if (!value) continue;

    const versioned = /\d+\.\d+/.test(value);
    checks.push({
      header,
      present: true,
      value: value.slice(0, 300),
      severity: versioned ? 'low' : 'info',
      advice: versioned
        ? 'Discloses an exact version — maps directly to a CVE search.'
        : 'Discloses the underlying technology.',
    });
    if (versioned) penalty += 1;
  }

  const grade =
    penalty === 0 ? 'A' : penalty <= 2 ? 'B' : penalty <= 4 ? 'C' : penalty <= 6 ? 'D' : 'F';

  return { checks, grade };
}

/**
 * Reads cookie names and flags — never values.
 *
 * A session cookie's value is the session; this dashboard exports to disk and
 * gets pasted into reports, so the value must not exist in the payload at all.
 */
export function readCookies(headers: Headers): CookieRecord[] {
  const raw =
    typeof headers.getSetCookie === 'function'
      ? headers.getSetCookie()
      : headers.get('set-cookie')
        ? [headers.get('set-cookie') as string]
        : [];

  const cookies = new Map<string, CookieRecord>();

  for (const cookie of raw) {
    const name = cookie.split('=')[0]?.trim();
    if (!name) continue;

    // Attributes are separated by ';' and are case-insensitive per RFC 6265.
    const attributes = cookie.split(';').slice(1).map((part) => part.trim().toLowerCase());

    cookies.set(name, {
      name,
      secure: attributes.includes('secure'),
      httpOnly: attributes.includes('httponly'),
      sameSite:
        attributes
          .find((attribute) => attribute.startsWith('samesite='))
          ?.split('=')[1] ?? null,
    });
  }

  return [...cookies.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function metaContent(html: string, pattern: RegExp): string | null {
  const match = html.match(pattern);
  return match?.[1]?.trim().slice(0, 300) || null;
}

/** Pulls the page's own description of itself out of the returned markup. */
export function parsePageIdentity(html: string): PageIdentity {
  return {
    title: metaContent(html, /<title[^>]*>([\s\S]{0,300}?)<\/title>/i),
    description:
      metaContent(
        html,
        /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i,
      ) ??
      metaContent(
        html,
        /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']/i,
      ),
    generator: metaContent(
      html,
      /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*)["']/i,
    ),
    ogImage: metaContent(
      html,
      /<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']/i,
    ),
    lang: metaContent(html, /<html[^>]+lang=["']([^"']{2,15})["']/i),
  };
}
