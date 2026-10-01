import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { buildFindings, countBySeverity } from './findings';
import {
  SEVERITY_ORDER,
  type DmarcInfo,
  type Finding,
  type ModuleId,
  type ScanReport,
  type SpfInfo,
} from './types';

/**
 * `buildFindings` is the triage layer: it answers "what here is worth my next
 * hour?", and the dashboard, the Markdown export and the JSON export all read
 * it, so a wrong answer here is wrong in three places at once.
 *
 * Most of these tests are negative cases. A finding that is merely noisy
 * teaches an operator to ignore the feed, which costs more than the finding
 * was ever worth.
 */

const MODULE_IDS: ModuleId[] = [
  'subdomains',
  'takeover',
  'dns',
  'mail',
  'whois',
  'tech',
  'js-endpoints',
  'archived',
  'url-intel',
  'meta',
];

/** A report where every module is still pending — the partial-report case. */
function emptyReport(): ScanReport {
  const modules = {} as ScanReport['modules'];
  for (const id of MODULE_IDS) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (modules as any)[id] = { status: 'pending', durationMs: null, error: null, data: null };
  }
  return {
    domain: 'example.com',
    startedAt: '2026-10-01T00:00:00.000Z',
    finishedAt: null,
    durationMs: null,
    modules,
  };
}

/** Builds a report carrying data for exactly one module. */
function reportWith(id: ModuleId, data: unknown): ScanReport {
  const report = emptyReport();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (report.modules as any)[id] = { status: 'done', durationMs: 10, error: null, data };
  return report;
}

function ids(findings: Finding[]): string[] {
  return findings.map((f) => f.id);
}

const BLANK_SPF: SpfInfo = {
  found: false,
  raw: null,
  includes: [],
  mechanisms: [],
  all: null,
  lookups: 0,
};
const BLANK_DMARC: DmarcInfo = {
  found: false,
  raw: null,
  policy: null,
  subdomainPolicy: null,
  percent: null,
  rua: [],
  ruf: [],
};

function mailPayload(overrides: {
  spf?: Partial<SpfInfo>;
  dmarc?: Partial<DmarcInfo>;
  caa?: string[];
}) {
  return {
    spf: { ...BLANK_SPF, ...overrides.spf },
    dmarc: { ...BLANK_DMARC, ...overrides.dmarc },
    mx: [],
    caa: overrides.caa ?? ['0 issue "letsencrypt.org"'],
    dkim: [],
  };
}

function metaPayload(disallowed: string[]) {
  return {
    robots: { found: true, url: 'https://example.com/robots.txt', disallowed, sitemaps: [] },
    sitemap: { found: false, documents: [], urls: [], truncated: false },
    securityTxt: { found: true, url: 'https://example.com/.well-known/security.txt', fields: [] },
    favicon: { found: false, url: null, hash: null, bytes: null },
    wellKnown: [],
  };
}

function techPayload(
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[],
) {
  return {
    finalUrl: 'https://example.com/',
    status: 200,
    redirected: false,
    technologies: [],
    headers: [],
    cookies,
    security: [],
    grade: 'A',
    identity: { title: null, description: null, generator: null },
  };
}

describe('buildFindings — a partial report produces no findings', () => {
  it('returns nothing when every module is still pending', () => {
    expect(buildFindings(emptyReport())).toEqual([]);
  });

  it('ignores a module that errored', () => {
    const report = emptyReport();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (report.modules as any).mail = {
      status: 'error',
      durationMs: 5,
      error: 'DNS timeout',
      data: null,
    };
    expect(buildFindings(report)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// robots.txt — the regression that motivated most of this file.
// ---------------------------------------------------------------------------
describe('buildFindings — robots.txt sensitive paths', () => {
  it('flags genuinely sensitive paths', () => {
    const sensitive = [
      '/admin/',
      '/wp-admin/',
      '/internal/',
      '/private/',
      '/backup/',
      '/config/',
      '/.git/',
      '/.env',
      '/graphql',
      '/debug/',
      '/staging/',
      '/api/',
      '/api-docs/',
      '/db/',
      '/logs/',
      '/dev/',
      '/test/',
      '/dump.sql',
      '/dbadmin/',
    ];
    for (const path of sensitive) {
      const findings = buildFindings(reportWith('meta', metaPayload([path])));
      expect(ids(findings), path).toContain('meta:robots-sensitive');
    }
  });

  it('does not flag ordinary paths that merely contain a keyword', () => {
    // Every one of these was reported as a "sensitive-looking path" by the
    // substring regex this replaced: blog/catalogue contain "log",
    // therapist contains "api", feedback/oldbooks contain "db",
    // latest/contest contain "test".
    const ordinary = [
      '/blog/',
      '/blogs/',
      '/catalogue/',
      '/therapist/',
      '/feedback/',
      '/oldbooks/',
      '/latest/',
      '/contest/',
      '/logout',
      '/portfolio/',
      '/products/',
      '/news/',
      '/cart/',
      '/videos/',
    ];
    for (const path of ordinary) {
      const findings = buildFindings(reportWith('meta', metaPayload([path])));
      expect(ids(findings), path).not.toContain('meta:robots-sensitive');
    }
  });

  it('reports only the sensitive subset when a robots.txt mixes both', () => {
    const findings = buildFindings(
      reportWith('meta', metaPayload(['/blog/', '/admin/', '/news/', '/.env'])),
    );
    const robots = findings.find((f) => f.id === 'meta:robots-sensitive');
    expect(robots).toBeDefined();
    expect(robots!.title).toContain('2 sensitive-looking paths');
    expect(robots!.evidence).toContain('/admin/');
    expect(robots!.evidence).toContain('/.env');
    expect(robots!.evidence).not.toContain('/blog/');
    expect(robots!.evidence).not.toContain('/news/');
  });

  it('says "path" rather than "paths" for a single hit', () => {
    const findings = buildFindings(reportWith('meta', metaPayload(['/admin/'])));
    const robots = findings.find((f) => f.id === 'meta:robots-sensitive')!;
    expect(robots.title).toContain('1 sensitive-looking path');
    expect(robots.title).not.toContain('paths');
  });
});

// ---------------------------------------------------------------------------
// Session-like cookies.
// ---------------------------------------------------------------------------
describe('buildFindings — session-like cookies', () => {
  const insecure = { secure: false, httpOnly: false, sameSite: null };

  it('flags real session cookie names that are missing flags', () => {
    const names = [
      'PHPSESSID',
      'JSESSIONID',
      'session',
      '_session',
      'laravel_session',
      'sid',
      'connect.sid',
      'auth_token',
      'access_token',
      'jwt',
      'remember_me',
      'XSRF-TOKEN',
      'csrftoken',
      'authorization',
    ];
    for (const name of names) {
      const findings = buildFindings(reportWith('tech', techPayload([{ name, ...insecure }])));
      expect(ids(findings), name).toContain(`cookie:${name}`);
    }
  });

  it('does not flag cookies that only look session-like as a substring', () => {
    // "assessment_id" contains sess; "author_pref" contains auth.
    const ordinary = [
      'assessment_id',
      'author_pref',
      'authors',
      'theme',
      'locale',
      'cart_items',
      '_ga',
    ];
    for (const name of ordinary) {
      const findings = buildFindings(reportWith('tech', techPayload([{ name, ...insecure }])));
      expect(ids(findings), name).toEqual([]);
    }
  });

  it('says nothing about a session cookie that already has every flag', () => {
    const findings = buildFindings(
      reportWith(
        'tech',
        techPayload([{ name: 'PHPSESSID', secure: true, httpOnly: true, sameSite: 'Lax' }]),
      ),
    );
    expect(findings).toEqual([]);
  });

  it('ranks a missing HttpOnly above the other flags', () => {
    const noHttpOnly = buildFindings(
      reportWith(
        'tech',
        techPayload([{ name: 'PHPSESSID', secure: true, httpOnly: false, sameSite: 'Lax' }]),
      ),
    );
    expect(noHttpOnly[0].severity).toBe('medium');

    const hasHttpOnly = buildFindings(
      reportWith(
        'tech',
        techPayload([{ name: 'PHPSESSID', secure: false, httpOnly: true, sameSite: null }]),
      ),
    );
    expect(hasHttpOnly[0].severity).toBe('low');
  });

  it('names every missing flag in the detail', () => {
    const findings = buildFindings(reportWith('tech', techPayload([{ name: 'PHPSESSID', ...insecure }])));
    expect(findings[0].detail).toContain('no Secure');
    expect(findings[0].detail).toContain('no HttpOnly');
    expect(findings[0].detail).toContain('no SameSite');
  });
});

// ---------------------------------------------------------------------------
// Mail: SPF / DMARC / CAA.
// ---------------------------------------------------------------------------
describe('buildFindings — mail', () => {
  it('reports a missing SPF record as medium', () => {
    const findings = buildFindings(reportWith('mail', mailPayload({ spf: { found: false } })));
    expect(findings.find((f) => f.id === 'mail:spf-missing')?.severity).toBe('medium');
  });

  it('reports +all as high, and treats a bare "all" the same way', () => {
    for (const all of ['+all', 'all']) {
      const findings = buildFindings(
        reportWith('mail', mailPayload({ spf: { found: true, all, raw: `v=spf1 ${all}` } })),
      );
      const spf = findings.find((f) => f.id === 'mail:spf-permissive');
      expect(spf, all).toBeDefined();
      expect(spf!.severity, all).toBe('high');
    }
  });

  it('says nothing about a hard-fail or soft-fail SPF', () => {
    for (const all of ['-all', '~all']) {
      const findings = buildFindings(
        reportWith('mail', mailPayload({ spf: { found: true, all, raw: `v=spf1 ${all}` } })),
      );
      expect(
        ids(findings).filter((id) => id.startsWith('mail:spf')),
        all,
      ).toEqual([]);
    }
  });

  it('flags a neutral or absent terminating qualifier as medium', () => {
    const neutral = buildFindings(reportWith('mail', mailPayload({ spf: { found: true, all: '?all' } })));
    expect(neutral.find((f) => f.id === 'mail:spf-neutral')?.severity).toBe('medium');

    const missing = buildFindings(reportWith('mail', mailPayload({ spf: { found: true, all: null } })));
    expect(missing.find((f) => f.id === 'mail:spf-neutral')!.title).toContain('no terminating');
  });

  it('flags more than ten SPF lookups but not exactly ten', () => {
    const over = buildFindings(
      reportWith('mail', mailPayload({ spf: { found: true, all: '-all', lookups: 11 } })),
    );
    expect(ids(over)).toContain('mail:spf-lookups');

    const atLimit = buildFindings(
      reportWith('mail', mailPayload({ spf: { found: true, all: '-all', lookups: 10 } })),
    );
    expect(ids(atLimit)).not.toContain('mail:spf-lookups');
  });

  it('reports a missing DMARC record, p=none and a partial percentage', () => {
    const missing = buildFindings(reportWith('mail', mailPayload({ dmarc: { found: false } })));
    expect(missing.find((f) => f.id === 'mail:dmarc-missing')?.severity).toBe('medium');

    const none = buildFindings(
      reportWith('mail', mailPayload({ dmarc: { found: true, policy: 'none' } })),
    );
    expect(none.find((f) => f.id === 'mail:dmarc-none')?.severity).toBe('medium');

    const partial = buildFindings(
      reportWith('mail', mailPayload({ dmarc: { found: true, policy: 'reject', percent: 20 } })),
    );
    const pct = partial.find((f) => f.id === 'mail:dmarc-pct')!;
    expect(pct.severity).toBe('low');
    expect(pct.title).toContain('20%');
  });

  it('says nothing about an enforcing DMARC at 100%', () => {
    const findings = buildFindings(
      reportWith('mail', mailPayload({ dmarc: { found: true, policy: 'reject', percent: 100 } })),
    );
    expect(ids(findings).filter((id) => id.startsWith('mail:dmarc'))).toEqual([]);
  });

  it('flags sp=none separately from the main policy', () => {
    const findings = buildFindings(
      reportWith(
        'mail',
        mailPayload({ dmarc: { found: true, policy: 'reject', subdomainPolicy: 'none' } }),
      ),
    );
    expect(findings.find((f) => f.id === 'mail:dmarc-sp-none')?.severity).toBe('low');
  });

  it('flags a missing CAA record but not a present one', () => {
    expect(ids(buildFindings(reportWith('mail', mailPayload({ caa: [] }))))).toContain(
      'mail:caa-missing',
    );
    expect(
      ids(buildFindings(reportWith('mail', mailPayload({ caa: ['0 issue "le.org"'] })))),
    ).not.toContain('mail:caa-missing');
  });
});

// ---------------------------------------------------------------------------
// Takeover hand-off: only dangling hosts become findings.
// ---------------------------------------------------------------------------
describe('buildFindings — takeover hosts', () => {
  const host = (over: Record<string, unknown>) => ({
    host: 'old.example.com',
    addresses: [],
    cname: 'gone.herokuapp.com',
    service: 'Heroku',
    status: 'dangling',
    takeover: true,
    severity: 'high',
    note: 'Dangling CNAME to Heroku.',
    ...over,
  });

  it('carries the severity the takeover module decided, unchanged', () => {
    const findings = buildFindings(
      reportWith('takeover', { hosts: [host({ severity: 'high' })], sources: [] }),
    );
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('Possible subdomain takeover');
  });

  it('titles a dangling CNAME that is not a takeover differently', () => {
    const findings = buildFindings(
      reportWith('takeover', {
        hosts: [host({ takeover: false, severity: 'medium', service: null })],
        sources: [],
      }),
    );
    expect(findings[0].title).toContain('Dangling CNAME');
    expect(findings[0].title).not.toContain('takeover');
  });

  it('ignores live, nxdomain and errored hosts entirely', () => {
    for (const status of ['live', 'nxdomain', 'error']) {
      const findings = buildFindings(
        reportWith('takeover', { hosts: [host({ status, takeover: false })], sources: [] }),
      );
      expect(findings, status).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// Domain expiry — the only time-dependent branch in the module.
// ---------------------------------------------------------------------------
describe('buildFindings — domain expiry', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-01T12:00:00.000Z'));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const whois = (expiresAt: string | null, dnssec: boolean | null = true) => ({
    domain: {
      found: true,
      registrar: 'Example Registrar',
      createdAt: null,
      updatedAt: null,
      expiresAt,
      statuses: [],
      nameservers: [],
      abuseContacts: [],
      dnssec,
    },
    network: [],
  });

  it('reports an already-expired registration as high', () => {
    const findings = buildFindings(reportWith('whois', whois('2026-09-01T12:00:00.000Z')));
    const expiring = findings.find((f) => f.id === 'whois:expiring')!;
    expect(expiring.severity).toBe('high');
    expect(expiring.title).toBe('Domain registration has expired');
  });

  it('does not claim a domain expiring today has already expired', () => {
    const findings = buildFindings(reportWith('whois', whois('2026-10-01T23:00:00.000Z')));
    const expiring = findings.find((f) => f.id === 'whois:expiring')!;
    expect(expiring.severity).toBe('high');
    expect(expiring.title).toBe('Domain registration expires today');
    expect(expiring.title).not.toContain('has expired');
  });

  it('reports an approaching expiry as medium, with correct pluralisation', () => {
    const inThirty = buildFindings(reportWith('whois', whois('2026-10-31T12:00:00.000Z')));
    const thirty = inThirty.find((f) => f.id === 'whois:expiring')!;
    expect(thirty.severity).toBe('medium');
    expect(thirty.title).toBe('Domain expires in 30 days');

    const inOne = buildFindings(reportWith('whois', whois('2026-10-02T12:00:00.000Z')));
    expect(inOne.find((f) => f.id === 'whois:expiring')!.title).toBe('Domain expires in 1 day');
  });

  it('says nothing when expiry is beyond the 60-day window', () => {
    const findings = buildFindings(reportWith('whois', whois('2027-06-01T12:00:00.000Z')));
    expect(ids(findings)).not.toContain('whois:expiring');
  });

  it('ignores an unparseable expiry date instead of inventing a finding', () => {
    const findings = buildFindings(reportWith('whois', whois('not-a-date')));
    expect(ids(findings)).not.toContain('whois:expiring');
  });

  it('notes disabled DNSSEC as info, and stays quiet when it is enabled or unknown', () => {
    const off = buildFindings(reportWith('whois', whois(null, false)));
    expect(off.find((f) => f.id === 'whois:dnssec')?.severity).toBe('info');

    for (const value of [true, null]) {
      const findings = buildFindings(reportWith('whois', whois(null, value)));
      expect(ids(findings), String(value)).not.toContain('whois:dnssec');
    }
  });

  it('ignores whois data when the domain lookup itself failed', () => {
    const report = reportWith('whois', {
      domain: { ...whois('2026-09-01T12:00:00.000Z').domain, found: false },
      network: [],
    });
    expect(buildFindings(report)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Ordering and counting.
// ---------------------------------------------------------------------------
describe('buildFindings — ordering', () => {
  it('sorts worst first', () => {
    const report = reportWith(
      'mail',
      mailPayload({ spf: { found: true, all: '+all' }, dmarc: { found: false }, caa: [] }),
    );
    const findings = buildFindings(report);
    const ranks = findings.map((f) => SEVERITY_ORDER[f.severity]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    expect(findings[0].severity).toBe('high');
  });

  it('breaks severity ties by title', () => {
    const report = reportWith('mail', mailPayload({ spf: { found: false }, dmarc: { found: false } }));
    const titles = buildFindings(report)
      .filter((f) => f.severity === 'medium')
      .map((f) => f.title);
    expect(titles).toEqual([...titles].sort((a, b) => a.localeCompare(b)));
  });
});

describe('countBySeverity', () => {
  it('returns every severity key, zeroed, for an empty list', () => {
    expect(countBySeverity([])).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('counts each severity independently', () => {
    const findings = [
      { id: 'a', module: 'mail', severity: 'high', title: 'a', detail: 'd' },
      { id: 'b', module: 'mail', severity: 'high', title: 'b', detail: 'd' },
      { id: 'c', module: 'mail', severity: 'low', title: 'c', detail: 'd' },
      { id: 'd', module: 'mail', severity: 'info', title: 'd', detail: 'd' },
    ] as Finding[];
    expect(countBySeverity(findings)).toEqual({
      critical: 0,
      high: 2,
      medium: 0,
      low: 1,
      info: 1,
    });
  });

  it('totals to the number of findings it was given', () => {
    const findings = buildFindings(
      reportWith('mail', mailPayload({ spf: { found: false }, caa: [] })),
    );
    const total = Object.values(countBySeverity(findings)).reduce((sum, n) => sum + n, 0);
    expect(total).toBe(findings.length);
  });
});
