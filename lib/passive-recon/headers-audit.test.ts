import { describe, it, expect } from 'vitest';
import { auditSecurityHeaders, readCookies, parsePageIdentity } from './headers-audit';

/**
 * This module produces the A–F security-header grade and the per-header
 * verdicts the dashboard leads with. Two failure modes matter equally:
 * calling a correctly configured site weak, and calling a weak one fine.
 * Both are covered below, with the emphasis on the former — a tool that
 * cries wolf on a hardened site is one an operator stops believing.
 */

/** Headers for a site that gets every check right. */
function hardenedHeaders(extra: Record<string, string> = {}): Headers {
  return new Headers({
    'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
    'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'cross-origin-opener-policy': 'same-origin',
    ...extra,
  });
}

function check(headers: Headers, header: string) {
  return auditSecurityHeaders(headers).checks.find((c) => c.header === header);
}

describe('auditSecurityHeaders — grading', () => {
  it('gives a fully hardened response an A and no non-info findings', () => {
    const audit = auditSecurityHeaders(hardenedHeaders());
    expect(audit.grade).toBe('A');
    expect(audit.checks.every((c) => c.severity === 'info')).toBe(true);
  });

  it('gives a bare response an F', () => {
    expect(auditSecurityHeaders(new Headers()).grade).toBe('F');
  });

  it('never improves the grade as headers are removed', () => {
    const order = ['A', 'B', 'C', 'D', 'F'];
    const all = hardenedHeaders();
    const removable = [
      'cross-origin-opener-policy',
      'permissions-policy',
      'referrer-policy',
      'x-content-type-options',
      'x-frame-options',
      'content-security-policy',
      'strict-transport-security',
    ];

    let previous = 0;
    for (let i = 0; i <= removable.length; i++) {
      const headers = new Headers(all);
      for (const header of removable.slice(0, i)) headers.delete(header);
      const rank = order.indexOf(auditSecurityHeaders(headers).grade);
      expect(rank, `after removing ${i}`).toBeGreaterThanOrEqual(previous);
      previous = rank;
    }
  });

  it('reports every header it knows about, present or not', () => {
    const audit = auditSecurityHeaders(new Headers());
    const headers = audit.checks.map((c) => c.header);
    for (const expected of [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
      'cross-origin-opener-policy',
    ]) {
      expect(headers, expected).toContain(expected);
    }
    expect(audit.checks.every((c) => c.present === false)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CSP — the regression that motivated most of this file.
// ---------------------------------------------------------------------------
describe('auditSecurityHeaders — CSP weakness is scoped to script directives', () => {
  it('does not call a CSP weak for unsafe-inline on style-src alone', () => {
    // Inline styles do not execute script. Reporting this as a weakened CSP
    // flagged correctly hardened sites.
    const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'";
    const result = check(
      hardenedHeaders({ 'content-security-policy': csp }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('info');
    expect(result?.advice).toBe('Present.');
  });

  it('does not call a CSP weak for a wildcard on img-src alone', () => {
    const csp = "default-src 'self'; script-src 'self'; img-src *";
    const result = check(
      hardenedHeaders({ 'content-security-policy': csp }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('info');
  });

  it('flags unsafe-inline and unsafe-eval on script-src', () => {
    const csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
    const result = check(
      hardenedHeaders({ 'content-security-policy': csp }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('low');
    expect(result?.advice).toContain("'unsafe-inline'");
    expect(result?.advice).toContain("'unsafe-eval'");
  });

  it('flags a weakness inherited from default-src when script-src is absent', () => {
    const csp = "default-src 'self' 'unsafe-inline'";
    const result = check(
      hardenedHeaders({ 'content-security-policy': csp }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('low');
    expect(result?.advice).toContain("'unsafe-inline'");
  });

  it('ignores a default-src weakness when script-src overrides it', () => {
    // script-src wins for scripts, so the policy is not weak for scripts.
    const csp = "default-src 'unsafe-inline' *; script-src 'self'";
    const result = check(
      hardenedHeaders({ 'content-security-policy': csp }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('info');
  });

  it('flags a bare wildcard source but not a wildcard hostname', () => {
    const bare = check(
      hardenedHeaders({ 'content-security-policy': "script-src 'self' *" }),
      'content-security-policy',
    );
    expect(bare?.advice).toContain('wildcard script source');

    const hostname = check(
      hardenedHeaders({ 'content-security-policy': "script-src 'self' https://*.cdn.example.com" }),
      'content-security-policy',
    );
    expect(hostname?.severity).toBe('info');
  });

  it('flags a CSP that constrains neither scripts nor defaults', () => {
    const result = check(
      hardenedHeaders({ 'content-security-policy': "img-src 'self'; style-src 'self'" }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('low');
    expect(result?.advice).toContain('neither script-src nor default-src');
  });

  it('honours the first occurrence of a duplicated directive, as the spec requires', () => {
    const csp = "script-src 'self'; script-src 'unsafe-inline'";
    const result = check(
      hardenedHeaders({ 'content-security-policy': csp }),
      'content-security-policy',
    );
    expect(result?.severity).toBe('info');
  });

  it('treats a CSP frame-ancestors directive as superseding X-Frame-Options', () => {
    const headers = hardenedHeaders({
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    });
    headers.delete('x-frame-options');

    const xfo = check(headers, 'x-frame-options');
    expect(xfo?.severity).toBe('info');
    expect(xfo?.advice).toContain('Superseded');
    // And it must not be penalised twice.
    expect(auditSecurityHeaders(headers).grade).toBe('A');
  });

  it('still reports a missing X-Frame-Options when the CSP has no frame-ancestors', () => {
    const headers = hardenedHeaders();
    headers.delete('x-frame-options');
    expect(check(headers, 'x-frame-options')?.severity).toBe('medium');
  });
});

// ---------------------------------------------------------------------------
// HSTS.
// ---------------------------------------------------------------------------
describe('auditSecurityHeaders — HSTS', () => {
  it('accepts a max-age at or above the preload threshold', () => {
    for (const value of ['max-age=15552000', 'max-age=63072000; includeSubDomains; preload']) {
      const result = check(
        hardenedHeaders({ 'strict-transport-security': value }),
        'strict-transport-security',
      );
      expect(result?.severity, value).toBe('info');
    }
  });

  it('flags a short max-age as low and names the value', () => {
    const result = check(
      hardenedHeaders({ 'strict-transport-security': 'max-age=86400' }),
      'strict-transport-security',
    );
    expect(result?.severity).toBe('low');
    expect(result?.advice).toContain('86400');
  });

  it('flags max-age=0 as medium, because it disables HSTS', () => {
    const result = check(
      hardenedHeaders({ 'strict-transport-security': 'max-age=0' }),
      'strict-transport-security',
    );
    expect(result?.severity).toBe('medium');
  });

  it('tolerates a quoted max-age', () => {
    const result = check(
      hardenedHeaders({ 'strict-transport-security': 'max-age="63072000"' }),
      'strict-transport-security',
    );
    expect(result?.severity).toBe('info');
  });
});

// ---------------------------------------------------------------------------
// CORS and version disclosure.
// ---------------------------------------------------------------------------
describe('auditSecurityHeaders — CORS', () => {
  it('reports credentialed CORS as high', () => {
    const result = check(
      hardenedHeaders({
        'access-control-allow-origin': 'https://app.example.com',
        'access-control-allow-credentials': 'true',
      }),
      'access-control-allow-origin',
    );
    expect(result?.severity).toBe('high');
    expect(result?.advice).toContain('reflected');
  });

  it('reports a wildcard origin without credentials as low', () => {
    const result = check(
      hardenedHeaders({ 'access-control-allow-origin': '*' }),
      'access-control-allow-origin',
    );
    expect(result?.severity).toBe('low');
  });

  it('reports a scoped origin as info', () => {
    const result = check(
      hardenedHeaders({ 'access-control-allow-origin': 'https://app.example.com' }),
      'access-control-allow-origin',
    );
    expect(result?.severity).toBe('info');
  });

  it('says nothing about CORS when the header is absent', () => {
    expect(check(hardenedHeaders(), 'access-control-allow-origin')).toBeUndefined();
  });
});

describe('auditSecurityHeaders — version disclosure', () => {
  it('reports an exact version as low', () => {
    const result = check(hardenedHeaders({ server: 'nginx/1.18.0' }), 'server');
    expect(result?.severity).toBe('low');
    expect(result?.advice).toContain('version');
  });

  it('reports a bare technology name as info', () => {
    const result = check(hardenedHeaders({ server: 'nginx' }), 'server');
    expect(result?.severity).toBe('info');
  });

  it('checks every disclosure header it knows about', () => {
    for (const header of ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']) {
      const result = check(hardenedHeaders({ [header]: 'thing/2.4' }), header);
      expect(result?.severity, header).toBe('low');
    }
  });
});

// ---------------------------------------------------------------------------
// Cookies — names and flags only, never values.
// ---------------------------------------------------------------------------
describe('readCookies', () => {
  function withCookies(...cookies: string[]): Headers {
    const headers = new Headers();
    for (const cookie of cookies) headers.append('set-cookie', cookie);
    return headers;
  }

  it('returns an empty list when nothing is set', () => {
    expect(readCookies(new Headers())).toEqual([]);
  });

  it('reads the name and every flag', () => {
    const [cookie] = readCookies(withCookies('sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax'));
    expect(cookie).toEqual({ name: 'sid', secure: true, httpOnly: true, sameSite: 'lax' });
  });

  it('never includes the cookie value', () => {
    const serialised = JSON.stringify(readCookies(withCookies('sid=SUPERSECRETVALUE; Secure')));
    expect(serialised).not.toContain('SUPERSECRETVALUE');
  });

  it('records absent flags as false and a missing SameSite as null', () => {
    const [cookie] = readCookies(withCookies('plain=value'));
    expect(cookie).toEqual({ name: 'plain', secure: false, httpOnly: false, sameSite: null });
  });

  it('is case-insensitive about attribute names', () => {
    const [cookie] = readCookies(withCookies('sid=x; SECURE; httponly; samesite=STRICT'));
    expect(cookie.secure).toBe(true);
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('strict');
  });

  it('keeps a value containing "=" out of the name', () => {
    const [cookie] = readCookies(withCookies('token=a=b=c; Secure'));
    expect(cookie.name).toBe('token');
  });

  it('does not mistake a value containing "secure" for the flag', () => {
    const [cookie] = readCookies(withCookies('pref=secure'));
    expect(cookie.secure).toBe(false);
  });

  it('returns cookies sorted by name', () => {
    const names = readCookies(withCookies('zeta=1', 'alpha=2', 'mid=3')).map((c) => c.name);
    expect(names).toEqual(['alpha', 'mid', 'zeta']);
  });

  it('skips a malformed entry with no name', () => {
    expect(readCookies(withCookies('=novalue', 'good=1')).map((c) => c.name)).toEqual(['good']);
  });
});

// ---------------------------------------------------------------------------
// Page identity — reporting absence where data exists is a wrong answer.
// ---------------------------------------------------------------------------
describe('parsePageIdentity', () => {
  it('reads a title, description, generator, og:image and lang', () => {
    const html = `
      <html lang="en-GB">
        <head>
          <title>Example Shop</title>
          <meta name="description" content="We sell things.">
          <meta name="generator" content="WordPress 6.5">
          <meta property="og:image" content="https://example.com/card.png">
        </head>
      </html>`;
    expect(parsePageIdentity(html)).toEqual({
      title: 'Example Shop',
      description: 'We sell things.',
      generator: 'WordPress 6.5',
      ogImage: 'https://example.com/card.png',
      lang: 'en-GB',
    });
  });

  it('returns nulls for markup with none of it', () => {
    expect(parsePageIdentity('<html><body><p>hi</p></body></html>')).toEqual({
      title: null,
      description: null,
      generator: null,
      ogImage: null,
      lang: null,
    });
  });

  it('truncates a long title instead of losing it', () => {
    // A {0,300} capture made the match fail outright, so a page with a long
    // title was reported as having no title at all.
    const html = `<title>${'x'.repeat(400)}</title>`;
    const { title } = parsePageIdentity(html);
    expect(title).not.toBeNull();
    expect(title!.length).toBe(300);
  });

  it('reads a meta tag whose content attribute comes before name', () => {
    const html = '<meta content="Content first" name="description">';
    expect(parsePageIdentity(html).description).toBe('Content first');
  });

  it('falls back to og:description when there is no name="description"', () => {
    const html = '<meta property="og:description" content="Social copy">';
    expect(parsePageIdentity(html).description).toBe('Social copy');
  });

  it('prefers name="description" over og:description', () => {
    const html = `
      <meta property="og:description" content="Social copy">
      <meta name="description" content="Real description">`;
    expect(parsePageIdentity(html).description).toBe('Real description');
  });

  it('ignores an empty content attribute rather than returning an empty string', () => {
    expect(parsePageIdentity('<meta name="description" content="">').description).toBeNull();
  });

  it('does not treat an unrelated og tag as a generator', () => {
    expect(parsePageIdentity('<meta property="og:title" content="Title">').generator).toBeNull();
  });

  it('tolerates attribute whitespace and single quotes', () => {
    const html = "<meta name = 'generator' content = 'Hugo 0.1'>";
    expect(parsePageIdentity(html).generator).toBe('Hugo 0.1');
  });

  it('trims surrounding whitespace in a title', () => {
    expect(parsePageIdentity('<title>\n  Spaced  \n</title>').title).toBe('Spaced');
  });
});
