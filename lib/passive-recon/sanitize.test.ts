import { describe, expect, it } from 'vitest';

import { sanitizeDomain } from './sanitize';

function ok(input: unknown): string {
  const result = sanitizeDomain(input);
  if (!result.ok) throw new Error(`expected ok, got error: ${result.error}`);
  return result.domain;
}

function err(input: unknown): string {
  const result = sanitizeDomain(input);
  if (result.ok) throw new Error(`expected error, got ok: ${result.domain}`);
  return result.error;
}

describe('sanitizeDomain — accepts legitimate targets', () => {
  it('accepts a plain domain', () => {
    expect(ok('example.com')).toBe('example.com');
  });

  it('lowercases the domain', () => {
    expect(ok('EXAMPLE.com')).toBe('example.com');
  });

  it('trims surrounding whitespace', () => {
    expect(ok('  example.com  ')).toBe('example.com');
  });

  it('accepts a subdomain', () => {
    expect(ok('www.example.co.uk')).toBe('www.example.co.uk');
  });

  it('accepts a punycode (IDN) TLD', () => {
    expect(ok('example.xn--p1ai')).toBe('example.xn--p1ai');
  });

  it('strips a pasted URL down to the host', () => {
    expect(ok('https://example.com/path?query=1#frag')).toBe('example.com');
  });

  it('strips a trailing DNS root dot', () => {
    expect(ok('example.com.')).toBe('example.com');
  });

  it('accepts a 63-character label', () => {
    const label = 'a'.repeat(63);
    expect(ok(`${label}.com`)).toBe(`${label}.com`);
  });
});

describe('sanitizeDomain — rejects malformed or unsafe input', () => {
  it('rejects a non-string', () => {
    expect(err(123)).toMatch(/must be a string/i);
    expect(err(null)).toMatch(/must be a string/i);
    expect(err(undefined)).toMatch(/must be a string/i);
    expect(err({})).toMatch(/must be a string/i);
  });

  it('rejects an empty string', () => {
    expect(err('')).toMatch(/required/i);
    expect(err('   ')).toMatch(/required/i);
  });

  it('rejects userinfo (@) — classic host-smuggling vector', () => {
    expect(err('user@example.com')).toMatch(/userinfo/i);
    expect(err('https://user:pass@example.com/')).toMatch(/userinfo/i);
  });

  it('rejects an explicit port', () => {
    expect(err('example.com:8080')).toMatch(/port/i);
  });

  it('rejects an IPv6 literal', () => {
    expect(err('::1')).toMatch(/port/i);
    // `[::1]` still contains a colon, so it hits the same port/IPv6 check.
    expect(err('[::1]')).toMatch(/port/i);
  });

  it('rejects a bare IPv4 literal', () => {
    expect(err('127.0.0.1')).toMatch(/IP literals/i);
    expect(err('93.184.216.34')).toMatch(/IP literals/i);
  });

  it('rejects shell metacharacters and whitespace inside the value', () => {
    expect(err('example.com; rm -rf /')).toMatch(/letters, digits/i);
    expect(err('example.com`whoami`')).toMatch(/letters, digits/i);
    expect(err('exa mple.com')).toMatch(/letters, digits/i);
  });

  it('rejects a bare hostname with no dot', () => {
    // A bare hostname always fails the fully-qualified check first, before
    // the reserved-TLD check ever runs — both single-label names end up
    // refused, which is what matters.
    expect(err('localhost')).toMatch(/fully-qualified/i);
    expect(err('intranet')).toMatch(/fully-qualified/i);
  });

  it('rejects an empty DNS label (double dot)', () => {
    expect(err('example..com')).toMatch(/empty DNS label/i);
  });

  it('rejects a label that starts or ends with a hyphen', () => {
    expect(err('-example.com')).toMatch(/hyphen/i);
    expect(err('example-.com')).toMatch(/hyphen/i);
  });

  it('rejects a label over 63 characters', () => {
    const label = 'a'.repeat(64);
    expect(err(`${label}.com`)).toMatch(/label length/i);
  });

  it('rejects a domain over 253 characters', () => {
    const long = `${'a'.repeat(250)}.com`;
    expect(err(long)).toMatch(/253-character/i);
  });

  it('rejects an invalid top-level domain', () => {
    expect(err('example.123')).toMatch(/top-level domain/i);
  });

  for (const tld of ['local', 'localhost', 'internal', 'intranet', 'lan', 'home', 'corp', 'test', 'onion']) {
    it(`rejects the reserved TLD .${tld}`, () => {
      expect(err(`foo.${tld}`)).toMatch(/reserved\/internal/i);
    });
  }

  it('rejects data: and other exotic schemes even when pasted as a URL', () => {
    // The scheme-stripping regex only fires on "scheme://"; a scheme with a
    // single colon and no slashes falls through to the port/colon check
    // instead, which still refuses it.
    expect(err('javascript:alert(1)')).toMatch(/port/i);
  });
});
