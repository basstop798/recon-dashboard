/**
 * Email-authentication parsing (SPF / DMARC).
 *
 * Pure string work over TXT records the DNS module already fetched. Mail
 * posture is in scope for a recon tool because a missing or permissive DMARC
 * policy is a reportable finding on many programs — it is the difference
 * between "anyone can send as this domain" and "spoofing is rejected".
 */

import type { DmarcInfo, SpfInfo } from './types';

/** Mechanisms that each cost one of RFC 7208's ten DNS lookups. */
const LOOKUP_MECHANISMS = /^(?:include|a|mx|ptr|exists|redirect)(?::|=|$)/i;

export function parseSpf(txtRecords: readonly string[]): SpfInfo {
  const raw = txtRecords.find((record) => /^v=spf1(\s|$)/i.test(record.trim())) ?? null;

  if (!raw) {
    return { found: false, raw: null, includes: [], mechanisms: [], all: null, lookups: 0 };
  }

  const terms = raw.trim().split(/\s+/).slice(1);
  const includes: string[] = [];
  const mechanisms: string[] = [];
  let all: string | null = null;
  let lookups = 0;

  for (const term of terms) {
    mechanisms.push(term);

    if (/^[-~?+]?all$/i.test(term)) {
      // The *last* `all` wins; everything after it is unreachable anyway.
      all = term.toLowerCase();
      continue;
    }

    if (/^include:/i.test(term)) includes.push(term.slice(term.indexOf(':') + 1));

    // A leading qualifier (+/-/~/?) is not part of the mechanism name.
    if (LOOKUP_MECHANISMS.test(term.replace(/^[-~?+]/, ''))) lookups += 1;
  }

  return { found: true, raw, includes, mechanisms, all, lookups };
}

function dmarcTag(raw: string, tag: string): string | null {
  const match = raw.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;]+)`, 'i'));
  return match?.[1]?.trim() ?? null;
}

function dmarcUris(value: string | null): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function parseDmarc(txtRecords: readonly string[]): DmarcInfo {
  const raw = txtRecords.find((record) => /^v=DMARC1\s*;/i.test(record.trim())) ?? null;

  if (!raw) {
    return {
      found: false,
      raw: null,
      policy: null,
      subdomainPolicy: null,
      percent: null,
      rua: [],
      ruf: [],
    };
  }

  const percent = dmarcTag(raw, 'pct');

  return {
    found: true,
    raw,
    policy: dmarcTag(raw, 'p')?.toLowerCase() ?? null,
    subdomainPolicy: dmarcTag(raw, 'sp')?.toLowerCase() ?? null,
    percent: percent !== null && /^\d+$/.test(percent) ? Number(percent) : null,
    rua: dmarcUris(dmarcTag(raw, 'rua')),
    ruf: dmarcUris(dmarcTag(raw, 'ruf')),
  };
}

export interface DkimKey {
  found: boolean;
  /** A published record whose `p=` tag is empty: the key is revoked. */
  revoked: boolean;
}

/**
 * Decides whether a selector actually carries a usable key.
 *
 * Presence alone is not enough for two reasons: a zone may publish a wildcard
 * `*._domainkey` that answers for every name (example.com does exactly this),
 * and RFC 6376 uses an empty `p=` to mean the key has been revoked. Counting
 * either as "DKIM is configured" would report a domain that sends no mail as
 * one with twelve working signing keys.
 */
export function parseDkimKey(records: readonly string[]): DkimKey {
  for (const record of records) {
    if (!/v\s*=\s*DKIM1/i.test(record)) continue;

    const key = record.match(/(?:^|;)\s*p\s*=\s*([^;]*)/i)?.[1]?.trim();
    if (key) return { found: true, revoked: false };

    // `v=DKIM1; p=` — published, but explicitly revoked.
    return { found: false, revoked: true };
  }

  return { found: false, revoked: false };
}

/**
 * DKIM selectors worth a lookup.
 *
 * DKIM has no discovery mechanism — a selector is only knowable from a message
 * header — so this is the conventional list of provider defaults. A miss proves
 * nothing, which is why the payload reports per-selector rather than a verdict.
 */
export const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'mail',
  'dkim',
  's1',
  's2',
  'mandrill',
  'zoho',
  'protonmail',
] as const;
