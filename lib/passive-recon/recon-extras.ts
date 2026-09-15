/**
 * Pure parsers for the "recon extras" module.
 *
 * Network-free by design, mirroring how `js-parser.ts` is split from the route:
 * the route owns fetching, this file owns interpretation. That keeps every rule
 * here unit-testable with a string literal and no server.
 */

import type { SecurityTxtField } from './types';

export interface RobotsParseResult {
  disallowed: string[];
  sitemaps: string[];
}

/**
 * Extracts `Disallow:` paths and `Sitemap:` URLs from a robots.txt.
 *
 * Disallowed paths are the interesting part for recon: they are the operator
 * telling crawlers exactly which routes they would rather nobody look at.
 */
export function parseRobotsTxt(text: string): RobotsParseResult {
  const disallowed = new Set<string>();
  const sitemaps = new Set<string>();

  for (const rawLine of text.split(/\r?\n/)) {
    // Everything after '#' is a comment, including trailing ones.
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;

    const disallow = line.match(/^disallow\s*:\s*(.*)$/i);
    if (disallow) {
      const value = disallow[1].trim();
      // A bare "Disallow:" means "allow everything" — not a path.
      if (value) disallowed.add(value);
      continue;
    }

    const sitemap = line.match(/^sitemap\s*:\s*(.*)$/i);
    if (sitemap) {
      const value = sitemap[1].trim();
      if (value) sitemaps.add(value);
    }
  }

  return { disallowed: [...disallowed], sitemaps: [...sitemaps] };
}

/**
 * Pulls `<loc>` values out of a sitemap.
 *
 * Deliberately agnostic between `<urlset>` (page URLs) and `<sitemapindex>`
 * (nested sitemap URLs) — both use `<loc>`, and the caller decides what the
 * results mean.
 */
export function parseSitemapLocs(xml: string): string[] {
  const locs = new Set<string>();

  for (const match of xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)) {
    const value = match[1]
      .replace(/^\s*<!\[CDATA\[/, '')
      .replace(/\]\]>\s*$/, '')
      .trim();

    if (value) locs.add(value);
  }

  return [...locs];
}

/**
 * Parses an RFC 9116 security.txt into ordered `Field: value` pairs.
 *
 * Returns an array rather than an object because duplicate fields are normal
 * and meaningful here — a policy commonly lists several `Contact:` lines in
 * preference order, and collapsing them into a map would discard all but one.
 */
export function parseSecurityTxt(text: string): SecurityTxtField[] {
  const fields: SecurityTxtField[] = [];

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const match = line.match(/^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$/);
    if (!match) continue;

    fields.push({ name: match[1], value: match[2].trim() });
  }

  return fields;
}

/**
 * Scores a `rel` attribute as a favicon candidate; lower wins, negative skips.
 *
 * Substring-matching `rel` for "icon" is wrong, and GitHub is the proof: it
 * ships `<link rel="fluid-icon">` *before* its real favicon, so a substring
 * test hashes a Fluid app icon instead. `rel` is a space-separated token list
 * per the HTML spec, so it is compared token-wise.
 */
function scoreIconRel(relValue: string): number {
  const tokens = relValue.toLowerCase().split(/\s+/).filter(Boolean);

  if (tokens.includes('icon')) {
    // "alternate icon" is the page's own fallback, so a plain "icon" outranks
    // it when a document declares both.
    return tokens.includes('alternate') ? 1 : 0;
  }

  if (
    tokens.includes('apple-touch-icon') ||
    tokens.includes('apple-touch-icon-precomposed')
  ) {
    return 2;
  }

  // "mask-icon" (monochrome pinned-tab SVG) and "fluid-icon" are not favicons.
  return -1;
}

/**
 * Finds the favicon for a document, falling back to the conventional location.
 *
 * Tolerant of attribute order and quote style because this runs against real
 * production HTML, where `<link href=x rel=icon>` is as common as the tidy form.
 */
export function resolveFaviconUrl(html: string, baseUrl: string): string | null {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return null;
  }

  let best: { score: number; url: string } | null = null;

  for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
    const rel = tag.match(/\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
    const score = scoreIconRel(rel?.[1] ?? rel?.[2] ?? rel?.[3] ?? '');

    if (score < 0) continue;
    // Ties keep the earlier tag, matching document order.
    if (best && best.score <= score) continue;

    const href = tag.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
    const raw = (href?.[1] ?? href?.[2] ?? href?.[3] ?? '').trim();

    // An inline data: icon has no URL to fetch and no Shodan presence.
    if (!raw || raw.toLowerCase().startsWith('data:')) continue;

    try {
      const resolved = new URL(raw, baseUrl);
      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
      resolved.hash = '';
      best = { score, url: resolved.toString() };
    } catch {
      continue;
    }
  }

  return best?.url ?? `${origin}/favicon.ico`;
}

/* -------------------------------------------------------------------------- */
/* Shodan favicon hash                                                        */
/* -------------------------------------------------------------------------- */

const BASE64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * 57 raw bytes encode to exactly 76 base64 characters with no padding, which is
 * why CPython picks it as the chunk size for `encodebytes`.
 */
const ENCODEBYTES_CHUNK = 57;

function base64Chunk(bytes: Uint8Array): string {
  let out = '';
  let i = 0;

  for (; i + 2 < bytes.length; i += 3) {
    const triple = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      BASE64_ALPHABET[(triple >>> 18) & 63] +
      BASE64_ALPHABET[(triple >>> 12) & 63] +
      BASE64_ALPHABET[(triple >>> 6) & 63] +
      BASE64_ALPHABET[triple & 63];
  }

  const remaining = bytes.length - i;

  if (remaining === 1) {
    const triple = bytes[i] << 16;
    out += `${BASE64_ALPHABET[(triple >>> 18) & 63]}${BASE64_ALPHABET[(triple >>> 12) & 63]}==`;
  } else if (remaining === 2) {
    const triple = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      BASE64_ALPHABET[(triple >>> 18) & 63] +
      BASE64_ALPHABET[(triple >>> 12) & 63] +
      BASE64_ALPHABET[(triple >>> 6) & 63] +
      '=';
  }

  return out;
}

/**
 * Reproduces Python's `base64.encodebytes`: standard base64 wrapped at 76
 * characters, with **every** line terminated by `\n` including the final one.
 *
 * This is not plain base64, and the difference is the whole ballgame — Shodan
 * indexes the hash of this exact byte sequence, so a missing trailing newline
 * produces a value that silently matches nothing.
 */
export function encodeBytesBase64(bytes: Uint8Array): string {
  // CPython's loop body never runs for empty input, so the result is "" — not
  // "\n". Emitting a bare newline here would hash to the wrong value entirely.
  if (bytes.length === 0) return '';

  let out = '';
  for (let offset = 0; offset < bytes.length; offset += ENCODEBYTES_CHUNK) {
    out += `${base64Chunk(bytes.subarray(offset, offset + ENCODEBYTES_CHUNK))}\n`;
  }
  return out;
}

function rotl32(value: number, shift: number): number {
  return (value << shift) | (value >>> (32 - shift));
}

/**
 * MurmurHash3 x86_32, returning a signed int32.
 *
 * `Math.imul` is required rather than `*`: the constants overflow 2^53 once
 * multiplied, so plain multiplication silently loses low bits. Signed output
 * matches Python's `mmh3.hash()`, which is what Shodan stores.
 *
 * @param input ASCII/latin1 text — each char code is treated as one byte.
 */
export function murmurHash3X86_32(input: string, seed = 0): number {
  const C1 = 0xcc9e2d51;
  const C2 = 0x1b873593;

  const length = input.length;
  const blockEnd = length & ~3;
  let h1 = seed | 0;

  for (let i = 0; i < blockEnd; i += 4) {
    // Little-endian 4-byte block.
    let k1 =
      (input.charCodeAt(i) & 0xff) |
      ((input.charCodeAt(i + 1) & 0xff) << 8) |
      ((input.charCodeAt(i + 2) & 0xff) << 16) |
      ((input.charCodeAt(i + 3) & 0xff) << 24);

    k1 = Math.imul(k1, C1);
    k1 = rotl32(k1, 15);
    k1 = Math.imul(k1, C2);

    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }

  // Tail: 1-3 leftover bytes. Written as ifs rather than a fallthrough switch
  // so the intent survives without relying on lint-suppressing comments.
  const remainder = length & 3;
  if (remainder > 0) {
    let k1 = 0;
    if (remainder === 3) k1 ^= (input.charCodeAt(blockEnd + 2) & 0xff) << 16;
    if (remainder >= 2) k1 ^= (input.charCodeAt(blockEnd + 1) & 0xff) << 8;
    k1 ^= input.charCodeAt(blockEnd) & 0xff;

    k1 = Math.imul(k1, C1);
    k1 = rotl32(k1, 15);
    k1 = Math.imul(k1, C2);
    h1 ^= k1;
  }

  h1 ^= length;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0;
}

/**
 * Computes Shodan's `http.favicon.hash` for raw icon bytes.
 *
 * Equivalent to Python `mmh3.hash(base64.encodebytes(favicon_bytes))`. Hunters
 * paste the result into `http.favicon.hash:<value>` to pivot from one icon to
 * every other host serving it — which surfaces infrastructure that DNS and
 * certificate transparency never reveal.
 */
export function shodanFaviconHash(bytes: Uint8Array): number {
  return murmurHash3X86_32(encodeBytesBase64(bytes));
}
