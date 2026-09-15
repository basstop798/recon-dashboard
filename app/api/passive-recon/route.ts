/**
 * Unified passive reconnaissance endpoint.
 *
 * POST { domain: string } -> streaming NDJSON (one `ScanEvent` per line).
 *
 * Why a stream rather than a single JSON response: the dashboard has to show
 * per-module progress from one trigger. Buffering everything until the slowest
 * upstream settles would make the progress indicators cosmetic. Each module
 * therefore emits `module_start` / `module_done` | `module_error` as it lands.
 *
 * Passivity contract — this route performs **no** active probing. There is no
 * port scanning, no directory brute-forcing and no shell execution. Third-party
 * OSINT indexes are queried for data they already hold, and the target itself
 * receives exactly one ordinary GET of its homepage (plus up to
 * `LIMITS.scripts` same-origin `<script src>` files it advertises), which is
 * indistinguishable from a single browser visit.
 */

import type { NextRequest } from 'next/server';

import { sanitizeDomain } from '@/lib/passive-recon/sanitize';
import { assertPublicHost } from '@/lib/passive-recon/net-guard';
import { extractEndpoints, extractScriptUrls } from '@/lib/passive-recon/js-parser';
import { collectDnsRecords } from '@/lib/passive-recon/dns-records';
import {
  parseRobotsTxt,
  parseSecurityTxt,
  parseSitemapLocs,
  resolveFaviconUrl,
  shodanFaviconHash,
} from '@/lib/passive-recon/recon-extras';
import {
  MODULE_IDS,
  type ArchivedPayload,
  type Confidence,
  type FaviconPayload,
  type HeaderRecord,
  type JsEndpointsPayload,
  type MetaPayload,
  type ModuleDoneEvent,
  type ModuleId,
  type ModulePayloads,
  type RobotsPayload,
  type ScanEvent,
  type SecurityTxtPayload,
  type SitemapPayload,
  type SourceStat,
  type SubdomainRecord,
  type SubdomainsPayload,
  type TechPayload,
  type Technology,
} from '@/lib/passive-recon/types';

// `node:dns` in the SSRF guard requires the Node runtime, not Edge.
export const runtime = 'nodejs';
// Allows the slowest OSINT index to finish on platforms that cap execution.
export const maxDuration = 60;

const USER_AGENT =
  'Mozilla/5.0 (compatible; PassiveReconDashboard/1.0; +passive-osint)';

const TIMEOUTS = {
  osint: 15_000,
  target: 10_000,
  script: 8_000,
  meta: 8_000,
} as const;

const LIMITS = {
  subdomains: 2_000,
  archivedUrls: 3_000,
  /** Same-origin bundles fetched per scan — kept low to stay polite. */
  scripts: 6,
  endpoints: 500,
  htmlBytes: 1_000_000,
  scriptBytes: 1_500_000,
  osintBytes: 8_000_000,
  robotsBytes: 100_000,
  securityTxtBytes: 20_000,
  sitemapBytes: 2_000_000,
  /** Sitemap documents followed per scan (an index can name hundreds). */
  sitemapDocs: 3,
  sitemapUrls: 1_000,
  faviconBytes: 300_000,
} as const;

/* -------------------------------------------------------------------------- */
/* Fetch plumbing                                                             */
/* -------------------------------------------------------------------------- */

function toMessage(error: unknown): string {
  if (error instanceof DOMException) {
    if (error.name === 'TimeoutError') return 'Upstream request timed out.';
    if (error.name === 'AbortError') return 'Request aborted.';
  }
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Reads a response body but stops after `maxBytes`.
 *
 * `await response.text()` on an attacker-influenced URL is an unbounded-memory
 * primitive — a multi-gigabyte body would take the process down. Streaming with
 * a hard ceiling keeps one hostile target from exhausting the server.
 */
async function readCapped(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return '';

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let out = '';
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      if (total + value.byteLength > maxBytes) {
        out += decoder.decode(value.slice(0, maxBytes - total));
        break;
      }

      total += value.byteLength;
      out += decoder.decode(value, { stream: true });
    }
  } finally {
    // Releases the socket when we bail out early.
    await reader.cancel().catch(() => {});
  }

  return out;
}

/** Byte-capped variant of `readCapped` for responses that are not text. */
async function readCappedBytes(
  response: Response,
  maxBytes: number,
): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array(0);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      if (total + value.byteLength > maxBytes) {
        chunks.push(value.subarray(0, maxBytes - total));
        total = maxBytes;
        break;
      }

      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

interface FetchOptions {
  parentSignal: AbortSignal;
  timeoutMs: number;
  maxBytes: number;
  accept?: string;
}

/** The shared request itself; callers decide how to drain the body. */
async function performFetch(
  url: string,
  { parentSignal, timeoutMs, accept }: FetchOptions,
): Promise<Response> {
  // Either the client hanging up or our own deadline cancels the request, so a
  // stalled upstream can never pin the connection open.
  const signal = AbortSignal.any([parentSignal, AbortSignal.timeout(timeoutMs)]);

  return fetch(url, {
    method: 'GET',
    redirect: 'follow',
    signal,
    cache: 'no-store',
    headers: {
      'User-Agent': USER_AGENT,
      Accept: accept ?? '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
    },
  });
}

async function fetchText(
  url: string,
  options: FetchOptions,
): Promise<{ response: Response; text: string }> {
  const response = await performFetch(url, options);
  return { response, text: await readCapped(response, options.maxBytes) };
}

async function fetchBytes(
  url: string,
  options: FetchOptions,
): Promise<{ response: Response; bytes: Uint8Array }> {
  const response = await performFetch(url, options);
  return { response, bytes: await readCappedBytes(response, options.maxBytes) };
}

/** Runs named sources concurrently, converting rejections into `SourceStat`s. */
async function runSources(
  sources: ReadonlyArray<{ name: string; run: () => Promise<string[]> }>,
): Promise<{ results: Array<{ name: string; items: string[] }>; stats: SourceStat[] }> {
  // Promise.allSettled is the requirement here: one dead index must degrade the
  // scan, never abort it.
  const settled = await Promise.allSettled(sources.map((source) => source.run()));

  const results: Array<{ name: string; items: string[] }> = [];
  const stats: SourceStat[] = [];

  settled.forEach((outcome, index) => {
    const { name } = sources[index];

    if (outcome.status === 'fulfilled') {
      results.push({ name, items: outcome.value });
      stats.push({ source: name, ok: true, count: outcome.value.length });
    } else {
      stats.push({
        source: name,
        ok: false,
        count: 0,
        error: toMessage(outcome.reason),
      });
    }
  });

  return { results, stats };
}

/* -------------------------------------------------------------------------- */
/* Module 1 — passive subdomain aggregation                                   */
/* -------------------------------------------------------------------------- */

function isInScope(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

/** Normalises a certificate/DNS name into a comparable hostname. */
function normalizeHost(raw: string): string {
  return raw.trim().toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '');
}

async function fetchHackerTarget(
  domain: string,
  parentSignal: AbortSignal,
): Promise<string[]> {
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  const { text } = await fetchText(url, {
    parentSignal,
    timeoutMs: TIMEOUTS.osint,
    maxBytes: LIMITS.osintBytes,
  });

  // The API signals failure with a 200 + plain-text message, so status codes
  // alone are not enough to detect quota exhaustion.
  if (/API count exceeded|error check your search parameter/i.test(text)) {
    throw new Error(text.trim().slice(0, 120));
  }

  return text
    .split('\n')
    .map((line) => normalizeHost(line.split(',')[0] ?? ''))
    .filter((host) => host.length > 0 && isInScope(host, domain));
}

async function fetchCrtSh(domain: string, parentSignal: AbortSignal): Promise<string[]> {
  // `%25` is a literal '%' — crt.sh's SQL-style wildcard for "any subdomain".
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  const { response, text } = await fetchText(url, {
    parentSignal,
    timeoutMs: TIMEOUTS.osint,
    maxBytes: LIMITS.osintBytes,
    accept: 'application/json',
  });

  if (!response.ok) {
    throw new Error(`crt.sh responded ${response.status}.`);
  }

  let rows: Array<{ name_value?: string; common_name?: string }>;
  try {
    rows = JSON.parse(text);
  } catch {
    throw new Error('crt.sh returned a non-JSON body (commonly a rate limit).');
  }

  const hosts = new Set<string>();

  for (const row of rows) {
    // `name_value` packs every SAN of the certificate into one newline string.
    for (const candidate of [
      ...(row.name_value?.split('\n') ?? []),
      row.common_name ?? '',
    ]) {
      const host = normalizeHost(candidate);
      if (host && isInScope(host, domain)) hosts.add(host);
    }
  }

  return [...hosts];
}

async function collectSubdomains(
  domain: string,
  parentSignal: AbortSignal,
): Promise<SubdomainsPayload> {
  const { results, stats } = await runSources([
    { name: 'HackerTarget', run: () => fetchHackerTarget(domain, parentSignal) },
    { name: 'crt.sh', run: () => fetchCrtSh(domain, parentSignal) },
  ]);

  // Track which sources reported each host — agreement across independent
  // indexes is a useful confidence signal when triaging a large list.
  const merged = new Map<string, Set<string>>();

  for (const { name, items } of results) {
    for (const host of items) {
      const entry = merged.get(host);
      if (entry) entry.add(name);
      else merged.set(host, new Set([name]));
    }
  }

  const subdomains: SubdomainRecord[] = [...merged.entries()]
    .map(([host, sources]) => ({ host, sources: [...sources].sort() }))
    .sort((a, b) => a.host.localeCompare(b.host))
    .slice(0, LIMITS.subdomains);

  return { subdomains, sources: stats };
}

/* -------------------------------------------------------------------------- */
/* Module 2 — passive historical URL aggregation (GAU / Wayback logic)        */
/* -------------------------------------------------------------------------- */

async function fetchWayback(domain: string, parentSignal: AbortSignal): Promise<string[]> {
  const url =
    'https://web.archive.org/cdx/search/cdx' +
    `?url=${encodeURIComponent(`*.${domain}/*`)}` +
    '&output=json&fl=original&collapse=urlkey' +
    `&limit=${LIMITS.archivedUrls}`;

  const { response, text } = await fetchText(url, {
    parentSignal,
    timeoutMs: TIMEOUTS.osint,
    maxBytes: LIMITS.osintBytes,
    accept: 'application/json',
  });

  if (!response.ok) throw new Error(`Wayback CDX responded ${response.status}.`);
  if (text.trim().length === 0) return [];

  let rows: string[][];
  try {
    rows = JSON.parse(text);
  } catch {
    throw new Error('Wayback CDX returned a malformed body.');
  }

  // Row 0 is the column header (["original"]), not data.
  return rows.slice(1).map((row) => row[0]).filter(Boolean);
}

async function fetchCommonCrawl(
  domain: string,
  parentSignal: AbortSignal,
): Promise<string[]> {
  // The index name rotates every crawl, so resolve the newest one rather than
  // hardcoding an ID that silently rots.
  const { response: infoResponse, text: infoText } = await fetchText(
    'https://index.commoncrawl.org/collinfo.json',
    {
      parentSignal,
      timeoutMs: TIMEOUTS.osint,
      maxBytes: 2_000_000,
      accept: 'application/json',
    },
  );

  if (!infoResponse.ok) {
    throw new Error(`Common Crawl index list responded ${infoResponse.status}.`);
  }

  let collections: Array<{ 'cdx-api'?: string }>;
  try {
    collections = JSON.parse(infoText);
  } catch {
    throw new Error('Common Crawl index list was malformed.');
  }

  const cdxApi = collections[0]?.['cdx-api'];
  if (!cdxApi) throw new Error('No Common Crawl index is currently available.');

  const url =
    `${cdxApi}?url=${encodeURIComponent(`*.${domain}`)}` +
    `&output=json&fl=url&limit=${LIMITS.archivedUrls}`;

  const { response, text } = await fetchText(url, {
    parentSignal,
    timeoutMs: TIMEOUTS.osint,
    maxBytes: LIMITS.osintBytes,
    accept: 'application/json',
  });

  // A target absent from the crawl legitimately 404s; that is empty, not broken.
  if (response.status === 404) return [];
  if (!response.ok) throw new Error(`Common Crawl responded ${response.status}.`);

  // This endpoint emits NDJSON, not a JSON array.
  const urls: string[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as { url?: string };
      if (parsed.url) urls.push(parsed.url);
    } catch {
      // Tolerate a truncated final line from the byte cap.
    }
  }
  return urls;
}

async function collectArchivedUrls(
  domain: string,
  parentSignal: AbortSignal,
): Promise<ArchivedPayload> {
  const { results, stats } = await runSources([
    { name: 'Wayback Machine', run: () => fetchWayback(domain, parentSignal) },
    { name: 'Common Crawl', run: () => fetchCommonCrawl(domain, parentSignal) },
  ]);

  const unique = new Set<string>();
  for (const { items } of results) {
    for (const url of items) unique.add(url);
  }

  const all = [...unique].sort();
  const urls = all.slice(0, LIMITS.archivedUrls);

  return { urls, sources: stats, truncated: all.length > urls.length };
}

/* -------------------------------------------------------------------------- */
/* Shared single request to the target                                        */
/* -------------------------------------------------------------------------- */

type HomepageResult =
  | { ok: true; response: Response; html: string; finalUrl: string }
  | { ok: false; error: string };

/**
 * Fetches the target homepage exactly once and shares it between the tech and
 * JS-endpoint modules, so a scan never hits the target twice for the same body.
 *
 * Resolves to a result object instead of rejecting: two modules await this
 * promise, and a rejected shared promise would surface as an unhandled
 * rejection for whichever consumer attached second.
 */
async function fetchHomepage(
  domain: string,
  parentSignal: AbortSignal,
): Promise<HomepageResult> {
  try {
    const { response, text } = await fetchText(`https://${domain}/`, {
      parentSignal,
      timeoutMs: TIMEOUTS.target,
      maxBytes: LIMITS.htmlBytes,
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    });

    return {
      ok: true,
      response,
      html: text,
      finalUrl: response.url || `https://${domain}/`,
    };
  } catch (error) {
    return { ok: false, error: toMessage(error) };
  }
}

/* -------------------------------------------------------------------------- */
/* Module 3 — technology detection (Wappalyzer-style, passive)                */
/* -------------------------------------------------------------------------- */

interface HeaderRule {
  header: string;
  pattern: RegExp;
  /** `$1` is replaced with the first capture group (usually a version). */
  name: string;
  category: string;
  confidence: Confidence;
}

const HEADER_RULES: readonly HeaderRule[] = [
  { header: 'server', pattern: /nginx(?:\/([\d.]+))?/i, name: 'Nginx $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /apache(?:\/([\d.]+))?/i, name: 'Apache $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /microsoft-iis(?:\/([\d.]+))?/i, name: 'IIS $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /litespeed/i, name: 'LiteSpeed', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /envoy/i, name: 'Envoy', category: 'Proxy', confidence: 'high' },
  { header: 'server', pattern: /caddy/i, name: 'Caddy', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /cloudflare/i, name: 'Cloudflare', category: 'CDN / WAF', confidence: 'high' },
  { header: 'server', pattern: /gws/i, name: 'Google Web Server', category: 'Web Server', confidence: 'medium' },
  { header: 'server', pattern: /awselb/i, name: 'AWS ELB', category: 'Load Balancer', confidence: 'high' },
  { header: 'server', pattern: /vercel/i, name: 'Vercel', category: 'Hosting', confidence: 'high' },

  { header: 'x-powered-by', pattern: /php(?:\/([\d.]+))?/i, name: 'PHP $1', category: 'Language', confidence: 'high' },
  { header: 'x-powered-by', pattern: /asp\.net/i, name: 'ASP.NET', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /express/i, name: 'Express', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /next\.js/i, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /servlet/i, name: 'Java Servlet', category: 'Framework', confidence: 'high' },

  { header: 'x-aspnet-version', pattern: /([\d.]+)/, name: 'ASP.NET $1', category: 'Framework', confidence: 'high' },
  { header: 'x-generator', pattern: /drupal\s*([\d.]+)?/i, name: 'Drupal $1', category: 'CMS', confidence: 'high' },
  { header: 'x-drupal-cache', pattern: /.+/, name: 'Drupal', category: 'CMS', confidence: 'high' },
  { header: 'x-shopify-stage', pattern: /.+/, name: 'Shopify', category: 'E-commerce', confidence: 'high' },
  { header: 'x-wix-request-id', pattern: /.+/, name: 'Wix', category: 'CMS', confidence: 'high' },
  { header: 'x-ghost-cache-status', pattern: /.+/, name: 'Ghost', category: 'CMS', confidence: 'high' },

  { header: 'cf-ray', pattern: /.+/, name: 'Cloudflare', category: 'CDN / WAF', confidence: 'high' },
  { header: 'x-amz-cf-id', pattern: /.+/, name: 'AWS CloudFront', category: 'CDN', confidence: 'high' },
  { header: 'x-vercel-id', pattern: /.+/, name: 'Vercel', category: 'Hosting', confidence: 'high' },
  { header: 'x-nextjs-cache', pattern: /.+/, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { header: 'x-fastly-request-id', pattern: /.+/, name: 'Fastly', category: 'CDN', confidence: 'high' },
  { header: 'x-akamai-transformed', pattern: /.+/, name: 'Akamai', category: 'CDN', confidence: 'high' },
  { header: 'x-github-request-id', pattern: /.+/, name: 'GitHub Pages', category: 'Hosting', confidence: 'high' },
  { header: 'x-sucuri-id', pattern: /.+/, name: 'Sucuri WAF', category: 'CDN / WAF', confidence: 'high' },
  { header: 'x-varnish', pattern: /.+/, name: 'Varnish', category: 'Cache', confidence: 'high' },
  { header: 'via', pattern: /varnish/i, name: 'Varnish', category: 'Cache', confidence: 'medium' },
  { header: 'x-runtime', pattern: /.+/, name: 'Ruby on Rails', category: 'Framework', confidence: 'low' },

  { header: 'strict-transport-security', pattern: /.+/, name: 'HSTS', category: 'Security', confidence: 'high' },
  { header: 'content-security-policy', pattern: /.+/, name: 'CSP', category: 'Security', confidence: 'high' },
  { header: 'x-frame-options', pattern: /.+/, name: 'X-Frame-Options', category: 'Security', confidence: 'high' },
];

/** Session-cookie names are among the most reliable stack fingerprints. */
const COOKIE_RULES: ReadonlyArray<{ pattern: RegExp; name: string; category: string }> = [
  { pattern: /^phpsessid$/i, name: 'PHP', category: 'Language' },
  { pattern: /^jsessionid$/i, name: 'Java / Servlet', category: 'Framework' },
  { pattern: /^asp\.net_sessionid$|^\.aspxauth$/i, name: 'ASP.NET', category: 'Framework' },
  { pattern: /^laravel_session$|^xsrf-token$/i, name: 'Laravel', category: 'Framework' },
  { pattern: /^_rails_session$|^_session_id$/i, name: 'Ruby on Rails', category: 'Framework' },
  { pattern: /^csrftoken$|^django_language$/i, name: 'Django', category: 'Framework' },
  { pattern: /^connect\.sid$/i, name: 'Express', category: 'Framework' },
  { pattern: /^ci_session$/i, name: 'CodeIgniter', category: 'Framework' },
  { pattern: /^wordpress_|^wp-settings/i, name: 'WordPress', category: 'CMS' },
];

/**
 * Front-end frameworks leave no header trace, so they are detected from markup
 * the server already returned — still passive, just a different signal source.
 */
const HTML_RULES: ReadonlyArray<{
  pattern: RegExp;
  name: string;
  category: string;
  confidence: Confidence;
}> = [
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i, name: '$1', category: 'Generator', confidence: 'high' },
  { pattern: /\/_next\/static\//, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { pattern: /__NEXT_DATA__/, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { pattern: /__NUXT__/, name: 'Nuxt', category: 'Framework', confidence: 'high' },
  { pattern: /ng-version=["']([^"']+)["']/i, name: 'Angular $1', category: 'Framework', confidence: 'high' },
  { pattern: /data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js/i, name: 'React', category: 'Framework', confidence: 'medium' },
  { pattern: /__sveltekit|svelte-/i, name: 'Svelte / SvelteKit', category: 'Framework', confidence: 'medium' },
  { pattern: /___gatsby/, name: 'Gatsby', category: 'Framework', confidence: 'high' },
  { pattern: /\/wp-content\/|\/wp-includes\//i, name: 'WordPress', category: 'CMS', confidence: 'high' },
  { pattern: /cdn\.shopify\.com/i, name: 'Shopify', category: 'E-commerce', confidence: 'high' },
  { pattern: /jquery(?:[-.]([\d.]+))?(?:\.min)?\.js/i, name: 'jQuery $1', category: 'Library', confidence: 'medium' },
  { pattern: /bootstrap(?:[-.]([\d.]+))?(?:\.min)?\.css/i, name: 'Bootstrap $1', category: 'UI Framework', confidence: 'medium' },
  { pattern: /googletagmanager\.com\/gtm\.js/i, name: 'Google Tag Manager', category: 'Analytics', confidence: 'high' },
];

function applyTemplate(template: string, match: RegExpMatchArray): string {
  return template.replace('$1', match[1] ?? '').trim();
}

/** Reads `Set-Cookie` names only — values are deliberately never captured. */
function readCookieNames(headers: Headers): string[] {
  const raw =
    typeof headers.getSetCookie === 'function'
      ? headers.getSetCookie()
      : headers.get('set-cookie')
        ? [headers.get('set-cookie') as string]
        : [];

  const names = new Set<string>();
  for (const cookie of raw) {
    const name = cookie.split('=')[0]?.trim();
    if (name) names.add(name);
  }
  return [...names];
}

async function fingerprintTech(homepage: Promise<HomepageResult>): Promise<TechPayload> {
  const result = await homepage;
  if (!result.ok) throw new Error(result.error);

  const { response, html, finalUrl } = result;
  const found = new Map<string, Technology>();

  const add = (tech: Technology) => {
    // First match wins so a high-confidence hit is not overwritten by a weaker
    // rule for the same product.
    if (tech.name && !found.has(tech.name)) found.set(tech.name, tech);
  };

  for (const rule of HEADER_RULES) {
    const value = response.headers.get(rule.header);
    if (!value) continue;

    const match = value.match(rule.pattern);
    if (!match) continue;

    add({
      name: applyTemplate(rule.name, match),
      category: rule.category,
      evidence: `${rule.header}: ${value.slice(0, 120)}`,
      confidence: rule.confidence,
    });
  }

  const cookieNames = readCookieNames(response.headers);
  for (const cookieName of cookieNames) {
    for (const rule of COOKIE_RULES) {
      if (!rule.pattern.test(cookieName)) continue;
      add({
        name: rule.name,
        category: rule.category,
        evidence: `Set-Cookie: ${cookieName}`,
        confidence: 'high',
      });
    }
  }

  for (const rule of HTML_RULES) {
    const match = html.match(rule.pattern);
    if (!match) continue;
    add({
      name: applyTemplate(rule.name, match),
      category: rule.category,
      evidence: `HTML body: ${match[0].slice(0, 100)}`,
      confidence: rule.confidence,
    });
  }

  // Set-Cookie is excluded on purpose; its names are reported separately and
  // its values are never persisted into a report the operator may share.
  const headers: HeaderRecord[] = [...response.headers.entries()]
    .filter(([name]) => name.toLowerCase() !== 'set-cookie')
    .map(([name, value]) => ({ name, value: value.slice(0, 300) }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return {
    finalUrl,
    status: response.status,
    technologies: [...found.values()].sort(
      (a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name),
    ),
    headers,
    cookieNames,
  };
}

/* -------------------------------------------------------------------------- */
/* Module 4 — static JS endpoint mining                                       */
/* -------------------------------------------------------------------------- */

async function collectJsEndpoints(
  domain: string,
  homepage: Promise<HomepageResult>,
  parentSignal: AbortSignal,
): Promise<JsEndpointsPayload> {
  const result = await homepage;
  if (!result.ok) throw new Error(result.error);

  const allScripts = extractScriptUrls(result.html, result.finalUrl);
  const scripts = allScripts.slice(0, LIMITS.scripts);

  const settled = await Promise.allSettled(
    scripts.map(async (scriptUrl) => {
      const { text } = await fetchText(scriptUrl, {
        parentSignal,
        timeoutMs: TIMEOUTS.script,
        maxBytes: LIMITS.scriptBytes,
        accept: 'application/javascript,text/javascript,*/*;q=0.8',
      });
      return extractEndpoints(text, domain);
    }),
  );

  const endpoints = new Set<string>();
  let scanned = 0;

  for (const outcome of settled) {
    if (outcome.status !== 'fulfilled') continue;
    scanned += 1;
    for (const endpoint of outcome.value) endpoints.add(endpoint);
  }

  const all = [...endpoints].sort();

  return {
    scripts: allScripts,
    endpoints: all.slice(0, LIMITS.endpoints),
    scanned,
    truncated: all.length > LIMITS.endpoints || allScripts.length > scripts.length,
  };
}

/* -------------------------------------------------------------------------- */
/* Module 5 — recon extras (robots.txt, sitemap, security.txt, favicon)       */
/* -------------------------------------------------------------------------- */

async function fetchRobotsTxt(
  domain: string,
  parentSignal: AbortSignal,
): Promise<RobotsPayload> {
  const url = `https://${domain}/robots.txt`;
  const missing: RobotsPayload = { found: false, url, disallowed: [], sitemaps: [] };

  try {
    const { response, text } = await fetchText(url, {
      parentSignal,
      timeoutMs: TIMEOUTS.meta,
      maxBytes: LIMITS.robotsBytes,
      accept: 'text/plain,*/*;q=0.8',
    });

    // Not publishing robots.txt is normal, so a 404 is a result, not a failure.
    if (!response.ok) return missing;

    return { found: true, url, ...parseRobotsTxt(text) };
  } catch {
    return missing;
  }
}

/**
 * Keeps only sitemap URLs that stay on the target site.
 *
 * robots.txt is target-controlled content: a hostile host could declare
 * `Sitemap: http://169.254.169.254/...` and turn this module into an SSRF
 * primitive. Restricting to the target's own site mirrors the same-origin rule
 * `js-parser.ts` already applies to script references — and a sitemap hosted
 * somewhere else is not the target's sitemap anyway.
 */
function sameSiteSitemaps(declared: string[], domain: string): string[] {
  const out: string[] = [];

  for (const raw of declared) {
    try {
      const parsed = new URL(raw);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      if (parsed.hostname !== domain && !parsed.hostname.endsWith(`.${domain}`)) {
        continue;
      }
      out.push(parsed.toString());
    } catch {
      continue;
    }
  }

  return out;
}

async function fetchSitemap(
  domain: string,
  declared: string[],
  parentSignal: AbortSignal,
): Promise<SitemapPayload> {
  const candidates = [
    ...new Set([...declared, `https://${domain}/sitemap.xml`]),
  ].slice(0, LIMITS.sitemapDocs);

  const settled = await Promise.allSettled(
    candidates.map(async (url) => {
      const { response, text } = await fetchText(url, {
        parentSignal,
        timeoutMs: TIMEOUTS.meta,
        maxBytes: LIMITS.sitemapBytes,
        accept: 'application/xml,text/xml,*/*;q=0.8',
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return { url, locs: parseSitemapLocs(text) };
    }),
  );

  const documents: string[] = [];
  const urls = new Set<string>();

  for (const outcome of settled) {
    if (outcome.status !== 'fulfilled') continue;
    documents.push(outcome.value.url);
    for (const loc of outcome.value.locs) urls.add(loc);
  }

  const all = [...urls].sort();

  return {
    found: documents.length > 0,
    documents,
    urls: all.slice(0, LIMITS.sitemapUrls),
    truncated: all.length > LIMITS.sitemapUrls,
  };
}

async function fetchSecurityTxt(
  domain: string,
  parentSignal: AbortSignal,
): Promise<SecurityTxtPayload> {
  // RFC 9116 makes /.well-known/ authoritative; the bare path is a legacy
  // location still seen in the wild.
  const candidates = [
    `https://${domain}/.well-known/security.txt`,
    `https://${domain}/security.txt`,
  ];

  for (const url of candidates) {
    try {
      const { response, text } = await fetchText(url, {
        parentSignal,
        timeoutMs: TIMEOUTS.meta,
        maxBytes: LIMITS.securityTxtBytes,
        accept: 'text/plain,*/*;q=0.8',
      });

      if (!response.ok) continue;

      const fields = parseSecurityTxt(text);
      // A soft-404 HTML page yields no parsable fields; treat that as absent.
      if (fields.length === 0) continue;

      return { found: true, url, fields };
    } catch {
      continue;
    }
  }

  return { found: false, url: null, fields: [] };
}

async function fetchFavicon(
  homepage: HomepageResult,
  parentSignal: AbortSignal,
): Promise<FaviconPayload> {
  const missing: FaviconPayload = {
    found: false,
    url: null,
    hash: null,
    bytes: null,
  };

  if (!homepage.ok) return missing;

  const url = resolveFaviconUrl(homepage.html, homepage.finalUrl);
  if (!url) return missing;

  try {
    // The href comes from target-controlled markup and may name any host, so it
    // gets the same public-address check as the target. Refusing off-site icons
    // outright would be wrong — large sites legitimately serve favicons from a
    // CDN, and that icon is still the one Shodan indexed.
    const guard = await assertPublicHost(new URL(url).hostname);
    if (!guard.ok) return { ...missing, url };

    const { response, bytes } = await fetchBytes(url, {
      parentSignal,
      timeoutMs: TIMEOUTS.meta,
      maxBytes: LIMITS.faviconBytes,
      accept: 'image/*,*/*;q=0.8',
    });

    if (!response.ok || bytes.length === 0) return { ...missing, url };

    return {
      found: true,
      url,
      hash: shodanFaviconHash(bytes),
      bytes: bytes.length,
    };
  } catch {
    return { ...missing, url };
  }
}

/**
 * Best-effort metadata sweep.
 *
 * Every sub-fetch absorbs its own failure into a `found: false` result, so this
 * never throws and the module always reports a partial. A target that publishes
 * no security.txt is a normal finding, not a broken scan.
 */
async function collectMeta(
  domain: string,
  homepage: Promise<HomepageResult>,
  parentSignal: AbortSignal,
): Promise<MetaPayload> {
  // Reuses the one shared homepage request rather than fetching the page again.
  const page = await homepage;

  // robots.txt runs first because it declares the sitemaps the next step reads.
  const robots = await fetchRobotsTxt(domain, parentSignal);

  const [sitemap, securityTxt, favicon] = await Promise.all([
    fetchSitemap(domain, sameSiteSitemaps(robots.sitemaps, domain), parentSignal),
    fetchSecurityTxt(domain, parentSignal),
    fetchFavicon(page, parentSignal),
  ]);

  return { robots, sitemap, securityTxt, favicon };
}

/* -------------------------------------------------------------------------- */
/* Route handler                                                              */
/* -------------------------------------------------------------------------- */

function badRequest(error: string): Response {
  return Response.json({ error }, { status: 400 });
}

/**
 * TypeScript cannot correlate a generic `K` with the distributed union member
 * it produces, so this one assertion is contained here rather than leaking an
 * `any` into every call site.
 */
function doneEvent<K extends ModuleId>(
  module: K,
  durationMs: number,
  data: ModulePayloads[K],
): ModuleDoneEvent {
  return { type: 'module_done', module, durationMs, data } as ModuleDoneEvent;
}

export async function POST(request: NextRequest): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return badRequest('Request body must be valid JSON.');
  }

  // Note: this endpoint takes `domain`, not the `target` key used by /api/scan.
  const raw = (body as { domain?: unknown } | null)?.domain;
  const sanitized = sanitizeDomain(raw);
  if (!sanitized.ok) return badRequest(sanitized.error);

  const { domain } = sanitized;

  // Second gate: the target must currently resolve to a public address.
  const guard = await assertPublicHost(domain);
  if (!guard.ok) return badRequest(guard.error);

  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;

      const send = (event: ScanEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          // The client hung up mid-scan; stop trying to write.
          closed = true;
        }
      };

      const startedAt = Date.now();

      try {
        send({
          type: 'scan_start',
          domain,
          startedAt: new Date(startedAt).toISOString(),
          modules: [...MODULE_IDS],
        });

        // One shared request to the target, consumed by two modules.
        const homepage = fetchHomepage(domain, request.signal);

        const run = async <K extends ModuleId>(
          module: K,
          task: () => Promise<ModulePayloads[K]>,
        ): Promise<void> => {
          const moduleStart = Date.now();
          send({ type: 'module_start', module });
          try {
            const data = await task();
            send(doneEvent(module, Date.now() - moduleStart, data));
          } catch (error) {
            send({
              type: 'module_error',
              module,
              durationMs: Date.now() - moduleStart,
              error: toMessage(error),
            });
          }
        };

        // allSettled is belt-and-braces: `run` already absorbs its own errors,
        // so this is purely the join barrier that lets every module finish.
        await Promise.allSettled([
          run('subdomains', () => collectSubdomains(domain, request.signal)),
          run('archived', () => collectArchivedUrls(domain, request.signal)),
          run('tech', () => fingerprintTech(homepage)),
          run('js-endpoints', () =>
            collectJsEndpoints(domain, homepage, request.signal),
          ),
          run('dns', () => collectDnsRecords(domain)),
          run('meta', () => collectMeta(domain, homepage, request.signal)),
        ]);

        send({
          type: 'scan_complete',
          finishedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        send({ type: 'scan_error', error: toMessage(error) });
      } finally {
        if (!closed) {
          try {
            controller.close();
          } catch {
            // Already closed by a client disconnect.
          }
        }
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      'X-Content-Type-Options': 'nosniff',
      // Stops reverse proxies (nginx) from buffering away the progressive flush.
      'X-Accel-Buffering': 'no',
    },
  });
}
