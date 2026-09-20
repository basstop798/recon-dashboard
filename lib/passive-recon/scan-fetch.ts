/**
 * Shared HTTP plumbing for every passive-recon module.
 *
 * Centralised here because the SSRF re-check on redirects, the byte caps and
 * the settle-without-throwing helpers apply identically no matter which
 * module is doing the fetching — duplicating them per module would be how one
 * of them quietly loses the redirect guard.
 */

import { assertPublicHost } from './net-guard';
import type { SourceStat } from './types';

export const USER_AGENT =
  'Mozilla/5.0 (compatible; BulletReconDashboard/2.0; +passive-osint)';

export const TIMEOUTS = {
  osint: 20_000,
  target: 12_000,
  script: 10_000,
  meta: 8_000,
  rdap: 12_000,
} as const;

export const LIMITS = {
  subdomains: 5_000,
  archivedUrls: 5_000,
  /** Same-origin bundles fetched per scan — kept low to stay polite. */
  scripts: 12,
  endpoints: 1_000,
  secrets: 200,
  /** Discovered hosts put through the resolution/takeover sweep. */
  resolveHosts: 250,
  /** IPs sent to the ASN lookup. */
  asnLookups: 4,
  htmlBytes: 1_500_000,
  scriptBytes: 3_000_000,
  osintBytes: 12_000_000,
  robotsBytes: 200_000,
  securityTxtBytes: 20_000,
  sitemapBytes: 3_000_000,
  /** Sitemap documents followed per scan (an index can name hundreds). */
  sitemapDocs: 5,
  sitemapUrls: 3_000,
  faviconBytes: 300_000,
  wellKnownBytes: 60_000,
  wellKnownPreview: 400,
} as const;

export function toMessage(error: unknown): string {
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
export async function readCapped(response: Response, maxBytes: number): Promise<string> {
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
export async function readCappedBytes(
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

export interface FetchOptions {
  parentSignal: AbortSignal;
  timeoutMs: number;
  maxBytes: number;
  accept?: string;
}

/** Hops allowed before a redirect chain is treated as hostile or broken. */
const MAX_REDIRECTS = 5;

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/** Frees the socket for a response whose body we are never going to read. */
async function discard(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Already consumed or already errored; nothing left to release.
  }
}

export interface FetchResult {
  response: Response;
  /** The URL that actually served the body, after any redirects. */
  finalUrl: string;
  redirected: boolean;
}

/**
 * The shared request itself; callers decide how to drain the body.
 *
 * Redirects are followed by hand so that `assertPublicHost` runs on *every*
 * hop. Handing that to `redirect: 'follow'` was an SSRF hole: the gate in
 * `POST` only ever validates the domain the operator typed, so a target whose
 * homepage answered `302 http://169.254.169.254/` walked the fetch straight
 * into cloud metadata — and the body came back through the tech/JS modules,
 * which parse and display it. The same applies to any internal host reachable
 * from wherever this is deployed.
 */
export async function performFetch(
  url: string,
  { parentSignal, timeoutMs, accept }: FetchOptions,
): Promise<FetchResult> {
  // Either the client hanging up or our own deadline cancels the request, so a
  // stalled upstream can never pin the connection open. One signal covers the
  // whole redirect chain, so hops cannot be used to extend the deadline.
  const signal = AbortSignal.any([parentSignal, AbortSignal.timeout(timeoutMs)]);

  let current = url;

  for (let hop = 0; ; hop += 1) {
    const guard = await assertPublicHost(new URL(current).hostname);
    if (!guard.ok) throw new Error(guard.error);

    const response = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      signal,
      cache: 'no-store',
      headers: {
        'User-Agent': USER_AGENT,
        Accept: accept ?? '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });

    const location = response.headers.get('location');
    if (!isRedirectStatus(response.status) || !location) {
      return { response, finalUrl: current, redirected: hop > 0 };
    }

    if (hop >= MAX_REDIRECTS) {
      await discard(response);
      throw new Error(`More than ${MAX_REDIRECTS} redirects from ${url}.`);
    }

    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      await discard(response);
      throw new Error(`Invalid redirect target "${location}" from ${current}.`);
    }

    // `data:`, `file:` and friends are never a legitimate redirect for a web
    // page, and each one is a different way to sidestep the host check above.
    if (next.protocol !== 'https:' && next.protocol !== 'http:') {
      await discard(response);
      throw new Error(`Refusing to follow a "${next.protocol}" redirect from ${current}.`);
    }

    await discard(response);
    current = next.toString();
  }
}

export async function fetchText(
  url: string,
  options: FetchOptions,
): Promise<FetchResult & { text: string }> {
  const result = await performFetch(url, options);
  return { ...result, text: await readCapped(result.response, options.maxBytes) };
}

export async function fetchBytes(
  url: string,
  options: FetchOptions,
): Promise<FetchResult & { bytes: Uint8Array }> {
  const result = await performFetch(url, options);
  return { ...result, bytes: await readCappedBytes(result.response, options.maxBytes) };
}

/** Fetches JSON with the byte cap intact, and a clear error when it is not JSON. */
export async function fetchJson<T>(
  url: string,
  options: FetchOptions,
  label: string,
): Promise<T> {
  const { response, text } = await fetchText(url, { ...options, accept: 'application/json' });

  if (!response.ok) throw new Error(`${label} responded ${response.status}.`);
  if (text.trim().length === 0) throw new Error(`${label} returned an empty body.`);

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${label} returned a non-JSON body (commonly a rate limit).`);
  }
}

/** Runs named sources concurrently, converting rejections into `SourceStat`s. */
export async function runSources(
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

/**
 * Wraps a shared promise so several modules can await it safely.
 *
 * A rejected promise with more than one consumer surfaces as an unhandled
 * rejection for whichever consumer attached second, so the rejection is folded
 * into the value and re-thrown per consumer by `unwrap`.
 */
export type Settled<T> = { ok: true; value: T } | { ok: false; error: string };

export function share<T>(promise: Promise<T>): Promise<Settled<T>> {
  return promise.then(
    (value) => ({ ok: true, value }) as const,
    (error: unknown) => ({ ok: false, error: toMessage(error) }) as const,
  );
}

export async function unwrap<T>(settled: Promise<Settled<T>>): Promise<T> {
  const result = await settled;
  if (!result.ok) throw new Error(result.error);
  return result.value;
}

/** Awaits a shared promise, substituting a default when it failed. */
export async function unwrapOr<T>(settled: Promise<Settled<T>>, fallback: T): Promise<T> {
  const result = await settled;
  return result.ok ? result.value : fallback;
}
