/**
 * Module 2 — passive historical URL aggregation (GAU / waybackurls logic):
 * Wayback CDX, Common Crawl, AlienVault OTX and urlscan.io.
 */

import { fetchJson, fetchText, LIMITS, runSources, TIMEOUTS } from '../scan-fetch';
import type { ArchivedPayload } from '../types';
import { fetchUrlscan } from './subdomains';

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
  const collections = await fetchJson<Array<{ 'cdx-api'?: string }>>(
    'https://index.commoncrawl.org/collinfo.json',
    { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: 2_000_000 },
    'Common Crawl index list',
  );

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

/** OTX's URL list — observed URLs, often more recent than the archives. */
async function fetchOtxUrls(domain: string, parentSignal: AbortSignal): Promise<string[]> {
  const urls = new Set<string>();

  // The endpoint pages at 500 rows; two pages is a good depth/latency trade.
  for (let page = 1; page <= 2; page += 1) {
    const url =
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}` +
      `/url_list?limit=500&page=${page}`;

    const payload = await fetchJson<{ url_list?: Array<{ url?: string }>; has_next?: boolean }>(
      url,
      { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: LIMITS.osintBytes },
      'AlienVault OTX URLs',
    );

    for (const row of payload.url_list ?? []) {
      if (row.url) urls.add(row.url);
    }

    if (!payload.has_next) break;
  }

  return [...urls];
}

export async function collectArchivedUrls(
  domain: string,
  parentSignal: AbortSignal,
): Promise<ArchivedPayload> {
  const { results, stats } = await runSources([
    { name: 'Wayback Machine', run: () => fetchWayback(domain, parentSignal) },
    { name: 'Common Crawl', run: () => fetchCommonCrawl(domain, parentSignal) },
    { name: 'AlienVault OTX', run: () => fetchOtxUrls(domain, parentSignal) },
    {
      name: 'urlscan.io',
      run: async () => {
        const rows = await fetchUrlscan(domain, parentSignal);
        const urls = new Set<string>();
        for (const row of rows) {
          for (const candidate of [row.page?.url, row.task?.url]) {
            if (candidate) urls.add(candidate);
          }
        }
        return [...urls];
      },
    },
  ]);

  const unique = new Set<string>();
  for (const { items } of results) {
    for (const url of items) unique.add(url);
  }

  const all = [...unique].sort();
  const urls = all.slice(0, LIMITS.archivedUrls);

  return { urls, sources: stats, truncated: all.length > urls.length };
}
