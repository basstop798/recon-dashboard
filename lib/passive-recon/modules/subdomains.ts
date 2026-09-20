/**
 * Module 1 — passive subdomain aggregation (crt.sh, Cert Spotter, HackerTarget,
 * AlienVault OTX, Anubis, urlscan.io), merged with per-host source attribution.
 */

import { fetchJson, fetchText, LIMITS, runSources, TIMEOUTS } from '../scan-fetch';
import type { SubdomainRecord, SubdomainsPayload } from '../types';

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
  const rows = await fetchJson<Array<{ name_value?: string; common_name?: string }>>(
    url,
    { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: LIMITS.osintBytes },
    'crt.sh',
  );

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

/**
 * SSLMate's Cert Spotter — a second, independently operated CT feed.
 *
 * crt.sh is the community default and is also the one that rate-limits first,
 * so a scan that depends on it alone loses certificate transparency entirely on
 * a bad day.
 */
async function fetchCertSpotter(
  domain: string,
  parentSignal: AbortSignal,
): Promise<string[]> {
  const url =
    'https://api.certspotter.com/v1/issuances' +
    `?domain=${encodeURIComponent(domain)}` +
    '&include_subdomains=true&expand=dns_names';

  const rows = await fetchJson<Array<{ dns_names?: string[] }>>(
    url,
    { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: LIMITS.osintBytes },
    'Cert Spotter',
  );

  const hosts = new Set<string>();
  for (const row of rows) {
    for (const name of row.dns_names ?? []) {
      const host = normalizeHost(name);
      if (host && isInScope(host, domain)) hosts.add(host);
    }
  }
  return [...hosts];
}

/** AlienVault OTX passive DNS — hosts observed resolving, not just certificated. */
async function fetchOtxSubdomains(
  domain: string,
  parentSignal: AbortSignal,
): Promise<string[]> {
  const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(
    domain,
  )}/passive_dns`;

  const payload = await fetchJson<{ passive_dns?: Array<{ hostname?: string }> }>(
    url,
    { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: LIMITS.osintBytes },
    'AlienVault OTX',
  );

  const hosts = new Set<string>();
  for (const row of payload.passive_dns ?? []) {
    const host = normalizeHost(row.hostname ?? '');
    if (host && isInScope(host, domain)) hosts.add(host);
  }
  return [...hosts];
}

/** JonLuca's Anubis DB — an aggregate of several enumeration runs. */
async function fetchAnubis(domain: string, parentSignal: AbortSignal): Promise<string[]> {
  const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
  const rows = await fetchJson<string[]>(
    url,
    { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: LIMITS.osintBytes },
    'Anubis',
  );

  const hosts = new Set<string>();
  for (const row of Array.isArray(rows) ? rows : []) {
    const host = normalizeHost(String(row));
    if (host && isInScope(host, domain)) hosts.add(host);
  }
  return [...hosts];
}

export interface UrlscanResult {
  page?: { domain?: string; url?: string };
  task?: { domain?: string; url?: string };
}

/** urlscan.io submissions — hosts and URLs somebody already loaded in a browser. */
export async function fetchUrlscan(
  domain: string,
  parentSignal: AbortSignal,
): Promise<UrlscanResult[]> {
  const url = `https://urlscan.io/api/v1/search/?q=domain%3A${encodeURIComponent(
    domain,
  )}&size=1000`;

  const payload = await fetchJson<{ results?: UrlscanResult[] }>(
    url,
    { parentSignal, timeoutMs: TIMEOUTS.osint, maxBytes: LIMITS.osintBytes },
    'urlscan.io',
  );

  return payload.results ?? [];
}

export async function collectSubdomains(
  domain: string,
  parentSignal: AbortSignal,
): Promise<SubdomainsPayload> {
  const { results, stats } = await runSources([
    { name: 'crt.sh', run: () => fetchCrtSh(domain, parentSignal) },
    { name: 'Cert Spotter', run: () => fetchCertSpotter(domain, parentSignal) },
    { name: 'HackerTarget', run: () => fetchHackerTarget(domain, parentSignal) },
    { name: 'AlienVault OTX', run: () => fetchOtxSubdomains(domain, parentSignal) },
    { name: 'Anubis', run: () => fetchAnubis(domain, parentSignal) },
    {
      name: 'urlscan.io',
      run: async () => {
        const rows = await fetchUrlscan(domain, parentSignal);
        const hosts = new Set<string>();
        for (const row of rows) {
          for (const candidate of [row.page?.domain, row.task?.domain]) {
            const host = normalizeHost(candidate ?? '');
            if (host && isInScope(host, domain)) hosts.add(host);
          }
        }
        return [...hosts];
      },
    },
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

  const all = [...merged.entries()]
    .map(([host, sources]) => ({ host, sources: [...sources].sort() }))
    .sort((a, b) => a.host.localeCompare(b.host));

  const subdomains: SubdomainRecord[] = all.slice(0, LIMITS.subdomains);

  return { subdomains, sources: stats, truncated: all.length > subdomains.length };
}
