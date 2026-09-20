/**
 * Module 7 — registration (RDAP) and network ownership (ASN).
 */

import { lookupAsn } from '../dns-records';
import { fetchJson, LIMITS, TIMEOUTS, toMessage, unwrapOr, type Settled } from '../scan-fetch';
import { EMPTY_WHOIS, parseRdapDomain } from '../whois-intel';
import type { ModulePayloads, SourceStat, WhoisPayload } from '../types';

export async function collectWhois(
  domain: string,
  dns: Promise<Settled<ModulePayloads['dns']>>,
  parentSignal: AbortSignal,
): Promise<WhoisPayload> {
  const sources: SourceStat[] = [];

  // RDAP: the IANA bootstrap service redirects to the registry that owns the
  // TLD, so one URL works for every domain without a per-TLD table.
  let domainRecord = EMPTY_WHOIS;
  try {
    const payload = await fetchJson<Parameters<typeof parseRdapDomain>[0]>(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { parentSignal, timeoutMs: TIMEOUTS.rdap, maxBytes: 2_000_000 },
      'RDAP',
    );
    domainRecord = parseRdapDomain(payload);
    sources.push({ source: 'RDAP', ok: true, count: 1 });
  } catch (error) {
    sources.push({ source: 'RDAP', ok: false, count: 0, error: toMessage(error) });
  }

  const addresses = (await unwrapOr(dns, { records: [], sources: [] })).records
    .filter((record) => record.type === 'A')
    .map((record) => record.value)
    .slice(0, LIMITS.asnLookups);

  const networks = await Promise.all(
    addresses.map(async (ip) => ({ ip, org: null, ...(await lookupAsn(ip)) })),
  );

  sources.push({
    source: 'Team Cymru ASN',
    ok: networks.some((network) => network.asn !== null) || networks.length === 0,
    count: networks.filter((network) => network.asn !== null).length,
  });

  return { domain: domainRecord, networks, sources };
}
