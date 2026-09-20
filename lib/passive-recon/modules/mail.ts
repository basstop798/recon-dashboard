/**
 * Module 6 — email security posture.
 *
 * Builds the mail posture from records the DNS module already fetched, plus
 * the two lookups only this module needs (`_dmarc` and the DKIM selectors).
 *
 * Reusing the shared DNS payload matters: SPF and MX live in the apex records
 * we have already paid for, so re-querying them would double the traffic for
 * no new information.
 */

import { resolveCaaFor, resolveTxtFor } from '../dns-records';
import { COMMON_DKIM_SELECTORS, parseDkimKey, parseDmarc, parseSpf } from '../mail-security';
import { unwrapOr, type Settled } from '../scan-fetch';
import type { MailPayload, ModulePayloads } from '../types';

export async function collectMailSecurity(
  domain: string,
  dns: Promise<Settled<ModulePayloads['dns']>>,
): Promise<MailPayload> {
  const records = (await unwrapOr(dns, { records: [], sources: [] })).records;

  const txt = records.filter((record) => record.type === 'TXT').map((record) => record.value);
  const mx = records
    .filter((record) => record.type === 'MX')
    .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));

  const caaFromDns = records
    .filter((record) => record.type === 'CAA')
    .map((record) => record.value);

  const [dmarcTxt, caa, dkim] = await Promise.all([
    resolveTxtFor(`_dmarc.${domain}`),
    caaFromDns.length > 0 ? Promise.resolve(caaFromDns) : resolveCaaFor(domain),
    Promise.all(
      COMMON_DKIM_SELECTORS.map(async (selector) => ({
        selector,
        // A DKIM key lives at <selector>._domainkey.<domain>; there is no way to
        // enumerate selectors, so a miss proves nothing (see mail-security.ts).
        ...parseDkimKey(await resolveTxtFor(`${selector}._domainkey.${domain}`)),
      })),
    ),
  ]);

  return {
    spf: parseSpf(txt),
    dmarc: parseDmarc(dmarcTxt),
    mx,
    caa,
    dkim,
  };
}
