/**
 * Registration and network-ownership parsing.
 *
 * Two independent, pure parsers:
 *   1. RDAP (RFC 9083) — the structured JSON replacement for WHOIS text. No
 *      scraping, no rate-limited HTML, and no port-43 socket.
 *   2. Team Cymru's IP-to-ASN *DNS* service — an ordinary TXT lookup, so ASN
 *      ownership costs one resolver query instead of a third-party HTTP API.
 *
 * Why an operator cares: registrar and expiry dates catch soon-to-lapse domains,
 * and the ASN tells you which netblocks belong to the target, which is where the
 * rest of the estate usually hides.
 */

import type { DomainWhois, NetworkRecord } from './types';

/* -------------------------------------------------------------------------- */
/* RDAP                                                                       */
/* -------------------------------------------------------------------------- */

interface VCardEntry {
  0?: unknown;
  1?: unknown;
  2?: unknown;
  3?: unknown;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, VCardEntry[]];
  entities?: RdapEntity[];
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

export interface RdapDomainResponse {
  status?: string[];
  events?: RdapEvent[];
  entities?: RdapEntity[];
  nameservers?: Array<{ ldhName?: string }>;
  secureDNS?: { delegationSigned?: boolean };
}

/** Reads one property out of a jCard ("vcardArray") entity. */
function vcardValue(entity: RdapEntity, property: string): string | null {
  const entries = entity.vcardArray?.[1];
  if (!Array.isArray(entries)) return null;

  for (const entry of entries) {
    const record = entry as unknown[];
    if (record[0] !== property) continue;

    const value = record[3];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }

  return null;
}

function findEntities(entities: RdapEntity[] | undefined, role: string): RdapEntity[] {
  const out: RdapEntity[] = [];

  const walk = (list: RdapEntity[] | undefined) => {
    for (const entity of list ?? []) {
      if (entity.roles?.includes(role)) out.push(entity);
      // Abuse contacts are nested inside the registrar entity, not top level.
      walk(entity.entities);
    }
  };

  walk(entities);
  return out;
}

function eventDate(events: RdapEvent[] | undefined, action: string): string | null {
  return (
    events?.find((event) => event.eventAction?.toLowerCase() === action)?.eventDate ?? null
  );
}

export function parseRdapDomain(payload: RdapDomainResponse): DomainWhois {
  const registrar = findEntities(payload.entities, 'registrar')[0];
  const abuse = findEntities(payload.entities, 'abuse');

  const abuseContacts = new Set<string>();
  for (const entity of abuse) {
    const email = vcardValue(entity, 'email');
    if (email) abuseContacts.add(email);
  }

  return {
    found: true,
    registrar: registrar ? vcardValue(registrar, 'fn') : null,
    createdAt: eventDate(payload.events, 'registration'),
    updatedAt: eventDate(payload.events, 'last changed'),
    expiresAt: eventDate(payload.events, 'expiration'),
    statuses: (payload.status ?? []).map((status) => String(status)),
    nameservers: (payload.nameservers ?? [])
      .map((nameserver) => nameserver.ldhName?.toLowerCase() ?? '')
      .filter(Boolean)
      .sort(),
    abuseContacts: [...abuseContacts],
    dnssec: payload.secureDNS?.delegationSigned ?? null,
  };
}

export const EMPTY_WHOIS: DomainWhois = {
  found: false,
  registrar: null,
  createdAt: null,
  updatedAt: null,
  expiresAt: null,
  statuses: [],
  nameservers: [],
  abuseContacts: [],
  dnssec: null,
};

/* -------------------------------------------------------------------------- */
/* Team Cymru IP-to-ASN (DNS)                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Builds the TXT query name for an IPv4 address.
 *
 * `8.8.8.8` becomes `8.8.8.8.origin.asn.cymru.com` — the octets are reversed
 * exactly as they are for a PTR lookup.
 */
export function cymruOriginQuery(ip: string): string | null {
  const octets = ip.split('.');
  if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/.test(octet))) return null;
  return `${octets.reverse().join('.')}.origin.asn.cymru.com`;
}

/**
 * Parses `"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`.
 *
 * Several prefixes can answer one query; the caller passes whichever record it
 * prefers and this only splits fields.
 */
export function parseCymruOrigin(
  txt: string,
  ip: string,
): Pick<NetworkRecord, 'ip' | 'asn' | 'prefix' | 'country'> {
  const [asn, prefix, country] = txt.split('|').map((field) => field.trim());

  return {
    ip,
    // A prefix announced by multiple ASNs answers with a space-separated list.
    asn: asn ? asn.split(/\s+/)[0] : null,
    prefix: prefix || null,
    country: country || null,
  };
}

/** Parses `"15169 | US | arin | 2000-03-30 | GOOGLE, US"` from AS<n>.asn.cymru.com. */
export function parseCymruAsName(txt: string): string | null {
  const fields = txt.split('|').map((field) => field.trim());
  return fields[4] || null;
}
