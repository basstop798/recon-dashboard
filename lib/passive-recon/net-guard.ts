/**
 * Server-only SSRF guard. Kept separate from `sanitize.ts` because it imports
 * `node:dns`, which would break the isomorphic import used by the client.
 *
 * `sanitizeDomain` proves the target *looks* like a public domain; this proves
 * it currently *resolves* to one. An attacker can otherwise point a perfectly
 * well-formed domain they control at 127.0.0.1 or 169.254.169.254.
 *
 * Known limitation (documented rather than hidden): this is a lookup-then-fetch
 * check, so it is theoretically defeatable by DNS rebinding — the record can
 * change between our resolution and the runtime's. Closing that fully requires
 * pinning the connection to the validated address via a custom agent. This
 * check still removes the trivial attack and is the right cost/benefit here.
 */

import { lookup } from 'node:dns/promises';

/** [network, prefix-length] pairs that must never be reachable. */
const BLOCKED_V4: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // RFC1918
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local — cloud metadata lives here
  ['172.16.0.0', 12], // RFC1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16], // RFC1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved / broadcast
];

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let acc = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    acc = acc * 256 + octet;
  }
  return acc;
}

export function isBlockedIpv4(ip: string): boolean {
  const value = ipv4ToInt(ip);
  if (value === null) return true; // unparseable -> fail closed

  for (const [network, bits] of BLOCKED_V4) {
    const base = ipv4ToInt(network);
    if (base === null) continue;
    // `>>> 0` keeps the mask unsigned; a /0 would shift by 32 (undefined), but
    // no entry uses /0 so the simple form is safe here.
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    if ((value & mask) >>> 0 === (base & mask) >>> 0) return true;
  }
  return false;
}

export function isBlockedIpv6(ip: string): boolean {
  const addr = ip.toLowerCase().split('%')[0]; // drop any zone index

  if (addr === '::' || addr === '::1') return true;

  // IPv4-mapped (::ffff:127.0.0.1) and IPv4-compatible forms re-enter v4 space.
  const mapped = addr.match(/^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isBlockedIpv4(mapped[1]);

  if (/^f[cd]/.test(addr)) return true; // fc00::/7 unique-local
  if (/^fe[89ab]/.test(addr)) return true; // fe80::/10 link-local
  if (/^ff/.test(addr)) return true; // ff00::/8 multicast

  return false;
}

export type HostGuardResult =
  | { ok: true; addresses: string[] }
  | { ok: false; error: string };

/**
 * Resolves `host` and refuses it if any returned address is internal.
 *
 * Fails closed on *any* blocked address rather than filtering to the good ones:
 * a host that advertises both a public and a loopback record is a rebinding
 * attempt, not a legitimate target.
 */
export async function assertPublicHost(host: string): Promise<HostGuardResult> {
  let records: Array<{ address: string; family: number }>;

  try {
    records = await lookup(host, { all: true });
  } catch {
    return { ok: false, error: `DNS resolution failed for "${host}".` };
  }

  if (records.length === 0) {
    return { ok: false, error: `"${host}" did not resolve to any address.` };
  }

  for (const { address, family } of records) {
    const blocked =
      family === 4 ? isBlockedIpv4(address) : isBlockedIpv6(address);

    if (blocked) {
      return {
        ok: false,
        error: `"${host}" resolves to a non-public address (${address}); refusing to scan.`,
      };
    }
  }

  return { ok: true, addresses: records.map((r) => r.address) };
}
