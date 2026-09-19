/**
 * Passive DNS record collection.
 *
 * Ordinary recursive resolution — the same lookups a browser performs before it
 * opens any connection — so this stays within the passive-only guarantee. No
 * packets are sent to the target itself; the configured resolver answers.
 */

import { Resolver } from 'node:dns/promises';

import { classifyResolution } from './takeover';
import { cymruOriginQuery, parseCymruAsName, parseCymruOrigin } from './whois-intel';
import { NULL_MX, type DnsPayload, type DnsRecord, type HostResolution, type SourceStat } from './types';

/**
 * Comma-separated resolver IPs, e.g. `PASSIVE_RECON_DNS_SERVERS=1.1.1.1,8.8.8.8`.
 *
 * Opt-in by design. `resolve*` uses c-ares, which reads its own nameserver
 * config rather than the OS resolver, and on some hosts (containers with a
 * stub resolv.conf, or a machine pointing at a local resolver that is not
 * running) it ends up with an unusable server and fails every query instantly.
 *
 * This is deliberately NOT defaulted to a public resolver: doing so would send
 * every scanned target's hostname to a third party, quietly exposing an
 * operator's scope list to whoever runs that resolver. Operators who want that
 * trade can ask for it explicitly.
 */
const DNS_SERVERS_ENV = 'PASSIVE_RECON_DNS_SERVERS';

/**
 * Node's resolver applies its own retry/backoff, which can outlast the scan if
 * a nameserver blackholes us, so every query gets an outer deadline.
 */
const QUERY_TIMEOUT_MS = 8_000;

/**
 * These resolver codes mean "this domain publishes no record of that type",
 * which is a perfectly normal answer — not a failed lookup. Reporting them as
 * errors would paint most healthy domains red (few publish a CNAME at apex).
 */
const EMPTY_RESULT_CODES = new Set(['ENODATA', 'ENOTFOUND']);

/**
 * Codes meaning the *resolver* is unusable rather than the record being absent.
 * When every query fails this way, the useful message is "your DNS is broken",
 * not seven copies of a c-ares errno.
 */
const RESOLVER_FAILURE_CODES = new Set([
  'ECONNREFUSED',
  'ESERVFAIL',
  'EREFUSED',
  'ETIMEOUT',
  'ENOTIMP',
  'EBADRESP',
]);

function toMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/** Builds a private resolver so we never mutate global DNS state. */
function createResolver(): Resolver {
  const resolver = new Resolver();
  const configured = process.env[DNS_SERVERS_ENV]?.trim();

  if (configured) {
    const servers = configured
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);

    try {
      if (servers.length > 0) resolver.setServers(servers);
    } catch {
      // A malformed override should degrade to the system resolver, not crash
      // the whole scan; the failure surfaces below if the system one is broken.
    }
  }

  return resolver;
}

async function withTimeout<T>(task: () => Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      task(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${label} lookup timed out after ${QUERY_TIMEOUT_MS}ms.`)),
          QUERY_TIMEOUT_MS,
        );
      }),
    ]);
  } finally {
    // Without this the pending timer keeps the event loop busy after a win.
    if (timer !== undefined) clearTimeout(timer);
  }
}

interface QuerySpec {
  type: string;
  run: (resolver: Resolver, domain: string) => Promise<DnsRecord[]>;
}

const QUERIES: readonly QuerySpec[] = [
  {
    type: 'A',
    run: async (resolver, domain) =>
      (await resolver.resolve4(domain)).map((value) => ({ type: 'A', value })),
  },
  {
    type: 'AAAA',
    run: async (resolver, domain) =>
      (await resolver.resolve6(domain)).map((value) => ({ type: 'AAAA', value })),
  },
  {
    type: 'MX',
    run: async (resolver, domain) =>
      (await resolver.resolveMx(domain)).map((record) => ({
        type: 'MX',
        // RFC 7505 lets a domain publish `MX 0 .` to declare that it handles no
        // mail at all; c-ares reports that root label as an empty exchange.
        value: record.exchange || NULL_MX,
        priority: record.priority,
      })),
  },
  {
    type: 'TXT',
    run: async (resolver, domain) =>
      // A TXT record longer than 255 bytes arrives as multiple chunks that are
      // concatenated with no separator to rebuild the original string.
      (await resolver.resolveTxt(domain)).map((chunks) => ({
        type: 'TXT',
        value: chunks.join(''),
      })),
  },
  {
    type: 'NS',
    run: async (resolver, domain) =>
      (await resolver.resolveNs(domain)).map((value) => ({ type: 'NS', value })),
  },
  {
    type: 'CNAME',
    run: async (resolver, domain) =>
      (await resolver.resolveCname(domain)).map((value) => ({
        type: 'CNAME',
        value,
      })),
  },
  {
    type: 'CAA',
    run: async (resolver, domain) =>
      // CAA names which CAs may issue for the domain. Its absence is itself a
      // finding: any public CA will issue without one.
      (await resolver.resolveCaa(domain)).map((record) => {
        const [tag, value] = Object.entries(record).find(([key]) => key !== 'critical') ?? [];
        return {
          type: 'CAA',
          value: `${tag ?? '?'} "${String(value ?? '')}"`,
        };
      }),
  },
  {
    type: 'SOA',
    run: async (resolver, domain) => {
      const soa = await resolver.resolveSoa(domain);
      return [
        {
          type: 'SOA',
          value:
            `${soa.nsname} ${soa.hostmaster} serial=${soa.serial} ` +
            `refresh=${soa.refresh} retry=${soa.retry} expire=${soa.expire}`,
        },
      ];
    },
  },
];

export async function collectDnsRecords(domain: string): Promise<DnsPayload> {
  const resolver = createResolver();

  // allSettled so one dead record type degrades that row only, never the module.
  const settled = await Promise.allSettled(
    QUERIES.map((query) => withTimeout(() => query.run(resolver, domain), query.type)),
  );

  const records: DnsRecord[] = [];
  const sources: SourceStat[] = [];
  let resolverFailures = 0;

  settled.forEach((outcome, index) => {
    const { type } = QUERIES[index];

    if (outcome.status === 'fulfilled') {
      records.push(...outcome.value);
      sources.push({ source: type, ok: true, count: outcome.value.length });
      return;
    }

    const code = (outcome.reason as NodeJS.ErrnoException | undefined)?.code;

    if (code && EMPTY_RESULT_CODES.has(code)) {
      sources.push({ source: type, ok: true, count: 0 });
      return;
    }

    if (code && RESOLVER_FAILURE_CODES.has(code)) resolverFailures += 1;

    sources.push({
      source: type,
      ok: false,
      count: 0,
      error: toMessage(outcome.reason),
    });
  });

  // Every single query failing at the transport level is one fault, not seven.
  // Surfacing it as a module error gives the operator something actionable
  // instead of a grid of identical errnos.
  if (resolverFailures === QUERIES.length) {
    const servers = resolver.getServers();
    throw new Error(
      `No usable DNS resolver: every query failed against [${
        servers.length > 0 ? servers.join(', ') : 'none configured'
      }]. Set ${DNS_SERVERS_ENV} (comma-separated IPs, e.g. "1.1.1.1,8.8.8.8") to override.`,
    );
  }

  records.sort(
    (a, b) => a.type.localeCompare(b.type) || a.value.localeCompare(b.value),
  );

  return { records, sources };
}

/* -------------------------------------------------------------------------- */
/* Targeted lookups                                                           */
/* -------------------------------------------------------------------------- */

/**
 * TXT records for an arbitrary name (`_dmarc.example.com`, a DKIM selector…).
 *
 * Returns `[]` rather than throwing when the name simply has no TXT record,
 * because "not published" is the answer the caller is asking about.
 */
export async function resolveTxtFor(name: string): Promise<string[]> {
  const resolver = createResolver();

  try {
    const chunks = await withTimeout(() => resolver.resolveTxt(name), `TXT ${name}`);
    return chunks.map((parts) => parts.join(''));
  } catch {
    return [];
  }
}

/** CAA records as `tag "value"` strings, or `[]` when none are published. */
export async function resolveCaaFor(domain: string): Promise<string[]> {
  const resolver = createResolver();

  try {
    const records = await withTimeout(() => resolver.resolveCaa(domain), `CAA ${domain}`);
    return records.map((record) => {
      const [tag, value] = Object.entries(record).find(([key]) => key !== 'critical') ?? [];
      return `${tag ?? '?'} "${String(value ?? '')}"`;
    });
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/* Host sweep (subdomain takeover detection)                                  */
/* -------------------------------------------------------------------------- */

/** Parallel resolutions in flight. High enough to be quick, low enough to be polite. */
const SWEEP_CONCURRENCY = 16;

async function resolveOne(resolver: Resolver, host: string): Promise<HostResolution> {
  let cname: string | null = null;
  let addresses: string[] = [];
  let errored = false;

  try {
    cname = (await withTimeout(() => resolver.resolveCname(host), `CNAME ${host}`))[0] ?? null;
  } catch (error) {
    // ENODATA just means "no CNAME at this name", which is the common case.
    const code = (error as NodeJS.ErrnoException).code;
    if (code && !EMPTY_RESULT_CODES.has(code)) errored = true;
  }

  try {
    addresses = await withTimeout(() => resolver.resolve4(host), `A ${host}`);
  } catch {
    try {
      addresses = await withTimeout(() => resolver.resolve6(host), `AAAA ${host}`);
    } catch {
      addresses = [];
    }
  }

  const classification = classifyResolution({
    host,
    addresses,
    cname,
    // A recursive resolver follows the CNAME chain for us: an address means the
    // chain terminates somewhere real, and no address with a CNAME present
    // means the target of that CNAME is gone.
    resolves: addresses.length > 0,
  });

  return {
    host,
    addresses,
    cname,
    ...classification,
    ...(errored && addresses.length === 0 && !cname
      ? { status: 'error' as const, note: 'Resolution failed.' }
      : {}),
  };
}

/**
 * Resolves discovered hosts and fingerprints their CNAMEs for takeover.
 *
 * Passivity note: these are ordinary recursive lookups — the same ones a
 * browser performs before it opens any connection — so nothing is sent to the
 * target's web servers. The target's *authoritative* nameservers may answer via
 * the recursive resolver, exactly as they do for any visitor. The sweep is
 * capped and concurrency-limited so it stays indistinguishable from normal
 * traffic.
 */
export async function sweepHosts(
  hosts: readonly string[],
  limit: number,
): Promise<HostResolution[]> {
  const resolver = createResolver();
  const queue = hosts.slice(0, limit);
  const results: HostResolution[] = [];
  let cursor = 0;

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= queue.length) return;

      try {
        results.push(await resolveOne(resolver, queue[index]));
      } catch {
        results.push({
          host: queue[index],
          addresses: [],
          cname: null,
          service: null,
          status: 'error',
          takeover: false,
          severity: 'info',
          note: 'Resolution failed.',
        });
      }
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(SWEEP_CONCURRENCY, queue.length) }, worker),
  );

  // Interesting first: takeover candidates, then dangling, then the rest.
  const rank = (host: HostResolution): number =>
    host.takeover ? 0 : host.status === 'dangling' ? 1 : host.status === 'live' ? 2 : 3;

  return results.sort((a, b) => rank(a) - rank(b) || a.host.localeCompare(b.host));
}

/* -------------------------------------------------------------------------- */
/* ASN lookup (Team Cymru, over DNS)                                          */
/* -------------------------------------------------------------------------- */

/**
 * Looks up the origin AS for an IPv4 address using Team Cymru's TXT service.
 *
 * DNS rather than an HTTP API on purpose: no key, no rate-limit headers, and
 * the query joins the same resolver traffic every other lookup uses.
 */
export async function lookupAsn(
  ip: string,
): Promise<{ asn: string | null; prefix: string | null; country: string | null; asnName: string | null }> {
  const empty = { asn: null, prefix: null, country: null, asnName: null };

  const query = cymruOriginQuery(ip);
  if (!query) return empty;

  const resolver = createResolver();

  let origin: string;
  try {
    const records = await withTimeout(() => resolver.resolveTxt(query), `ASN ${ip}`);
    origin = records[0]?.join('') ?? '';
  } catch {
    return empty;
  }

  if (!origin) return empty;

  const parsed = parseCymruOrigin(origin, ip);
  let asnName: string | null = null;

  if (parsed.asn) {
    try {
      const records = await withTimeout(
        () => resolver.resolveTxt(`AS${parsed.asn}.asn.cymru.com`),
        `AS name ${parsed.asn}`,
      );
      asnName = parseCymruAsName(records[0]?.join('') ?? '');
    } catch {
      // The origin lookup is the useful half; a missing name is cosmetic.
    }
  }

  return { asn: parsed.asn, prefix: parsed.prefix, country: parsed.country, asnName };
}
