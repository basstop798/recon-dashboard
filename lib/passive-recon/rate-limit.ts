/**
 * Abuse controls for the scan endpoint.
 *
 * A hosted passive-recon tool is an attractive proxy: the person who clicks
 * "scan" is anonymous, but the requests that reach the OSINT indexes and the
 * target come from *your* server's IP. Without limits, a public deployment is
 * a free, unattributable scanning service — and the first thing that happens is
 * your IP gets rate-limited by crt.sh and friends, which breaks the tool for
 * everybody.
 *
 * Three independent controls, because each one covers a gap the others leave:
 *
 *   1. Per-client window — stops one person monopolising the instance. This is
 *      the weakest of the three: client identity comes from a header, so it is
 *      spoofable unless a trusted proxy sets it (see `clientKey`).
 *   2. Global window — caps how much this deployment can burn through upstream
 *      APIs per hour *in total*. Header spoofing does not get around this one.
 *   3. Concurrency — caps simultaneous in-flight scans, which is what actually
 *      protects CPU, sockets and platform execution limits.
 *
 * State is per-process and in memory. On a single VM or container that is the
 * whole deployment and the limits hold exactly. On serverless (Vercel, Lambda)
 * each warm instance keeps its own counters, so the effective ceiling is the
 * configured limit multiplied by the number of live instances — deliberately
 * documented in the README rather than papered over. A deployment that needs
 * exact global limits wants Redis, or the platform's own edge rate limiting in
 * front of this.
 */

export interface GateConfig {
  /** Scans allowed per client per window. */
  perClient: number;
  /** Scans allowed across all clients per window. */
  perInstance: number;
  windowMs: number;
  /** Simultaneous in-flight scans. */
  maxConcurrent: number;
}

export const DEFAULT_CONFIG: GateConfig = {
  perClient: 5,
  perInstance: 60,
  windowMs: 10 * 60_000,
  maxConcurrent: 3,
};

/** "1 scan" / "5 scans" — the message is user-facing, so it should read right. */
function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

function positiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const value = Number(raw.trim());
  // A malformed override must not silently disable the control it configures.
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

export function readGateConfig(env: NodeJS.ProcessEnv = process.env): GateConfig {
  return {
    perClient: positiveInt(env.PASSIVE_RECON_RATE_PER_CLIENT, DEFAULT_CONFIG.perClient),
    perInstance: positiveInt(env.PASSIVE_RECON_RATE_PER_INSTANCE, DEFAULT_CONFIG.perInstance),
    windowMs: positiveInt(env.PASSIVE_RECON_RATE_WINDOW_MS, DEFAULT_CONFIG.windowMs),
    maxConcurrent: positiveInt(env.PASSIVE_RECON_MAX_CONCURRENT, DEFAULT_CONFIG.maxConcurrent),
  };
}

/* -------------------------------------------------------------------------- */
/* Client identity                                                            */
/* -------------------------------------------------------------------------- */

/** Strips a port suffix and an IPv6 zone index, and normalises case. */
function normalizeAddress(raw: string): string {
  let value = raw.trim().toLowerCase();
  if (!value) return '';

  // "[2001:db8::1]:443" -> "2001:db8::1"
  const bracketed = value.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) value = bracketed[1];
  // "203.0.113.4:51234" -> "203.0.113.4" (IPv4 only; a bare IPv6 has many colons)
  else if ((value.match(/:/g)?.length ?? 0) === 1) value = value.split(':')[0];

  return value.split('%')[0];
}

/**
 * Buckets an IPv6 address by its /64.
 *
 * A single residential IPv6 allocation is usually a /64 or larger, so limiting
 * by the full address lets one person rotate through billions of addresses for
 * free. IPv4 is used whole — NAT means one address is often many people, and
 * bucketing it further would punish them collectively.
 */
function bucketAddress(address: string): string {
  if (!address.includes(':')) return address;

  // Expand only as far as needed to take the first four hextets.
  const [head] = address.split('::');
  const groups = head.split(':').filter(Boolean).slice(0, 4);
  return groups.length >= 4 ? `${groups.join(':')}::/64` : `${address}/128`;
}

/**
 * Derives a rate-limit key from request headers.
 *
 * `NextRequest.ip` was removed in Next 15, so the client address has to come
 * from a forwarding header. Those are attacker-controlled unless a proxy you
 * trust overwrites them — which is why the global window and the concurrency
 * cap, neither of which depends on client identity, are the real controls.
 * Set `PASSIVE_RECON_TRUST_PROXY=false` when the app is exposed directly to
 * the internet: every client then shares one bucket, which is strict but
 * honest.
 */
export function clientKey(
  headers: Headers,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (env.PASSIVE_RECON_TRUST_PROXY === 'false') return 'direct';

  const forwarded = headers.get('x-forwarded-for');
  if (forwarded) {
    // Leftmost entry is the original client as recorded by the first proxy.
    const first = normalizeAddress(forwarded.split(',')[0] ?? '');
    if (first) return bucketAddress(first);
  }

  for (const header of ['x-real-ip', 'cf-connecting-ip', 'true-client-ip']) {
    const value = headers.get(header);
    if (value) {
      const address = normalizeAddress(value);
      if (address) return bucketAddress(address);
    }
  }

  return 'unknown';
}

/* -------------------------------------------------------------------------- */
/* The gate                                                                   */
/* -------------------------------------------------------------------------- */

export type GateDecision =
  | { ok: true; release: () => void }
  | {
      ok: false;
      status: 429 | 503;
      error: string;
      retryAfterSeconds: number;
    };

/** Hard ceiling on tracked clients, so the map cannot grow without bound. */
const MAX_TRACKED_CLIENTS = 10_000;

export class ScanGate {
  private readonly clients = new Map<string, number[]>();
  private readonly instance: number[] = [];
  private inFlight = 0;

  constructor(private readonly config: GateConfig) {}

  /**
   * Drops timestamps that have fallen out of the window, in place.
   *
   * In place on purpose. An earlier version returned a pruned copy, which
   * aliased the input whenever there was nothing to prune — so the caller's
   * `array.length = 0; array.push(...pruned)` emptied the very array it was
   * copying from, silently resetting the window on every request and disabling
   * the per-instance limit entirely. Mutating one array removes the class of
   * bug rather than the instance of it.
   */
  private prune(timestamps: number[], now: number): number[] {
    const cutoff = now - this.config.windowMs;
    // Timestamps are appended in order, so the expired ones are a prefix.
    let expired = 0;
    while (expired < timestamps.length && timestamps[expired] <= cutoff) expired += 1;
    if (expired > 0) timestamps.splice(0, expired);
    return timestamps;
  }

  /** Evicts clients whose window has fully expired. */
  private sweep(now: number): void {
    for (const [key, timestamps] of this.clients) {
      if (this.prune(timestamps, now).length === 0) this.clients.delete(key);
    }

    // Still oversized after a sweep means sustained traffic from many clients.
    // Dropping the oldest entries is the safe direction: a forgotten client
    // gets a fresh allowance, which is better than unbounded memory growth.
    if (this.clients.size > MAX_TRACKED_CLIENTS) {
      const excess = this.clients.size - MAX_TRACKED_CLIENTS;
      let removed = 0;
      for (const key of this.clients.keys()) {
        this.clients.delete(key);
        removed += 1;
        if (removed >= excess) break;
      }
    }
  }

  private retryAfter(timestamps: number[], now: number): number {
    const oldest = timestamps[0];
    if (oldest === undefined) return Math.ceil(this.config.windowMs / 1000);
    return Math.max(1, Math.ceil((oldest + this.config.windowMs - now) / 1000));
  }

  /**
   * Admits a scan, or explains why not.
   *
   * On success the caller MUST call `release()` exactly once when the scan
   * finishes — including on error and on client disconnect — or the
   * concurrency slot leaks and the instance slowly strangles itself.
   */
  admit(key: string, now = Date.now()): GateDecision {
    if (this.clients.size > MAX_TRACKED_CLIENTS) this.sweep(now);

    // Concurrency first: it is the control that protects this process, and
    // being turned away for it should not consume the caller's hourly quota.
    if (this.inFlight >= this.config.maxConcurrent) {
      return {
        ok: false,
        status: 503,
        error: `This instance is already running ${this.config.maxConcurrent} scans. Try again in a moment.`,
        retryAfterSeconds: 30,
      };
    }

    const instanceWindow = this.prune(this.instance, now);

    if (instanceWindow.length >= this.config.perInstance) {
      return {
        ok: false,
        status: 429,
        error:
          'This deployment has reached its scan quota for the current window. ' +
          'The limit exists to keep its IP in good standing with the upstream OSINT indexes.',
        retryAfterSeconds: this.retryAfter(instanceWindow, now),
      };
    }

    const clientWindow = this.prune(this.clients.get(key) ?? [], now);
    this.clients.set(key, clientWindow);

    if (clientWindow.length >= this.config.perClient) {
      const seconds = this.retryAfter(clientWindow, now);
      const minutes = Math.ceil(seconds / 60);
      return {
        ok: false,
        status: 429,
        error:
          `Rate limit: ${plural(this.config.perClient, 'scan')} per ` +
          `${plural(Math.round(this.config.windowMs / 60_000), 'minute')}. ` +
          `Try again in ${plural(minutes, 'minute')}.`,
        retryAfterSeconds: seconds,
      };
    }

    clientWindow.push(now);
    this.instance.push(now);
    this.inFlight += 1;

    let released = false;
    return {
      ok: true,
      release: () => {
        // Idempotent: the route releases from several paths (early return,
        // stream end, client disconnect) and must never double-decrement.
        if (released) return;
        released = true;
        this.inFlight = Math.max(0, this.inFlight - 1);
      },
    };
  }

  /** Current load, for the audit log. */
  stats(): { inFlight: number; trackedClients: number; instanceWindow: number } {
    return {
      inFlight: this.inFlight,
      trackedClients: this.clients.size,
      instanceWindow: this.instance.length,
    };
  }
}

/**
 * Process-wide gate.
 *
 * Module scope is the right lifetime: it is created once per server process and
 * shared by every request that process handles.
 */
export const scanGate = new ScanGate(readGateConfig());

/* -------------------------------------------------------------------------- */
/* Origin checking                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Rejects cross-site browser requests.
 *
 * This is not CORS and does not pretend to be: CORS is enforced by the browser
 * on *responses*, and stops nobody using curl. What this stops is a page on
 * another site quietly driving scans from its visitors' browsers to burn this
 * deployment's quota. A request with no `Origin` header (curl, a server, a
 * same-origin navigation) is allowed through to the rate limiter, which is the
 * control that actually applies to it.
 */
export function isAllowedOrigin(
  origin: string | null,
  host: string | null,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (!origin) return true;

  let originHost: string;
  try {
    originHost = new URL(origin).host.toLowerCase();
  } catch {
    return false;
  }

  if (host && originHost === host.toLowerCase()) return true;

  const allowed = env.PASSIVE_RECON_ALLOWED_ORIGINS?.split(',') ?? [];
  return allowed.some((entry) => {
    const trimmed = entry.trim().toLowerCase();
    if (!trimmed) return false;
    try {
      return new URL(trimmed).host === originHost;
    } catch {
      return trimmed === originHost;
    }
  });
}
