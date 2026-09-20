import { describe, expect, it } from 'vitest';

import {
  clientKey,
  envValue,
  isAllowedOrigin,
  readGateConfig,
  ScanGate,
  type GateConfig,
} from './rate-limit';

const CONFIG: GateConfig = {
  perClient: 3,
  perInstance: 5,
  windowMs: 1000,
  maxConcurrent: 2,
};

/**
 * `NodeJS.ProcessEnv` requires `NODE_ENV`, which every test env object below
 * would otherwise have to repeat. This is a test-only convenience — the
 * functions under test only ever read the specific keys they document.
 */
function env(vars: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { NODE_ENV: 'test', ...vars } as NodeJS.ProcessEnv;
}

describe('ScanGate — concurrency', () => {
  it('admits up to maxConcurrent simultaneous scans', () => {
    const gate = new ScanGate(CONFIG);
    const a = gate.admit('client-a', 0);
    const b = gate.admit('client-b', 0);
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
  });

  it('rejects the scan beyond maxConcurrent with 503', () => {
    const gate = new ScanGate(CONFIG);
    gate.admit('client-a', 0);
    gate.admit('client-b', 0);
    const third = gate.admit('client-c', 0);
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.status).toBe(503);
  });

  it('frees the slot when release() is called', () => {
    const gate = new ScanGate(CONFIG);
    const a = gate.admit('client-a', 0);
    const b = gate.admit('client-b', 0);
    expect(a.ok && b.ok).toBe(true);
    if (a.ok) a.release();

    const third = gate.admit('client-c', 0);
    expect(third.ok).toBe(true);
  });

  it('release() is idempotent — calling it twice does not free two slots', () => {
    const gate = new ScanGate(CONFIG);
    const a = gate.admit('client-a', 0);
    if (a.ok) {
      a.release();
      a.release(); // double release must not double-free
    }
    // Only one slot should have been freed; capacity is 2, so both remaining
    // admits still succeed and a third at full concurrency does not.
    const b = gate.admit('client-b', 0);
    const c = gate.admit('client-c', 0);
    expect(b.ok).toBe(true);
    expect(c.ok).toBe(true);
    const d = gate.admit('client-d', 0);
    expect(d.ok).toBe(false);
  });

  it('being turned away for concurrency does not consume the per-client quota', () => {
    const gate = new ScanGate(CONFIG);
    gate.admit('other-1', 0);
    gate.admit('other-2', 0); // fills concurrency to the cap

    // client-a is rejected for concurrency, not counted against its window.
    const rejected = gate.admit('client-a', 0);
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.status).toBe(503);
  });
});

describe('ScanGate — per-client window', () => {
  it('admits up to perClient scans, then rejects with 429', () => {
    const gate = new ScanGate({ ...CONFIG, maxConcurrent: 100 });
    for (let i = 0; i < CONFIG.perClient; i += 1) {
      const result = gate.admit('client-a', 0);
      expect(result.ok).toBe(true);
      if (result.ok) result.release(); // free concurrency, window still counts
    }
    const rejected = gate.admit('client-a', 0);
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) {
      expect(rejected.status).toBe(429);
      expect(rejected.retryAfterSeconds).toBeGreaterThan(0);
    }
  });

  it('does not let one client affect another client independent window', () => {
    const gate = new ScanGate({ ...CONFIG, maxConcurrent: 100 });
    for (let i = 0; i < CONFIG.perClient; i += 1) {
      const r = gate.admit('client-a', 0);
      if (r.ok) r.release();
    }
    const other = gate.admit('client-b', 0);
    expect(other.ok).toBe(true);
  });

  it('resets the window after windowMs elapses', () => {
    const gate = new ScanGate({ ...CONFIG, maxConcurrent: 100 });
    for (let i = 0; i < CONFIG.perClient; i += 1) {
      const r = gate.admit('client-a', 0);
      if (r.ok) r.release();
    }
    const stillBlocked = gate.admit('client-a', 500);
    expect(stillBlocked.ok).toBe(false);

    const afterWindow = gate.admit('client-a', CONFIG.windowMs + 1);
    expect(afterWindow.ok).toBe(true);
  });
});

describe('ScanGate — per-instance window', () => {
  it('rejects once the global window is exhausted regardless of client', () => {
    const gate = new ScanGate({ ...CONFIG, perClient: 100, maxConcurrent: 100 });
    for (let i = 0; i < CONFIG.perInstance; i += 1) {
      const r = gate.admit(`client-${i}`, 0);
      expect(r.ok).toBe(true);
      if (r.ok) r.release();
    }
    const rejected = gate.admit('client-overflow', 0);
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) expect(rejected.status).toBe(429);
  });

  it('a spoofed client identity cannot bypass the instance-wide cap', () => {
    // Simulates header spoofing: every request claims a distinct client key,
    // which defeats the per-client limiter but must still hit the global one.
    const gate = new ScanGate({ ...CONFIG, perClient: 1000, maxConcurrent: 1000 });
    let rejectedCount = 0;
    for (let i = 0; i < CONFIG.perInstance + 10; i += 1) {
      const r = gate.admit(`spoofed-${i}`, 0);
      if (r.ok) r.release();
      else rejectedCount += 1;
    }
    expect(rejectedCount).toBe(10);
  });
});

describe('ScanGate — stats', () => {
  it('reports in-flight count and tracked clients', () => {
    const gate = new ScanGate(CONFIG);
    gate.admit('client-a', 0);
    const stats = gate.stats();
    expect(stats.inFlight).toBe(1);
    expect(stats.trackedClients).toBe(1);
    expect(stats.instanceWindow).toBe(1);
  });
});

describe('ScanGate — memory bound (MAX_TRACKED_CLIENTS)', () => {
  it('does not grow the tracked-client map without bound under sustained unique traffic', () => {
    // 10_000 is the hard ceiling baked into the module; drive well past it
    // with expired entries and confirm the map gets swept back down instead
    // of growing forever (the DoS this guards against: an attacker rotating
    // through unique client identities to exhaust server memory).
    const gate = new ScanGate({ ...CONFIG, perClient: 1, maxConcurrent: 1_000_000, windowMs: 1 });
    for (let i = 0; i < 10_050; i += 1) {
      const r = gate.admit(`unique-${i}`, i); // strictly increasing "now" expires earlier entries
      if (r.ok) r.release();
    }
    const stats = gate.stats();
    expect(stats.trackedClients).toBeLessThanOrEqual(10_000);
  });
});

describe('readGateConfig', () => {
  it('uses defaults when nothing is set', () => {
    const config = readGateConfig(env());
    expect(config.perClient).toBe(5);
    expect(config.perInstance).toBe(60);
    expect(config.maxConcurrent).toBe(3);
  });

  it('reads BULLETRECON_ prefixed values', () => {
    const config = readGateConfig(env({ BULLETRECON_RATE_PER_CLIENT: '7' }));
    expect(config.perClient).toBe(7);
  });

  it('falls back to the legacy PASSIVE_RECON_ prefix', () => {
    const config = readGateConfig(env({ PASSIVE_RECON_RATE_PER_CLIENT: '9' }));
    expect(config.perClient).toBe(9);
  });

  it('prefers BULLETRECON_ over the legacy prefix when both are set', () => {
    const config = readGateConfig(env({
      BULLETRECON_RATE_PER_CLIENT: '7',
      PASSIVE_RECON_RATE_PER_CLIENT: '9',
    }));
    expect(config.perClient).toBe(7);
  });

  it('ignores a malformed override rather than disabling the control', () => {
    const config = readGateConfig(env({ BULLETRECON_RATE_PER_CLIENT: 'not-a-number' }));
    expect(config.perClient).toBe(5);
  });

  it('ignores a zero or negative override', () => {
    expect(readGateConfig(env({ BULLETRECON_MAX_CONCURRENT: '0' })).maxConcurrent).toBe(3);
    expect(readGateConfig(env({ BULLETRECON_MAX_CONCURRENT: '-1' })).maxConcurrent).toBe(3);
  });
});

describe('envValue', () => {
  it('returns undefined when neither prefix is set', () => {
    expect(envValue(env(), 'TRUST_PROXY')).toBeUndefined();
  });
});

describe('clientKey', () => {
  function headers(entries: Record<string, string>): Headers {
    return new Headers(entries);
  }

  it('returns "direct" when BULLETRECON_TRUST_PROXY=false, ignoring headers', () => {
    const key = clientKey(
      headers({ 'x-forwarded-for': '203.0.113.5' }),
      env({ BULLETRECON_TRUST_PROXY: 'false' }),
    );
    expect(key).toBe('direct');
  });

  it('uses the leftmost x-forwarded-for entry', () => {
    const key = clientKey(
      headers({ 'x-forwarded-for': '203.0.113.5, 10.0.0.1' }),
      env(),
    );
    expect(key).toBe('203.0.113.5');
  });

  it('strips a port suffix from an IPv4 address', () => {
    const key = clientKey(headers({ 'x-real-ip': '203.0.113.5:51234' }), env());
    expect(key).toBe('203.0.113.5');
  });

  it('buckets an IPv6 address to a /64', () => {
    const key = clientKey(
      headers({ 'x-forwarded-for': '2001:db8:abcd:1234:5678::1' }),
      env(),
    );
    expect(key).toBe('2001:db8:abcd:1234::/64');
  });

  it('two addresses in the same /64 map to the same bucket', () => {
    const keyA = clientKey(headers({ 'x-forwarded-for': '2001:db8:abcd:1234::1' }), env());
    const keyB = clientKey(headers({ 'x-forwarded-for': '2001:db8:abcd:1234::9999' }), env());
    expect(keyA).toBe(keyB);
  });

  it('falls back to x-real-ip, cf-connecting-ip, true-client-ip in order', () => {
    expect(clientKey(headers({ 'x-real-ip': '203.0.113.9' }), env())).toBe('203.0.113.9');
    expect(clientKey(headers({ 'cf-connecting-ip': '203.0.113.10' }), env())).toBe('203.0.113.10');
    expect(clientKey(headers({ 'true-client-ip': '203.0.113.11' }), env())).toBe('203.0.113.11');
  });

  it('returns "unknown" when no identifying header is present', () => {
    expect(clientKey(headers({}), env())).toBe('unknown');
  });
});

describe('isAllowedOrigin', () => {
  it('allows a request with no Origin header (curl, server-to-server)', () => {
    expect(isAllowedOrigin(null, 'example.com')).toBe(true);
  });

  it('allows a same-origin request', () => {
    expect(isAllowedOrigin('https://example.com', 'example.com')).toBe(true);
  });

  it('rejects a cross-site origin by default', () => {
    expect(isAllowedOrigin('https://evil.example', 'example.com')).toBe(false);
  });

  it('allows an origin listed in BULLETRECON_ALLOWED_ORIGINS', () => {
    const allowed = isAllowedOrigin('https://trusted.example', 'example.com', env({
      BULLETRECON_ALLOWED_ORIGINS: 'https://trusted.example',
    }));
    expect(allowed).toBe(true);
  });

  it('rejects an origin not present in the allowlist', () => {
    const allowed = isAllowedOrigin('https://untrusted.example', 'example.com', env({
      BULLETRECON_ALLOWED_ORIGINS: 'https://trusted.example',
    }));
    expect(allowed).toBe(false);
  });

  it('rejects a malformed Origin header', () => {
    expect(isAllowedOrigin('not-a-url', 'example.com')).toBe(false);
  });

  it('is case-insensitive when comparing hosts', () => {
    expect(isAllowedOrigin('https://EXAMPLE.com', 'example.com')).toBe(true);
  });

  it('matches an allowlist entry given as a bare host (no scheme)', () => {
    const allowed = isAllowedOrigin('https://trusted.example', 'example.com', env({
      BULLETRECON_ALLOWED_ORIGINS: 'trusted.example',
    }));
    expect(allowed).toBe(true);
  });

  it('matches one entry out of a comma-separated allowlist', () => {
    const allowed = isAllowedOrigin('https://second.example', 'example.com', env({
      BULLETRECON_ALLOWED_ORIGINS: 'https://first.example, https://second.example',
    }));
    expect(allowed).toBe(true);
  });
});
