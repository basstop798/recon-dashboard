import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

import { assertPublicHost, isBlockedIpv4, isBlockedIpv6 } from './net-guard';

describe('isBlockedIpv4', () => {
  it('blocks loopback', () => {
    expect(isBlockedIpv4('127.0.0.1')).toBe(true);
    expect(isBlockedIpv4('127.255.255.255')).toBe(true);
  });

  it('blocks RFC1918 private ranges', () => {
    expect(isBlockedIpv4('10.0.0.1')).toBe(true);
    expect(isBlockedIpv4('172.16.0.1')).toBe(true);
    expect(isBlockedIpv4('172.31.255.255')).toBe(true);
    expect(isBlockedIpv4('192.168.1.1')).toBe(true);
  });

  it('blocks link-local / cloud metadata', () => {
    expect(isBlockedIpv4('169.254.169.254')).toBe(true);
    expect(isBlockedIpv4('169.254.0.1')).toBe(true);
  });

  it('blocks CGNAT', () => {
    expect(isBlockedIpv4('100.64.0.1')).toBe(true);
  });

  it('blocks TEST-NET ranges and benchmarking', () => {
    expect(isBlockedIpv4('192.0.2.1')).toBe(true);
    expect(isBlockedIpv4('198.51.100.1')).toBe(true);
    expect(isBlockedIpv4('203.0.113.1')).toBe(true);
    expect(isBlockedIpv4('198.18.0.1')).toBe(true);
  });

  it('blocks multicast and reserved space', () => {
    expect(isBlockedIpv4('224.0.0.1')).toBe(true);
    expect(isBlockedIpv4('255.255.255.255')).toBe(true);
  });

  it('does not block ordinary public addresses', () => {
    expect(isBlockedIpv4('8.8.8.8')).toBe(false);
    expect(isBlockedIpv4('93.184.216.34')).toBe(false);
    expect(isBlockedIpv4('1.1.1.1')).toBe(false);
  });

  it('fails closed on an unparseable address', () => {
    expect(isBlockedIpv4('not-an-ip')).toBe(true);
    expect(isBlockedIpv4('999.999.999.999')).toBe(true);
    expect(isBlockedIpv4('1.2.3')).toBe(true);
  });

  it('respects exact subnet boundaries at the edges', () => {
    // 172.16.0.0/12 covers 172.16.0.0-172.31.255.255
    expect(isBlockedIpv4('172.15.255.255')).toBe(false);
    expect(isBlockedIpv4('172.32.0.0')).toBe(false);
  });
});

describe('isBlockedIpv6', () => {
  it('blocks loopback and unspecified', () => {
    expect(isBlockedIpv6('::1')).toBe(true);
    expect(isBlockedIpv6('::')).toBe(true);
  });

  it('blocks unique-local (fc00::/7)', () => {
    expect(isBlockedIpv6('fc00::1')).toBe(true);
    expect(isBlockedIpv6('fd12:3456::1')).toBe(true);
  });

  it('blocks link-local (fe80::/10)', () => {
    expect(isBlockedIpv6('fe80::1')).toBe(true);
  });

  it('blocks multicast (ff00::/8)', () => {
    expect(isBlockedIpv6('ff02::1')).toBe(true);
  });

  it('unwraps IPv4-mapped addresses and applies the v4 rules', () => {
    expect(isBlockedIpv6('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedIpv6('::ffff:169.254.169.254')).toBe(true);
    expect(isBlockedIpv6('::ffff:8.8.8.8')).toBe(false);
  });

  it('strips a zone index before evaluating', () => {
    expect(isBlockedIpv6('fe80::1%eth0')).toBe(true);
  });

  it('does not block an ordinary public IPv6 address', () => {
    expect(isBlockedIpv6('2606:4700:4700::1111')).toBe(false);
  });
});

describe('assertPublicHost', () => {
  const dnsMocks = vi.hoisted(() => ({ lookup: vi.fn() }));

  vi.mock('node:dns/promises', () => ({
    lookup: dnsMocks.lookup,
  }));

  beforeEach(() => {
    dnsMocks.lookup.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('accepts a host that resolves only to public addresses', async () => {
    dnsMocks.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    const result = await assertPublicHost('example.com');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.addresses).toEqual(['93.184.216.34']);
  });

  it('refuses a host that resolves to a loopback address', async () => {
    dnsMocks.lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const result = await assertPublicHost('evil.example');
    expect(result.ok).toBe(false);
  });

  it('refuses a host with mixed public + internal answers (fail closed)', async () => {
    dnsMocks.lookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '169.254.169.254', family: 4 },
    ]);
    const result = await assertPublicHost('rebinding.example');
    expect(result.ok).toBe(false);
  });

  it('refuses a host that fails to resolve', async () => {
    dnsMocks.lookup.mockRejectedValue(new Error('ENOTFOUND'));
    const result = await assertPublicHost('nonexistent.example');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/DNS resolution failed/i);
  });

  it('refuses a host that resolves to zero addresses', async () => {
    dnsMocks.lookup.mockResolvedValue([]);
    const result = await assertPublicHost('empty.example');
    expect(result.ok).toBe(false);
  });

  it('refuses an IPv6 loopback answer', async () => {
    dnsMocks.lookup.mockResolvedValue([{ address: '::1', family: 6 }]);
    const result = await assertPublicHost('v6loopback.example');
    expect(result.ok).toBe(false);
  });
});
