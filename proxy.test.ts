import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { NextRequest } from 'next/server';

import { proxy } from './proxy';

function requestWith(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('https://example.com/passive-recon', { headers });
}

function basicAuthHeader(user: string, password: string): string {
  return `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
}

describe('proxy (HTTP Basic auth)', () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    delete process.env.BULLETRECON_AUTH_USER;
    delete process.env.BULLETRECON_AUTH_PASSWORD;
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    vi.restoreAllMocks();
  });

  it('passes every request through when auth is unset (local dev)', async () => {
    const response = await proxy(requestWith());
    expect(response.status).not.toBe(401);
  });

  it('fails closed when only the username is set', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    const response = await proxy(requestWith());
    expect(response.status).toBe(401);
  });

  it('fails closed when only the password is set', async () => {
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(requestWith());
    expect(response.status).toBe(401);
  });

  it('rejects a request with no Authorization header once configured', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(requestWith());
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/Basic/);
  });

  it('rejects wrong credentials', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(
      requestWith({ authorization: basicAuthHeader('admin', 'wrong') }),
    );
    expect(response.status).toBe(401);
  });

  it('rejects a well-formed but non-Basic Authorization header', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(
      requestWith({ authorization: 'Bearer sometoken' }),
    );
    expect(response.status).toBe(401);
  });

  it('accepts correct credentials', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(
      requestWith({ authorization: basicAuthHeader('admin', 'secret') }),
    );
    expect(response.status).not.toBe(401);
  });

  it('accepts a password containing a colon (splits on the first colon only)', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'pass:with:colons';
    const response = await proxy(
      requestWith({ authorization: basicAuthHeader('admin', 'pass:with:colons') }),
    );
    expect(response.status).not.toBe(401);
  });

  it('rejects a garbled base64 payload', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(
      requestWith({ authorization: 'Basic %%%not-base64%%%' }),
    );
    expect(response.status).toBe(401);
  });

  it('rejects a decoded value with no colon separator', async () => {
    process.env.BULLETRECON_AUTH_USER = 'admin';
    process.env.BULLETRECON_AUTH_PASSWORD = 'secret';
    const response = await proxy(
      requestWith({ authorization: `Basic ${Buffer.from('nocolonhere').toString('base64')}` }),
    );
    expect(response.status).toBe(401);
  });
});
