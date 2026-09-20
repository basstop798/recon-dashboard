/**
 * HTTP Basic authentication for the whole deployment.
 *
 * A hosted scan endpoint runs OSINT lookups and target fetches from the
 * server's IP on behalf of whoever calls it. The rate limiter caps how much
 * damage an anonymous caller can do; this decides whether there is an
 * anonymous caller at all.
 *
 * Opt-in by design: with `BULLETRECON_AUTH_USER` / `BULLETRECON_AUTH_PASSWORD`
 * unset — the normal local case — every request passes straight through and
 * `next dev` behaves exactly as before. Set both in the hosting platform's
 * environment and every route, including the API, requires credentials.
 *
 * This is the `proxy` file convention: `middleware` is deprecated in this
 * version of Next.js and was renamed. Proxy runs on the Node.js runtime, but
 * everything here is Web-standard so it survives being hoisted to an edge.
 */

import { NextResponse, type NextRequest } from 'next/server';

const REALM = 'BulletRecon';

function unauthorized(): NextResponse {
  return new NextResponse('Authentication required.', {
    status: 401,
    headers: {
      // Prompts the browser once, then it repeats the header on every request
      // to this origin — including the dashboard's own fetch to /api.
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Cache-Control': 'no-store',
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}

/** Base64 -> UTF-8. `atob` alone mangles any non-ASCII byte in a password. */
function decodeBase64(value: string): string | null {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Compares by digest so the comparison time does not depend on how many
 * leading characters a guess got right. A plain `===` on the secrets themselves
 * leaks their prefix to anyone patient enough to measure.
 */
async function secretEquals(supplied: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([sha256(supplied), sha256(expected)]);
  return a === b;
}

export async function proxy(request: NextRequest): Promise<NextResponse> {
  const user = process.env.BULLETRECON_AUTH_USER;
  const password = process.env.BULLETRECON_AUTH_PASSWORD;

  // Both must be present. A half-configured deployment failing open would be
  // the worst outcome, so treat "user set, password missing" as locked.
  if (!user && !password) return NextResponse.next();
  if (!user || !password) return unauthorized();

  const header = request.headers.get('authorization');
  if (!header?.startsWith('Basic ')) return unauthorized();

  const decoded = decodeBase64(header.slice('Basic '.length).trim());
  if (decoded === null) return unauthorized();

  // Split on the FIRST colon: passwords may legitimately contain more.
  const separator = decoded.indexOf(':');
  if (separator < 0) return unauthorized();

  const [suppliedUser, suppliedPassword] = [
    decoded.slice(0, separator),
    decoded.slice(separator + 1),
  ];

  // Both comparisons always run, so a wrong username costs the same as a wrong
  // password and neither can be distinguished by timing.
  const [userOk, passwordOk] = await Promise.all([
    secretEquals(suppliedUser, user),
    secretEquals(suppliedPassword, password),
  ]);

  return userOk && passwordOk ? NextResponse.next() : unauthorized();
}

export const config = {
  /*
   * Everything except Next's own immutable build assets. Those carry no target
   * data, and 401-ing them makes browsers re-prompt for every stylesheet.
   */
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
