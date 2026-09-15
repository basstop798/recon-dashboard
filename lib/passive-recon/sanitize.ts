/**
 * Strict target sanitisation.
 *
 * This module is deliberately dependency-free and isomorphic so the browser can
 * pre-validate with the *exact* same rules the server enforces. The server still
 * re-validates — client checks are UX, never a control.
 *
 * Threat model: the sanitised value is interpolated into `https://${domain}` and
 * into upstream OSINT query strings. The realistic attacks are therefore
 *   1. SSRF   — pointing the fetch at loopback/RFC1918/cloud-metadata hosts, and
 *   2. URL smuggling — credentials (`@`), path/query breakouts (`/ ? #`), ports.
 * Command injection is not reachable here (no shell is ever spawned), but the
 * allowlist below blocks shell metacharacters anyway as defence in depth.
 */

const MAX_DOMAIN_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;

/** A single DNS label: alphanumeric edges, hyphens only in the interior. */
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Public-suffix shape: alpha TLD, or a punycode (IDN) TLD such as `xn--p1ai`. */
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * Reserved / internal-use suffixes (RFC 2606, RFC 6761, RFC 7686) plus the
 * conventional corporate ones. Resolving these can reach intranet hosts.
 */
const BLOCKED_TLDS = new Set([
  'local',
  'localhost',
  'localdomain',
  'internal',
  'intranet',
  'lan',
  'home',
  'corp',
  'private',
  'test',
  'example',
  'invalid',
  'onion',
  'i2p',
  'alt',
]);

export type SanitizeResult =
  | { ok: true; domain: string }
  | { ok: false; error: string };

/**
 * Normalises a user-supplied target and validates it as a public registrable
 * hostname. Accepts pasted URLs (`https://x.com/a?b`) by trimming to the host,
 * then validates the *result* strictly — so trimming can never widen the input.
 */
export function sanitizeDomain(input: unknown): SanitizeResult {
  if (typeof input !== 'string') {
    return { ok: false, error: 'Target must be a string.' };
  }

  let value = input.trim().toLowerCase();

  if (value.length === 0) {
    return { ok: false, error: 'Target is required.' };
  }

  // Tolerate a pasted URL: drop the scheme, then everything from the first
  // path/query/fragment delimiter. Anything still illegal is rejected below.
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  value = value.split(/[/?#\\]/, 1)[0];

  // Strip the DNS root dot ("example.com." is valid but normalises away).
  value = value.replace(/\.+$/, '');

  if (value.length === 0) {
    return { ok: false, error: 'Target is required.' };
  }

  // Credentials and explicit ports are never legitimate for a recon target and
  // are the classic way to smuggle a different host past a naive parser.
  if (value.includes('@')) {
    return { ok: false, error: 'Userinfo (@) is not allowed in a target.' };
  }
  if (value.includes(':')) {
    return { ok: false, error: 'Ports and IPv6 literals are not allowed.' };
  }

  if (value.length > MAX_DOMAIN_LENGTH) {
    return {
      ok: false,
      error: `Target exceeds the ${MAX_DOMAIN_LENGTH}-character DNS limit.`,
    };
  }

  // Positive allowlist. Anything outside [a-z0-9.-] — including whitespace,
  // shell metacharacters and raw unicode homoglyphs — is refused outright.
  if (!/^[a-z0-9.-]+$/.test(value)) {
    return {
      ok: false,
      error: 'Target may only contain letters, digits, dots and hyphens.',
    };
  }

  if (!value.includes('.')) {
    return { ok: false, error: 'Target must be a fully-qualified domain.' };
  }

  if (value.includes('..')) {
    return { ok: false, error: 'Target contains an empty DNS label.' };
  }

  const labels = value.split('.');

  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LENGTH) {
      return { ok: false, error: `Invalid DNS label length in "${value}".` };
    }
    if (!LABEL_RE.test(label)) {
      return {
        ok: false,
        error: `DNS label "${label}" must not start or end with a hyphen.`,
      };
    }
  }

  // Bare IP literals bypass the whole point of domain validation and are the
  // primary SSRF vector (169.254.169.254, 127.0.0.1, ...).
  if (IPV4_RE.test(value)) {
    return { ok: false, error: 'IP literals are not accepted — use a domain.' };
  }

  const tld = labels[labels.length - 1];

  if (!TLD_RE.test(tld)) {
    return { ok: false, error: `"${tld}" is not a valid top-level domain.` };
  }

  if (BLOCKED_TLDS.has(tld)) {
    return {
      ok: false,
      error: `".${tld}" is a reserved/internal suffix and cannot be scanned.`,
    };
  }

  return { ok: true, domain: value };
}
