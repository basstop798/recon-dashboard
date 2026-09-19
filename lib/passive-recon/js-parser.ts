/**
 * Static JavaScript parser utility.
 *
 * Two pure, side-effect-free passes:
 *   1. `extractScriptUrls` — pull `<script src>` references out of a document.
 *   2. `extractEndpoints`  — mine a JS bundle for API-looking paths and URLs.
 *
 * Both are regex-based on purpose. A real JS parse (acorn//babel) would be more
 * precise, but bundles are minified and frequently invalid as standalone
 * modules; for endpoint mining a tolerant scan beats a strict parse that throws.
 * Being pure also means both are unit-testable without any network.
 */

/** Asset types that are never an interesting "endpoint". */
const ASSET_EXT_RE =
  /\.(?:js|mjs|cjs|css|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|map|mp4|webm|mp3|wav|pdf|zip|gz)(?:$|[?#])/i;

/**
 * Tokens that promote a path to "probably an API surface". Paths without one of
 * these still qualify if they are structurally deep (see `isInterestingPath`).
 */
const API_HINTS = [
  'api',
  'graphql',
  'gql',
  'rest',
  'rpc',
  'v1',
  'v2',
  'v3',
  'auth',
  'oauth',
  'token',
  'session',
  'login',
  'logout',
  'signup',
  'register',
  'user',
  'account',
  'profile',
  'admin',
  'internal',
  'private',
  'upload',
  'download',
  'export',
  'import',
  'webhook',
  'callback',
  'search',
  'query',
  'config',
  'settings',
  'debug',
  'health',
  'status',
  'metrics',
];

/** `<script ... src="...">`, tolerant of attribute order and quote style. */
const SCRIPT_SRC_RE =
  /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))[^>]*>/gi;

/** Quoted absolute paths: "/foo/bar". */
const QUOTED_PATH_RE = /["'`](\/[A-Za-z0-9._~\-/]{1,180}(?:\?[A-Za-z0-9._~\-/=&%]{0,60})?)["'`]/g;

/** Quoted absolute URLs. */
const QUOTED_URL_RE = /["'`](https?:\/\/[A-Za-z0-9._~\-]+(?:\/[A-Za-z0-9._~\-/]{0,180})?)["'`]/g;

/**
 * Resolves every `<script src>` in `html` against `baseUrl`, keeping only
 * same-origin http(s) results.
 *
 * Same-origin filtering is both politeness (we do not pull third-party CDN
 * bundles) and safety: a `src` attribute is attacker-controlled content, so
 * following it off-origin would hand back the SSRF primitive that `net-guard`
 * exists to remove.
 */
export function extractScriptUrls(html: string, baseUrl: string): string[] {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const found = new Set<string>();

  for (const match of html.matchAll(SCRIPT_SRC_RE)) {
    const raw = (match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (!raw || raw.startsWith('data:')) continue;

    let resolved: URL;
    try {
      resolved = new URL(raw, baseUrl);
    } catch {
      continue;
    }

    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
    if (resolved.origin !== origin) continue;

    resolved.hash = '';
    found.add(resolved.toString());
  }

  return [...found];
}

function isInterestingPath(path: string): boolean {
  if (path.length < 4) return false;
  if (ASSET_EXT_RE.test(path)) return false;
  if (path.startsWith('//')) return false; // protocol-relative URL, not a path

  const lower = path.toLowerCase();

  if (API_HINTS.some((hint) => lower.includes(hint))) return true;

  // Fall back to structure: /a/b/c is far more likely to be a route than /a.
  const segments = path.split('/').filter(Boolean);
  return segments.length >= 3;
}

/**
 * Mines a JavaScript source string for endpoint candidates.
 *
 * This is a heuristic and will surface some false positives (i18n keys and
 * CSS selectors both look like paths). Results are labelled "candidates" in the
 * UI for exactly that reason — they are leads to verify, not confirmed routes.
 *
 * @param js        Raw JavaScript source.
 * @param sameHost  When given, absolute URLs are kept only for this host.
 */
export function extractEndpoints(js: string, sameHost?: string): string[] {
  const found = new Set<string>();

  for (const match of js.matchAll(QUOTED_PATH_RE)) {
    const path = match[1];
    if (isInterestingPath(path)) found.add(path);
  }

  for (const match of js.matchAll(QUOTED_URL_RE)) {
    const raw = match[1];

    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      continue;
    }

    if (ASSET_EXT_RE.test(parsed.pathname)) continue;

    // Keep third-party origins only when they expose a real path — a bare
    // "https://fonts.googleapis.com" is noise, but an API host with a route
    // is a genuine finding worth reporting.
    if (sameHost) {
      const onTarget =
        parsed.hostname === sameHost || parsed.hostname.endsWith(`.${sameHost}`);
      if (!onTarget && parsed.pathname.split('/').filter(Boolean).length < 2) {
        continue;
      }
    }

    found.add(raw);
  }

  return [...found];
}

/** `<script>` blocks with no `src` — inline config objects live here. */
const INLINE_SCRIPT_RE = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;

/**
 * Returns the body of every inline `<script>` in a document.
 *
 * Worth parsing separately from bundles: inline blocks are where a framework
 * dumps its bootstrap config, and that is routinely where an API key, an
 * internal hostname or a full user object ends up.
 */
export function extractInlineScripts(html: string): string[] {
  const blocks: string[] = [];

  for (const match of html.matchAll(INLINE_SCRIPT_RE)) {
    const body = match[1]?.trim();
    if (body && body.length > 0) blocks.push(body);
  }

  return blocks;
}

/** Hostname-shaped tokens, deliberately loose — the caller filters by scope. */
const HOSTNAME_RE = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}[a-z]{2,24})\b/gi;

/**
 * Mines text for hostnames inside the target's own domain.
 *
 * JavaScript bundles regularly name hosts that no certificate log and no
 * passive-DNS index has ever seen — internal APIs, regional endpoints, staging
 * environments — which makes this one of the better subdomain sources.
 */
export function extractHosts(text: string, domain: string): string[] {
  const suffix = `.${domain.toLowerCase()}`;
  const found = new Set<string>();

  for (const match of text.matchAll(HOSTNAME_RE)) {
    const host = match[1].toLowerCase();
    if (host === domain || host.endsWith(suffix)) found.add(host);
  }

  return [...found].sort();
}
