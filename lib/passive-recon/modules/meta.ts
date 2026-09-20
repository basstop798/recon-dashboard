/**
 * Module 5 — recon extras (robots, sitemap, security.txt, favicon, well-known).
 */

import {
  parseRobotsTxt,
  parseSecurityTxt,
  parseSitemapLocs,
  resolveFaviconUrl,
  shodanFaviconHash,
} from '../recon-extras';
import { assertPublicHost } from '../net-guard';
import { fetchBytes, fetchText, LIMITS, TIMEOUTS } from '../scan-fetch';
import type {
  FaviconPayload,
  MetaPayload,
  RobotsPayload,
  SitemapPayload,
  SecurityTxtPayload,
  WellKnownFile,
} from '../types';
import type { HomepageResult } from './homepage';

/**
 * Standardised, publicly advertised files. Fixed list, never generated — this
 * is metadata discovery, not content brute-forcing (see route.ts's contract).
 */
const WELL_KNOWN_PATHS = [
  '/.well-known/openid-configuration',
  '/.well-known/assetlinks.json',
  '/.well-known/apple-app-site-association',
  '/.well-known/change-password',
  '/.well-known/nodeinfo',
  '/ads.txt',
  '/humans.txt',
  '/crossdomain.xml',
] as const;

async function fetchRobotsTxt(
  domain: string,
  parentSignal: AbortSignal,
): Promise<RobotsPayload> {
  const url = `https://${domain}/robots.txt`;
  const missing: RobotsPayload = { found: false, url, disallowed: [], sitemaps: [] };

  try {
    const { response, text } = await fetchText(url, {
      parentSignal,
      timeoutMs: TIMEOUTS.meta,
      maxBytes: LIMITS.robotsBytes,
      accept: 'text/plain,*/*;q=0.8',
    });

    // Not publishing robots.txt is normal, so a 404 is a result, not a failure.
    if (!response.ok) return missing;

    return { found: true, url, ...parseRobotsTxt(text) };
  } catch {
    return missing;
  }
}

/**
 * Keeps only sitemap URLs that stay on the target site.
 *
 * robots.txt is target-controlled content: a hostile host could declare
 * `Sitemap: http://169.254.169.254/...` and turn this module into an SSRF
 * primitive. Restricting to the target's own site mirrors the same-origin rule
 * `js-parser.ts` already applies to script references — and a sitemap hosted
 * somewhere else is not the target's sitemap anyway.
 */
function sameSiteSitemaps(declared: string[], domain: string): string[] {
  const out: string[] = [];

  for (const raw of declared) {
    try {
      const parsed = new URL(raw);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      if (parsed.hostname !== domain && !parsed.hostname.endsWith(`.${domain}`)) {
        continue;
      }
      out.push(parsed.toString());
    } catch {
      continue;
    }
  }

  return out;
}

async function fetchSitemap(
  domain: string,
  declared: string[],
  parentSignal: AbortSignal,
): Promise<SitemapPayload> {
  const candidates = [
    ...new Set([...declared, `https://${domain}/sitemap.xml`]),
  ].slice(0, LIMITS.sitemapDocs);

  const settled = await Promise.allSettled(
    candidates.map(async (url) => {
      const { response, text } = await fetchText(url, {
        parentSignal,
        timeoutMs: TIMEOUTS.meta,
        maxBytes: LIMITS.sitemapBytes,
        accept: 'application/xml,text/xml,*/*;q=0.8',
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return { url, locs: parseSitemapLocs(text) };
    }),
  );

  const documents: string[] = [];
  const urls = new Set<string>();

  for (const outcome of settled) {
    if (outcome.status !== 'fulfilled') continue;
    documents.push(outcome.value.url);
    for (const loc of outcome.value.locs) urls.add(loc);
  }

  const all = [...urls].sort();

  return {
    found: documents.length > 0,
    documents,
    urls: all.slice(0, LIMITS.sitemapUrls),
    truncated: all.length > LIMITS.sitemapUrls,
  };
}

async function fetchSecurityTxt(
  domain: string,
  parentSignal: AbortSignal,
): Promise<SecurityTxtPayload> {
  // RFC 9116 makes /.well-known/ authoritative; the bare path is a legacy
  // location still seen in the wild.
  const candidates = [
    `https://${domain}/.well-known/security.txt`,
    `https://${domain}/security.txt`,
  ];

  for (const url of candidates) {
    try {
      const { response, text } = await fetchText(url, {
        parentSignal,
        timeoutMs: TIMEOUTS.meta,
        maxBytes: LIMITS.securityTxtBytes,
        accept: 'text/plain,*/*;q=0.8',
      });

      if (!response.ok) continue;

      const fields = parseSecurityTxt(text);
      // A soft-404 HTML page yields no parsable fields; treat that as absent.
      if (fields.length === 0) continue;

      return { found: true, url, fields };
    } catch {
      continue;
    }
  }

  return { found: false, url: null, fields: [] };
}

/** Icons above this are shown from their URL instead of inlined. */
const MAX_INLINE_FAVICON_BYTES = 64_000;

/**
 * Inlines the icon the server already fetched.
 *
 * Without this the dashboard would render `<img src="https://target/...">` and
 * the analyst's own browser would connect to the host they are researching —
 * putting their residential IP in that host's access log, which is exactly what
 * a passive tool must not do. The bytes are in hand anyway, since the Shodan
 * hash is computed from them.
 */
function toDataUri(bytes: Uint8Array, contentType: string | null): string | null {
  if (bytes.length === 0 || bytes.length > MAX_INLINE_FAVICON_BYTES) return null;

  // Target-controlled header: allow only image types, and never a `;` that
  // could close the media type and smuggle attributes into the URI.
  const declared = (contentType ?? '').split(';')[0].trim().toLowerCase();
  const mediaType = /^image\/[a-z0-9.+-]+$/.test(declared) ? declared : 'image/x-icon';

  return `data:${mediaType};base64,${Buffer.from(bytes).toString('base64')}`;
}

async function fetchFavicon(
  homepage: HomepageResult,
  parentSignal: AbortSignal,
): Promise<FaviconPayload> {
  const missing: FaviconPayload = {
    found: false,
    url: null,
    hash: null,
    bytes: null,
    dataUri: null,
  };

  if (!homepage.ok) return missing;

  const url = resolveFaviconUrl(homepage.html, homepage.finalUrl);
  if (!url) return missing;

  try {
    // The href comes from target-controlled markup and may name any host, so it
    // gets the same public-address check as the target. Refusing off-site icons
    // outright would be wrong — large sites legitimately serve favicons from a
    // CDN, and that icon is still the one Shodan indexed.
    const guard = await assertPublicHost(new URL(url).hostname);
    if (!guard.ok) return { ...missing, url };

    const { response, bytes } = await fetchBytes(url, {
      parentSignal,
      timeoutMs: TIMEOUTS.meta,
      maxBytes: LIMITS.faviconBytes,
      accept: 'image/*,*/*;q=0.8',
    });

    if (!response.ok || bytes.length === 0) return { ...missing, url };

    return {
      found: true,
      url,
      hash: shodanFaviconHash(bytes),
      bytes: bytes.length,
      dataUri: toDataUri(bytes, response.headers.get('content-type')),
    };
  } catch {
    return { ...missing, url };
  }
}

/**
 * Requests the fixed list of standardised public files.
 *
 * Each one is a published convention an ordinary client already asks for
 * (`assetlinks.json` by Android, `apple-app-site-association` by iOS, `ads.txt`
 * by every ad verifier). They are worth collecting because they name the app's
 * platform integrations — package IDs, OAuth endpoints, ad partners.
 */
async function fetchWellKnown(
  domain: string,
  parentSignal: AbortSignal,
): Promise<WellKnownFile[]> {
  const settled = await Promise.allSettled(
    WELL_KNOWN_PATHS.map(async (path): Promise<WellKnownFile> => {
      const url = `https://${domain}${path}`;
      const absent: WellKnownFile = {
        path,
        url,
        found: false,
        status: null,
        contentType: null,
        bytes: null,
        preview: null,
      };

      try {
        const { response, text } = await fetchText(url, {
          parentSignal,
          timeoutMs: TIMEOUTS.meta,
          maxBytes: LIMITS.wellKnownBytes,
        });

        if (!response.ok) return { ...absent, status: response.status };

        const contentType = response.headers.get('content-type');
        const trimmed = text.trim();

        // Many hosts answer every path with the SPA shell; a file that is just
        // the site's HTML is not the file we asked for.
        const isHtmlShell = /^<(?:!doctype|html)/i.test(trimmed);
        if (trimmed.length === 0 || isHtmlShell) {
          return { ...absent, status: response.status, contentType };
        }

        return {
          path,
          url,
          found: true,
          status: response.status,
          contentType,
          bytes: trimmed.length,
          preview: trimmed.slice(0, LIMITS.wellKnownPreview),
        };
      } catch {
        return absent;
      }
    }),
  );

  return settled
    .filter(
      (outcome): outcome is PromiseFulfilledResult<WellKnownFile> =>
        outcome.status === 'fulfilled',
    )
    .map((outcome) => outcome.value);
}

/**
 * Best-effort metadata sweep.
 *
 * Every sub-fetch absorbs its own failure into a `found: false` result, so this
 * never throws and the module always reports a partial. A target that publishes
 * no security.txt is a normal finding, not a broken scan.
 */
export async function collectMeta(
  domain: string,
  homepage: Promise<HomepageResult>,
  parentSignal: AbortSignal,
): Promise<MetaPayload> {
  // Reuses the one shared homepage request rather than fetching the page again.
  const page = await homepage;

  // robots.txt runs first because it declares the sitemaps the next step reads.
  const robots = await fetchRobotsTxt(domain, parentSignal);

  const [sitemap, securityTxt, favicon, wellKnown] = await Promise.all([
    fetchSitemap(domain, sameSiteSitemaps(robots.sitemaps, domain), parentSignal),
    fetchSecurityTxt(domain, parentSignal),
    fetchFavicon(page, parentSignal),
    fetchWellKnown(domain, parentSignal),
  ]);

  return { robots, sitemap, securityTxt, favicon, wellKnown };
}
