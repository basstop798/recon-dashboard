/**
 * Module 8 — URL intelligence (derived from every URL the scan produced).
 */

import { analyzeUrls } from '../url-intel';
import type { Settled } from '../scan-fetch';
import type { ArchivedPayload, JsEndpointsPayload, MetaPayload, UrlIntelPayload } from '../types';

export async function collectUrlIntel(
  domain: string,
  archived: Promise<Settled<ArchivedPayload>>,
  meta: Promise<Settled<MetaPayload>>,
  js: Promise<Settled<JsEndpointsPayload>>,
): Promise<UrlIntelPayload> {
  const [archivedResult, metaResult, jsResult] = await Promise.all([archived, meta, js]);

  const urls: string[] = [];
  const failures: string[] = [];

  if (archivedResult.ok) urls.push(...archivedResult.value.urls);
  else failures.push(`archives (${archivedResult.error})`);
  if (!metaResult.ok) failures.push(`sitemap (${metaResult.error})`);
  if (!jsResult.ok) failures.push(`JavaScript (${jsResult.error})`);

  if (metaResult.ok) {
    urls.push(...metaResult.value.sitemap.urls);
    // robots.txt disallow entries are paths, not URLs; resolving them makes
    // them analysable alongside everything else without losing the origin.
    for (const path of metaResult.value.robots.disallowed) {
      try {
        urls.push(new URL(path, `https://${domain}/`).toString());
      } catch {
        continue;
      }
    }
  }

  if (jsResult.ok) {
    for (const endpoint of jsResult.value.endpoints) {
      try {
        urls.push(new URL(endpoint, `https://${domain}/`).toString());
      } catch {
        continue;
      }
    }
  }

  // An empty result is a legitimate answer — a young domain with no archive
  // history really has no URLs. It is only a module failure when the upstreams
  // that would have supplied them broke, which is worth saying out loud.
  if (urls.length === 0 && failures.length > 0) {
    throw new Error(`No URLs to analyse: ${failures.join('; ')}`);
  }

  return analyzeUrls(urls, domain);
}
