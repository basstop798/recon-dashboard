/**
 * Module 4 — static JS mining (LinkFinder + SecretFinder logic).
 */

import {
  extractEndpoints,
  extractHosts,
  extractInlineScripts,
  extractScriptUrls,
} from '../js-parser';
import { extractSourceMaps, scanSecrets } from '../secrets';
import { fetchText, LIMITS, TIMEOUTS } from '../scan-fetch';
import type { JsEndpointsPayload, SecretMatch } from '../types';
import type { HomepageResult } from './homepage';

export async function collectJsEndpoints(
  domain: string,
  homepage: Promise<HomepageResult>,
  parentSignal: AbortSignal,
): Promise<JsEndpointsPayload> {
  const result = await homepage;
  if (!result.ok) throw new Error(result.error);

  const allScripts = extractScriptUrls(result.html, result.finalUrl);
  const scripts = allScripts.slice(0, LIMITS.scripts);

  const endpoints = new Set<string>();
  const hosts = new Set<string>();
  const sourceMaps = new Set<string>();
  const secrets: SecretMatch[] = [];

  // Inline blocks come free with the homepage we already hold, and are where
  // bootstrap configuration (and its API keys) usually lives.
  const inline = extractInlineScripts(result.html);
  for (const block of inline) {
    for (const endpoint of extractEndpoints(block, domain)) endpoints.add(endpoint);
    for (const host of extractHosts(block, domain)) hosts.add(host);
    secrets.push(...scanSecrets(block, `${result.finalUrl} (inline)`));
  }
  for (const host of extractHosts(result.html, domain)) hosts.add(host);

  const settled = await Promise.allSettled(
    scripts.map(async (scriptUrl) => {
      const { text } = await fetchText(scriptUrl, {
        parentSignal,
        timeoutMs: TIMEOUTS.script,
        maxBytes: LIMITS.scriptBytes,
        accept: 'application/javascript,text/javascript,*/*;q=0.8',
      });

      return {
        url: scriptUrl,
        endpoints: extractEndpoints(text, domain),
        hosts: extractHosts(text, domain),
        secrets: scanSecrets(text, scriptUrl),
        sourceMaps: extractSourceMaps(text, scriptUrl),
      };
    }),
  );

  let scanned = 0;

  for (const outcome of settled) {
    if (outcome.status !== 'fulfilled') continue;
    scanned += 1;

    for (const endpoint of outcome.value.endpoints) endpoints.add(endpoint);
    for (const host of outcome.value.hosts) hosts.add(host);
    for (const map of outcome.value.sourceMaps) sourceMaps.add(map);
    secrets.push(...outcome.value.secrets);
  }

  const all = [...endpoints].sort();

  return {
    scripts: allScripts,
    endpoints: all.slice(0, LIMITS.endpoints),
    scanned,
    inlineScripts: inline.length,
    truncated: all.length > LIMITS.endpoints || allScripts.length > scripts.length,
    secrets: secrets.slice(0, LIMITS.secrets),
    sourceMaps: [...sourceMaps].sort(),
    hosts: [...hosts].sort(),
  };
}
