/**
 * Fetches the target homepage exactly once and shares the result between every
 * module that needs markup (tech fingerprinting, JS mining, favicon), so a
 * scan never hits the target twice for the same body.
 */

import { fetchText, LIMITS, TIMEOUTS, toMessage } from '../scan-fetch';

export type HomepageResult =
  | { ok: true; response: Response; html: string; finalUrl: string; redirected: boolean }
  | { ok: false; error: string };

/**
 * Resolves to a result object instead of rejecting: several modules await this
 * promise, and a rejected shared promise would surface as an unhandled
 * rejection for whichever consumer attached second.
 */
export async function fetchHomepage(
  domain: string,
  parentSignal: AbortSignal,
): Promise<HomepageResult> {
  try {
    const { response, text, finalUrl, redirected } = await fetchText(`https://${domain}/`, {
      parentSignal,
      timeoutMs: TIMEOUTS.target,
      maxBytes: LIMITS.htmlBytes,
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    });

    return {
      ok: true,
      response,
      html: text,
      // `redirect: 'manual'` leaves `response.url` empty, so the hop-walking
      // fetch reports where the body actually came from.
      finalUrl,
      redirected,
    };
  } catch (error) {
    return { ok: false, error: toMessage(error) };
  }
}
