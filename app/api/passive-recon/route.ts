/**
 * Unified passive reconnaissance endpoint.
 *
 * POST { domain: string } -> streaming NDJSON (one `ScanEvent` per line).
 *
 * Why a stream rather than a single JSON response: the dashboard has to show
 * per-module progress from one trigger. Buffering everything until the slowest
 * upstream settles would make the progress indicators cosmetic. Each module
 * therefore emits `module_start` / `module_done` | `module_error` as it lands.
 *
 * This file is the orchestrator only: gates, the event stream, and wiring
 * shared work (the homepage fetch, DNS records) between modules that consume
 * it. Each module's own fetch/parse logic lives under
 * `lib/passive-recon/modules/*.ts`, and the fetch plumbing they all share
 * (byte caps, the redirect-safe SSRF-checked fetch, timeout wiring) lives in
 * `lib/passive-recon/scan-fetch.ts`.
 *
 * ── Passivity contract ────────────────────────────────────────────────────────
 * There is no port scanning, no directory brute-forcing, no parameter fuzzing
 * and no shell execution anywhere in this route. Concretely, one scan means:
 *
 *   • Third-party OSINT indexes are queried for data they already hold.
 *   • DNS resolution — apex records, plus a capped sweep of discovered hosts.
 *     These are ordinary recursive lookups; nothing reaches the target's web
 *     servers, and the target's authoritative nameservers see the same queries
 *     any visitor's resolver generates.
 *   • The target itself receives ONE homepage GET, up to `LIMITS.scripts`
 *     same-origin `<script src>` files it advertises, and a fixed, short list
 *     of standardised public files (robots.txt, sitemap, security.txt, favicon,
 *     `/.well-known/*`, ads.txt, humans.txt). That is a browser's first visit —
 *     a bounded, published set, never a wordlist.
 *
 * Anything that would put unauthorised traffic on the target belongs in the
 * operator's own tooling, which is why the dashboard exports wordlists instead
 * of firing them.
 *
 * ── Abuse controls ────────────────────────────────────────────────────────────
 * Every request passes an origin check, a per-client window, a per-instance
 * window and a concurrency cap before any network work happens. See
 * `lib/passive-recon/rate-limit.ts` for why all four exist: hosted publicly,
 * this endpoint runs OSINT lookups and target fetches from the *server's* IP on
 * behalf of an anonymous caller, and an unmetered one is a free scanning proxy.
 */

import type { NextRequest } from 'next/server';

import { sanitizeDomain } from '@/lib/passive-recon/sanitize';
import {
  clientKey,
  isAllowedOrigin,
  scanGate,
} from '@/lib/passive-recon/rate-limit';
import { assertPublicHost } from '@/lib/passive-recon/net-guard';
import { collectDnsRecords, sweepHosts } from '@/lib/passive-recon/dns-records';
import { LIMITS, share, toMessage, unwrap } from '@/lib/passive-recon/scan-fetch';
import { fetchHomepage } from '@/lib/passive-recon/modules/homepage';
import { collectSubdomains } from '@/lib/passive-recon/modules/subdomains';
import { collectArchivedUrls } from '@/lib/passive-recon/modules/archived-urls';
import { fingerprintTech } from '@/lib/passive-recon/modules/tech';
import { collectJsEndpoints } from '@/lib/passive-recon/modules/js-endpoints';
import { collectMeta } from '@/lib/passive-recon/modules/meta';
import { collectMailSecurity } from '@/lib/passive-recon/modules/mail';
import { collectWhois } from '@/lib/passive-recon/modules/whois';
import { collectUrlIntel } from '@/lib/passive-recon/modules/url-intel';
import {
  MODULE_IDS,
  type ModuleDoneEvent,
  type ModuleId,
  type ModulePayloads,
  type ScanEvent,
  type TakeoverPayload,
} from '@/lib/passive-recon/types';

// `node:dns` in the SSRF guard requires the Node runtime, not Edge.
export const runtime = 'nodejs';
/**
 * 60s is the ceiling on Vercel's Hobby plan, and a value above a platform's cap
 * is a deploy-time error rather than a clamp. Self-hosting has no such cap:
 * raise this to 120 there if a slow OSINT index is getting cut off.
 */
export const maxDuration = 60;

function badRequest(error: string): Response {
  return Response.json({ error }, { status: 400 });
}

/**
 * One JSON line per lifecycle event, on stdout.
 *
 * A hosted deployment needs an answer to "who scanned what, when" — both to
 * respond if the IP gets reported for abuse, and to see which client is
 * burning the quota. Platform log collectors (Vercel, Docker, journald) all
 * ingest stdout, so this needs no dependency. Note that `client` is an IP or
 * an IPv6 /64, which is personal data in most jurisdictions: say so in your
 * privacy notice and set a retention period.
 */
function audit(event: string, fields: Record<string, unknown>): void {
  console.log(
    JSON.stringify({ at: new Date().toISOString(), event, ...fields }),
  );
}

/**
 * TypeScript cannot correlate a generic `K` with the distributed union member
 * it produces, so this one assertion is contained here rather than leaking an
 * `any` into every call site.
 */
function doneEvent<K extends ModuleId>(
  module: K,
  durationMs: number,
  data: ModulePayloads[K],
): ModuleDoneEvent {
  return { type: 'module_done', module, durationMs, data } as ModuleDoneEvent;
}

export async function POST(request: NextRequest): Promise<Response> {
  const client = clientKey(request.headers);

  // Gate 1: refuse cross-site browser requests. This does not stop curl — the
  // rate limiter below is what applies there — but it stops another site
  // driving scans from its visitors' browsers on this deployment's quota.
  if (!isAllowedOrigin(request.headers.get('origin'), request.headers.get('host'))) {
    audit('scan_rejected', { client, reason: 'cross_origin', status: 403 });
    return Response.json(
      {
        error:
          'Cross-site requests are not accepted. Use the dashboard on this origin, ' +
          'or set BULLETRECON_ALLOWED_ORIGINS if you front it with another host.',
      },
      { status: 403 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return badRequest('Request body must be valid JSON.');
  }

  // Gate 2: validate before metering, so a typo does not cost the caller a
  // slot in their window. Sanitising is pure string work and costs nothing.
  const raw = (body as { domain?: unknown } | null)?.domain;
  const sanitized = sanitizeDomain(raw);
  if (!sanitized.ok) return badRequest(sanitized.error);

  const { domain } = sanitized;

  // Gate 3: rate limit and concurrency. Everything past this point does real
  // network work, so this is the last point at which refusing is free.
  const decision = scanGate.admit(client);
  if (!decision.ok) {
    audit('scan_rejected', {
      client,
      domain,
      reason: decision.status === 503 ? 'concurrency' : 'rate_limit',
      status: decision.status,
    });
    return Response.json(
      { error: decision.error },
      {
        status: decision.status,
        headers: { 'Retry-After': String(decision.retryAfterSeconds) },
      },
    );
  }

  // From here on the slot is held and MUST be released on every exit path.
  const { release } = decision;

  // Gate 4: the target must currently resolve to a public address.
  let guard;
  try {
    guard = await assertPublicHost(domain);
  } catch (error) {
    release();
    audit('scan_rejected', { client, domain, reason: 'guard_error', status: 500 });
    return Response.json({ error: toMessage(error) }, { status: 500 });
  }

  if (!guard.ok) {
    release();
    audit('scan_rejected', { client, domain, reason: 'non_public_target', status: 400 });
    return badRequest(guard.error);
  }

  audit('scan_started', { client, domain, ...scanGate.stats() });

  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;

      const send = (event: ScanEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          // The client hung up mid-scan; stop trying to write.
          closed = true;
        }
      };

      const startedAt = Date.now();
      const signal = request.signal;
      let succeeded = 0;
      let failed = 0;

      try {
        send({
          type: 'scan_start',
          domain,
          startedAt: new Date(startedAt).toISOString(),
          modules: [...MODULE_IDS],
        });

        // Work that more than one module consumes is started once here and
        // shared. `share` folds rejection into the value so a failure surfaces
        // in every consumer instead of becoming an unhandled rejection.
        const homepage = fetchHomepage(domain, signal);
        const subdomains = share(collectSubdomains(domain, signal));
        const dns = share(collectDnsRecords(domain));
        const archived = share(collectArchivedUrls(domain, signal));
        const meta = share(collectMeta(domain, homepage, signal));
        const js = share(collectJsEndpoints(domain, homepage, signal));

        const run = async <K extends ModuleId>(
          module: K,
          task: () => Promise<ModulePayloads[K]>,
        ): Promise<void> => {
          const moduleStart = Date.now();
          send({ type: 'module_start', module });
          try {
            const data = await task();
            succeeded += 1;
            send(doneEvent(module, Date.now() - moduleStart, data));
          } catch (error) {
            failed += 1;
            send({
              type: 'module_error',
              module,
              durationMs: Date.now() - moduleStart,
              error: toMessage(error),
            });
          }
        };

        // allSettled is belt-and-braces: `run` already absorbs its own errors,
        // so this is purely the join barrier that lets every module finish.
        await Promise.allSettled([
          run('subdomains', () => unwrap(subdomains)),
          run('takeover', async (): Promise<TakeoverPayload> => {
            const discovered = await unwrap(subdomains);
            const hosts = [domain, ...discovered.subdomains.map((record) => record.host)];
            const unique = [...new Set(hosts)];

            const resolutions = await sweepHosts(unique, LIMITS.resolveHosts);

            return {
              total: unique.length,
              checked: resolutions.length,
              live: resolutions.filter((host) => host.status === 'live').length,
              hosts: resolutions,
            };
          }),
          run('dns', () => unwrap(dns)),
          run('mail', () => collectMailSecurity(domain, dns)),
          run('whois', () => collectWhois(domain, dns, signal)),
          run('tech', () => fingerprintTech(homepage)),
          run('js-endpoints', () => unwrap(js)),
          run('archived', () => unwrap(archived)),
          run('url-intel', () => collectUrlIntel(domain, archived, meta, js)),
          run('meta', () => unwrap(meta)),
        ]);

        send({
          type: 'scan_complete',
          finishedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        send({ type: 'scan_error', error: toMessage(error) });
      } finally {
        // Releasing here rather than in `cancel` alone is what guarantees the
        // slot comes back: a client disconnect aborts the module fetches, they
        // settle, and this runs. `release` is idempotent, so `cancel` firing
        // too is harmless.
        release();
        audit('scan_finished', {
          client,
          domain,
          durationMs: Date.now() - startedAt,
          modulesOk: succeeded,
          modulesFailed: failed,
          disconnected: closed,
        });

        if (!closed) {
          try {
            controller.close();
          } catch {
            // Already closed by a client disconnect.
          }
        }
      }
    },

    /** Fires when the consumer goes away before the stream finishes. */
    cancel() {
      release();
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      'X-Content-Type-Options': 'nosniff',
      // Stops reverse proxies (nginx) from buffering away the progressive flush.
      'X-Accel-Buffering': 'no',
    },
  });
}
