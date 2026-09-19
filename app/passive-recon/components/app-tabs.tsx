'use client';

/**
 * Application-layer tabs: what the homepage response says about the stack, what
 * its JavaScript gives away, and which metadata files the site publishes.
 */

import { useMemo, useState } from 'react';

import type {
  JsEndpointsPayload,
  MetaPayload,
  ModuleState,
  TechPayload,
} from '@/lib/passive-recon/types';

import {
  CopyButton,
  EmptyState,
  ExternalLink,
  FilterInput,
  KeyValue,
  Panel,
  Pill,
  SeverityBadge,
  ShowMore,
  StatTile,
  UrlList,
  cx,
  useVisibleCount,
} from './ui';

const GRADE_TONE: Record<string, string> = {
  A: 'text-emerald-300',
  B: 'text-emerald-300',
  C: 'text-amber-300',
  D: 'text-orange-300',
  F: 'text-rose-300',
};

export function TechTab({ state, data }: { state: ModuleState; data: TechPayload | null }) {
  const [showRaw, setShowRaw] = useState(false);

  const byCategory = useMemo(() => {
    const groups = new Map<string, TechPayload['technologies']>();
    for (const technology of data?.technologies ?? []) {
      const entry = groups.get(technology.category);
      if (entry) entry.push(technology);
      else groups.set(technology.category, [technology]);
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [data]);

  if (!data) {
    return (
      <Panel title="Technology & headers">
        <EmptyState state={state} label="Technology fingerprint" />
      </Panel>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="HTTP status" value={data.status} hint={data.redirected ? 'redirected' : 'direct'} />
        <StatTile
          label="Header grade"
          value={<span className={GRADE_TONE[data.grade] ?? 'text-zinc-200'}>{data.grade}</span>}
          hint="security headers only"
        />
        <StatTile label="Technologies" value={data.technologies.length} tone="accent" />
        <StatTile label="Cookies set" value={data.cookies.length} hint="names and flags only" />
      </div>

      <Panel title="Page identity" subtitle={data.finalUrl}>
        <KeyValue
          rows={[
            { key: 'Title', value: data.identity.title ?? '—' },
            { key: 'Description', value: data.identity.description ?? '—' },
            { key: 'Generator', value: data.identity.generator ?? '—' },
            { key: 'Language', value: data.identity.lang ?? '—' },
            data.identity.ogImage
              ? { key: 'og:image', value: <ExternalLink href={data.identity.ogImage}>{data.identity.ogImage}</ExternalLink> }
              : null,
          ]}
        />
      </Panel>

      <Panel title="Detected technologies" subtitle="Hover any chip for the evidence that matched.">
        {byCategory.length === 0 ? (
          <p className="text-sm text-zinc-500">Nothing matched the fingerprint rules.</p>
        ) : (
          <div className="space-y-3">
            {byCategory.map(([category, items]) => (
              <div key={category} className="flex flex-wrap items-center gap-2">
                <span className="w-36 shrink-0 font-mono text-[11px] tracking-wider text-zinc-600 uppercase">
                  {category}
                </span>
                {items.map((technology) => (
                  <span
                    key={technology.name}
                    title={technology.evidence}
                    className={cx(
                      'rounded-lg border px-2.5 py-1 font-mono text-xs',
                      technology.confidence === 'high'
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                        : technology.confidence === 'medium'
                          ? 'border-cyan-500/25 bg-cyan-500/5 text-cyan-200'
                          : 'border-white/10 bg-white/5 text-zinc-400',
                    )}
                  >
                    {technology.name}
                  </span>
                ))}
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title="Security headers"
        subtitle="Read from the one homepage response — no extra requests were made."
      >
        <ul className="divide-y divide-white/5">
          {data.security.map((check) => (
            <li key={check.header} className="flex flex-wrap items-start gap-3 py-2.5">
              <span
                className={cx(
                  'mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold',
                  check.present
                    ? 'bg-emerald-500/15 text-emerald-300'
                    : 'bg-rose-500/15 text-rose-300',
                )}
              >
                {check.present ? '✓' : '✗'}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <code className="font-mono text-xs text-zinc-200">{check.header}</code>
                  {check.severity !== 'info' && <SeverityBadge severity={check.severity} />}
                </div>
                {check.value && (
                  <p className="mt-1 font-mono text-[11px] break-all text-zinc-500">{check.value}</p>
                )}
                <p className="mt-1 text-xs text-zinc-500">{check.advice}</p>
              </div>
            </li>
          ))}
        </ul>
      </Panel>

      {data.cookies.length > 0 && (
        <Panel title="Cookies" subtitle="Names and flags only — values are never captured or exported.">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="font-mono text-[11px] tracking-wider text-zinc-600 uppercase">
                  <th className="py-2 pr-4 font-medium">Name</th>
                  <th className="py-2 pr-4 font-medium">Secure</th>
                  <th className="py-2 pr-4 font-medium">HttpOnly</th>
                  <th className="py-2 font-medium">SameSite</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {data.cookies.map((cookie) => (
                  <tr key={cookie.name}>
                    <td className="py-2 pr-4 font-mono text-xs break-all text-zinc-200">
                      {cookie.name}
                    </td>
                    <td className={cx('py-2 pr-4 font-mono text-xs', cookie.secure ? 'text-emerald-300' : 'text-rose-300')}>
                      {cookie.secure ? 'yes' : 'no'}
                    </td>
                    <td className={cx('py-2 pr-4 font-mono text-xs', cookie.httpOnly ? 'text-emerald-300' : 'text-rose-300')}>
                      {cookie.httpOnly ? 'yes' : 'no'}
                    </td>
                    <td className="py-2 font-mono text-xs text-zinc-400">
                      {cookie.sameSite ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel
        title="Response headers"
        action={
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setShowRaw((current) => !current)}
              className="rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs text-zinc-300 hover:border-emerald-500/40 hover:text-emerald-300"
            >
              {showRaw ? 'hide' : `show all ${data.headers.length}`}
            </button>
            <CopyButton
              size="md"
              label="Copy"
              text={() => data.headers.map((header) => `${header.name}: ${header.value}`).join('\n')}
            />
          </div>
        }
      >
        {showRaw ? (
          <pre className="max-h-96 overflow-auto rounded-lg bg-black/40 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-zinc-300">
            {data.headers.map((header) => `${header.name}: ${header.value}`).join('\n')}
          </pre>
        ) : (
          <p className="text-sm text-zinc-500">
            {data.headers.length} headers captured. Set-Cookie is excluded by design.
          </p>
        )}
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function JsTab({
  state,
  data,
}: {
  state: ModuleState;
  data: JsEndpointsPayload | null;
}) {
  const [filter, setFilter] = useState('');
  const { visible, more } = useVisibleCount(200);

  const endpoints = useMemo(() => data?.endpoints ?? [], [data]);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return endpoints;
    return endpoints.filter((endpoint) => endpoint.toLowerCase().includes(needle));
  }, [endpoints, filter]);

  if (!data) {
    return (
      <Panel title="JS endpoints & secrets">
        <EmptyState state={state} label="Static JS parsing" />
      </Panel>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Bundles parsed"
          value={`${data.scanned}/${data.scripts.length}`}
          hint={`${data.inlineScripts} inline block(s) too`}
        />
        <StatTile label="Endpoint candidates" value={endpoints.length} tone="accent" />
        <StatTile
          label="Secret patterns"
          value={data.secrets.length}
          tone={data.secrets.length > 0 ? 'high' : 'default'}
        />
        <StatTile
          label="Source maps"
          value={data.sourceMaps.length}
          tone={data.sourceMaps.length > 0 ? 'medium' : 'default'}
        />
      </div>

      {data.secrets.length > 0 && (
        <Panel
          title="Credential patterns"
          subtitle="Matches are redacted here and in every export — confirm the live value at the source URL."
        >
          <ul className="divide-y divide-white/5">
            {data.secrets.map((secret, index) => (
              <li key={`${secret.rule}-${secret.match}-${index}`} className="py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={secret.severity} />
                  <span className="font-mono text-xs font-semibold text-zinc-100">
                    {secret.rule}
                  </span>
                  <code className="rounded bg-black/40 px-2 py-0.5 font-mono text-[11px] text-amber-200">
                    {secret.match}
                  </code>
                </div>
                <p className="mt-1 font-mono text-[11px] break-all text-zinc-500">
                  {secret.source}
                </p>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {data.sourceMaps.length > 0 && (
        <Panel
          title="Source maps"
          subtitle="These usually reconstruct the original, unminified source — including comments and internal paths."
          action={<CopyButton size="md" label="Copy" text={() => data.sourceMaps.join('\n')} />}
        >
          <UrlList urls={data.sourceMaps} visible={50} />
        </Panel>
      )}

      {data.hosts.length > 0 && (
        <Panel
          title={`${data.hosts.length} in-scope hosts named by the JavaScript`}
          subtitle="Bundles routinely reference hosts no certificate log or passive-DNS index has ever seen."
          action={<CopyButton size="md" label="Copy" text={() => data.hosts.join('\n')} />}
        >
          <div className="flex flex-wrap gap-1.5">
            {data.hosts.map((host) => (
              <Pill key={host} tone="accent">
                {host}
              </Pill>
            ))}
          </div>
        </Panel>
      )}

      <Panel
        title="Endpoint candidates"
        subtitle="Heuristic extraction from bundle strings — verify before acting on any of them."
        action={<CopyButton size="md" label="Copy all" text={() => endpoints.join('\n')} />}
      >
        {endpoints.length === 0 ? (
          <EmptyState state={state} label="Static JS parsing" />
        ) : (
          <>
            <div className="mb-3">
              <FilterInput value={filter} onChange={setFilter} placeholder="Filter endpoints…" />
            </div>
            <UrlList urls={filtered} visible={visible} linkify={false} />
            <ShowMore total={filtered.length} visible={visible} onMore={more} noun="endpoints" />
          </>
        )}
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function MetaTab({ state, data }: { state: ModuleState; data: MetaPayload | null }) {
  const { visible, more } = useVisibleCount(200);

  if (!data) {
    return (
      <Panel title="Recon extras">
        <EmptyState state={state} label="Recon extras" />
      </Panel>
    );
  }

  const { favicon, securityTxt, robots, sitemap, wellKnown } = data;
  const published = wellKnown.filter((file) => file.found);

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Favicon hash" subtitle="Shodan-compatible mmh3 hash for infrastructure pivoting.">
          {favicon.found && favicon.url ? (
            <div className="flex items-start gap-4">
              {/* eslint-disable-next-line @next/next/no-img-element -- next/image needs a remotePatterns entry per host, and the scanned host is arbitrary and only known at scan time. */}
              <img
                src={favicon.url}
                alt="Target favicon"
                width={40}
                height={40}
                className="h-10 w-10 shrink-0 rounded-lg border border-white/10 bg-black/30 object-contain p-1.5"
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <code className="rounded bg-black/40 px-2 py-1 font-mono text-xs text-emerald-300">
                    http.favicon.hash:{favicon.hash}
                  </code>
                  <CopyButton text={`http.favicon.hash:${favicon.hash}`} label="copy" />
                </div>
                <p className="mt-2 font-mono text-[11px] break-all text-zinc-500">
                  {favicon.url} · {favicon.bytes} bytes
                </p>
                <p className="mt-2 text-xs text-zinc-500">
                  Search this hash on Shodan or FOFA to find every other host serving the same
                  icon — which is how origin servers behind a CDN get found. Ready-made links are
                  in the Pivots tab.
                </p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-zinc-500">No favicon retrieved.</p>
          )}
        </Panel>

        <Panel title="security.txt" subtitle="RFC 9116 disclosure policy.">
          {securityTxt.found ? (
            <>
              <p className="mb-2 font-mono text-[11px] break-all text-zinc-500">{securityTxt.url}</p>
              <KeyValue
                rows={securityTxt.fields.map((field, index) => ({
                  key: `${field.name}${index > 0 && securityTxt.fields[index - 1].name === field.name ? ' (cont.)' : ''}`,
                  value: /^https?:\/\//.test(field.value) ? (
                    <ExternalLink href={field.value}>{field.value}</ExternalLink>
                  ) : (
                    field.value
                  ),
                }))}
              />
            </>
          ) : (
            <p className="text-sm text-zinc-500">
              Not published. Find the programme policy before reporting anything.
            </p>
          )}
        </Panel>
      </div>

      <Panel
        title="robots.txt — disallowed paths"
        subtitle="A curated list of what the operator would rather nobody visited."
        action={
          robots.disallowed.length > 0 && (
            <CopyButton size="md" label="Copy" text={() => robots.disallowed.join('\n')} />
          )
        }
      >
        {robots.found && robots.disallowed.length > 0 ? (
          <UrlList urls={robots.disallowed} visible={300} linkify={false} />
        ) : (
          <p className="text-sm text-zinc-500">
            {robots.found ? 'Published, but declares no disallowed paths.' : 'Not published.'}
          </p>
        )}
      </Panel>

      {published.length > 0 && (
        <Panel
          title="Well-known files"
          subtitle="Standardised public metadata — these name the app's platform integrations."
        >
          <ul className="space-y-3">
            {published.map((file) => (
              <li key={file.path} className="rounded-lg border border-white/5 bg-black/20 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <ExternalLink href={file.url}>
                    <code className="font-mono text-xs">{file.path}</code>
                  </ExternalLink>
                  <Pill>{file.contentType?.split(';')[0] ?? 'unknown'}</Pill>
                  <Pill>{file.bytes} bytes</Pill>
                </div>
                {file.preview && (
                  <pre className="mt-2 max-h-40 overflow-auto font-mono text-[11px] whitespace-pre-wrap text-zinc-400">
                    {file.preview}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel
        title={`Sitemap URLs (${sitemap.urls.length})`}
        subtitle={`From ${sitemap.documents.length} document(s).`}
        action={
          sitemap.urls.length > 0 && (
            <CopyButton size="md" label="Copy all" text={() => sitemap.urls.join('\n')} />
          )
        }
      >
        {sitemap.found && sitemap.urls.length > 0 ? (
          <>
            <UrlList urls={sitemap.urls} visible={visible} />
            <ShowMore total={sitemap.urls.length} visible={visible} onMore={more} noun="URLs" />
          </>
        ) : (
          <p className="text-sm text-zinc-500">No sitemap URLs found.</p>
        )}
      </Panel>
    </div>
  );
}
