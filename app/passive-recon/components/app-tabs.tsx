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

import { CheckIcon, XIcon } from './icons';
import {
  BUTTON_SECONDARY,
  CheckMark,
  CopyButton,
  DataTable,
  EmptyState,
  ExternalLink,
  FilterInput,
  INSET,
  KeyValue,
  LABEL,
  MONO,
  Panel,
  Pill,
  SeverityBadge,
  ShowMore,
  StatTile,
  Td,
  Tr,
  UrlList,
  cx,
  useVisibleCount,
} from './ui';

const GRADE_TONE: Record<string, string> = {
  A: 'text-emerald-400',
  B: 'text-emerald-400',
  C: 'text-amber-400',
  D: 'text-orange-400',
  F: 'text-rose-400',
};

const CONFIDENCE_TONE = {
  high: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20',
  medium: 'bg-sky-500/10 text-sky-300 ring-sky-500/20',
  low: 'bg-white/5 text-zinc-400 ring-white/10',
} as const;

/** Yes/no for a cookie flag, where "yes" is the safe answer. */
function Flag({ on }: { on: boolean }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 font-medium',
        on ? 'text-emerald-400' : 'text-rose-400',
      )}
    >
      {on ? <CheckIcon className="size-3.5" /> : <XIcon className="size-3.5" />}
      {on ? 'Yes' : 'No'}
    </span>
  );
}

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
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="HTTP status" value={data.status} hint={data.redirected ? 'redirected' : 'direct'} />
        <StatTile
          label="Header grade"
          value={<span className={GRADE_TONE[data.grade] ?? 'text-zinc-50'}>{data.grade}</span>}
          hint="security headers only"
        />
        <StatTile label="Technologies" value={data.technologies.length} tone="accent" />
        <StatTile label="Cookies set" value={data.cookies.length} hint="names and flags only" />
      </div>

      <Panel
        title="Page identity"
        subtitle={<span className="font-mono text-[13px] break-all">{data.finalUrl}</span>}
      >
        <KeyValue
          rows={[
            { key: 'Title', value: data.identity.title ?? '—' },
            { key: 'Description', value: data.identity.description ?? '—' },
            { key: 'Generator', value: data.identity.generator ?? '—' },
            { key: 'Language', value: data.identity.lang ?? '—' },
            data.identity.ogImage
              ? {
                  key: 'og:image',
                  value: <ExternalLink href={data.identity.ogImage}>{data.identity.ogImage}</ExternalLink>,
                  mono: true,
                }
              : null,
          ]}
        />
      </Panel>

      <Panel title="Detected technologies" subtitle="Hover any chip for the evidence that matched.">
        {byCategory.length === 0 ? (
          <p className="text-sm text-zinc-400">Nothing matched the fingerprint rules.</p>
        ) : (
          <div className="divide-y divide-white/5">
            {byCategory.map(([category, items]) => (
              <div
                key={category}
                className="flex flex-col gap-2 py-3 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:gap-4"
              >
                <span className={cx(LABEL, 'w-40 shrink-0')}>{category}</span>
                <span className="flex flex-wrap gap-2">
                  {items.map((technology) => (
                    <span
                      key={technology.name}
                      title={technology.evidence}
                      className={cx(
                        'rounded-md px-2.5 py-1 text-xs font-medium ring-1 ring-inset',
                        CONFIDENCE_TONE[technology.confidence],
                      )}
                    >
                      {technology.name}
                    </span>
                  ))}
                </span>
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
            <li key={check.header} className="flex items-start gap-4 py-4 first:pt-0 last:pb-0">
              <CheckMark ok={check.present} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <code className={cx(MONO, 'font-medium text-zinc-100')}>{check.header}</code>
                  {check.severity !== 'info' && <SeverityBadge severity={check.severity} />}
                </div>
                {check.value && (
                  <p className="mt-1.5 font-mono text-xs break-all text-zinc-500">{check.value}</p>
                )}
                <p className="mt-1.5 text-sm leading-relaxed text-zinc-400">{check.advice}</p>
              </div>
            </li>
          ))}
        </ul>
      </Panel>

      {data.cookies.length > 0 && (
        <Panel title="Cookies" subtitle="Names and flags only — values are never captured or exported.">
          <DataTable columns={['Name', 'Secure', 'HttpOnly', 'SameSite']}>
            {data.cookies.map((cookie) => (
              <Tr key={cookie.name}>
                <Td mono className="break-all text-zinc-100">
                  {cookie.name}
                </Td>
                <Td>
                  <Flag on={cookie.secure} />
                </Td>
                <Td>
                  <Flag on={cookie.httpOnly} />
                </Td>
                <Td className="text-zinc-300">{cookie.sameSite ?? '—'}</Td>
              </Tr>
            ))}
          </DataTable>
        </Panel>
      )}

      <Panel
        title="Response headers"
        action={
          <>
            <button
              type="button"
              onClick={() => setShowRaw((current) => !current)}
              className={BUTTON_SECONDARY}
            >
              {showRaw ? 'Hide' : `Show all ${data.headers.length}`}
            </button>
            <CopyButton
              size="md"
              label="Copy"
              text={() => data.headers.map((header) => `${header.name}: ${header.value}`).join('\n')}
            />
          </>
        }
      >
        {showRaw ? (
          <pre className="max-h-96 overflow-auto rounded-lg bg-zinc-950 p-4 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-zinc-300 ring-1 ring-white/5 ring-inset">
            {data.headers.map((header) => `${header.name}: ${header.value}`).join('\n')}
          </pre>
        ) : (
          <p className="text-sm text-zinc-400">
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
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
              <li key={`${secret.rule}-${secret.match}-${index}`} className="py-4 first:pt-0 last:pb-0">
                <div className="flex flex-wrap items-center gap-2.5">
                  <SeverityBadge severity={secret.severity} />
                  <span className="text-sm font-semibold text-zinc-100">{secret.rule}</span>
                  <code className="rounded-md bg-zinc-950 px-2 py-0.5 font-mono text-xs text-amber-300 ring-1 ring-white/5 ring-inset">
                    {secret.match}
                  </code>
                </div>
                <p className="mt-2 font-mono text-xs break-all text-zinc-500">{secret.source}</p>
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
          <div className="flex flex-wrap gap-2">
            {data.hosts.map((host) => (
              <Pill key={host} tone="accent" mono>
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
            <div className="mb-4">
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
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Favicon hash" subtitle="Shodan-compatible mmh3 hash for infrastructure pivoting.">
          {favicon.found && favicon.url ? (
            <div className="flex items-start gap-4">
              {/* The server inlines the icon it already fetched, so this never
                  reaches out to the target from the operator's browser. When it
                  is too large to inline, no image is shown — the hash below is
                  the part that matters, and a live fetch would leak the
                  analyst's IP to the host under research. */}
              {favicon.dataUri && (
                /* eslint-disable-next-line @next/next/no-img-element -- a data: URI has no host for next/image to optimise. */
                <img
                  src={favicon.dataUri}
                  alt="Target favicon"
                  width={48}
                  height={48}
                  className="size-12 shrink-0 rounded-lg bg-zinc-950 object-contain p-2 ring-1 ring-white/10 ring-inset"
                />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <code className="rounded-md bg-zinc-950 px-2.5 py-1 font-mono text-[13px] text-emerald-300 ring-1 ring-white/5 ring-inset">
                    http.favicon.hash:{favicon.hash}
                  </code>
                  <CopyButton text={`http.favicon.hash:${favicon.hash}`} />
                </div>
                <p className="mt-2.5 font-mono text-xs break-all text-zinc-500">
                  {favicon.url} · {favicon.bytes} bytes
                </p>
                <p className="mt-3 text-sm leading-relaxed text-zinc-400">
                  Search this hash on Shodan or FOFA to find every other host serving the same
                  icon — which is how origin servers behind a CDN get found. Ready-made links are
                  in the Pivots tab.
                </p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-zinc-400">No favicon retrieved.</p>
          )}
        </Panel>

        <Panel title="security.txt" subtitle="RFC 9116 disclosure policy.">
          {securityTxt.found ? (
            <>
              <p className="mb-4 font-mono text-xs break-all text-zinc-500">{securityTxt.url}</p>
              <KeyValue
                rows={securityTxt.fields.map((field, index) => ({
                  key: `${field.name}${index > 0 && securityTxt.fields[index - 1].name === field.name ? ' (cont.)' : ''}`,
                  value: /^https?:\/\//.test(field.value) ? (
                    <ExternalLink href={field.value}>{field.value}</ExternalLink>
                  ) : (
                    field.value
                  ),
                  mono: true,
                }))}
              />
            </>
          ) : (
            <p className="text-sm text-zinc-400">
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
          <p className="text-sm text-zinc-400">
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
              <li key={file.path} className={cx(INSET, 'p-4')}>
                <div className="flex flex-wrap items-center gap-2">
                  <ExternalLink href={file.url}>
                    <code className={MONO}>{file.path}</code>
                  </ExternalLink>
                  <Pill mono>{file.contentType?.split(';')[0] ?? 'unknown'}</Pill>
                  {file.bytes !== null && (
                    <Pill>
                      <span className="tabular-nums">{file.bytes.toLocaleString()}</span> bytes
                    </Pill>
                  )}
                </div>
                {file.preview && (
                  <pre className="mt-3 max-h-40 overflow-auto rounded-md bg-zinc-950 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap text-zinc-400 ring-1 ring-white/5 ring-inset">
                    {file.preview}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel
        title={`Sitemap URLs (${sitemap.urls.length.toLocaleString()})`}
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
          <p className="text-sm text-zinc-400">No sitemap URLs found.</p>
        )}
      </Panel>
    </div>
  );
}
