'use client';

/**
 * Attack-surface tabs: what hosts exist, which of them are live or claimable,
 * and what the collected URLs say about where to look first.
 */

import { useMemo, useState } from 'react';

import { classLabel } from '@/lib/passive-recon/url-intel';
import type {
  ArchivedPayload,
  HostResolution,
  ModuleState,
  SubdomainsPayload,
  UrlIntelPayload,
} from '@/lib/passive-recon/types';

import {
  CopyButton,
  EmptyState,
  FilterInput,
  Panel,
  Pill,
  SeverityBadge,
  ShowMore,
  SourceStats,
  StatTile,
  UrlList,
  cx,
  useVisibleCount,
} from './ui';

/* -------------------------------------------------------------------------- */

export function SubdomainsTab({
  state,
  data,
}: {
  state: ModuleState;
  data: SubdomainsPayload | null;
}) {
  const [filter, setFilter] = useState('');
  const { visible, more } = useVisibleCount(150);

  const hosts = useMemo(() => data?.subdomains ?? [], [data]);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return hosts;
    return hosts.filter((record) => record.host.includes(needle));
  }, [hosts, filter]);

  if (hosts.length === 0) {
    return (
      <Panel title="Subdomains">
        <SourceStats sources={data?.sources ?? []} />
        <EmptyState state={state} label="Subdomain aggregation" />
      </Panel>
    );
  }

  return (
    <Panel
      title={`${hosts.length} host${hosts.length === 1 ? '' : 's'} discovered`}
      subtitle="Corroboration across independent indexes is shown per row."
      action={
        <CopyButton
          size="md"
          label="Copy all"
          text={() => hosts.map((record) => record.host).join('\n')}
        />
      }
    >
      <SourceStats sources={data?.sources ?? []} />

      <div className="mb-3">
        <FilterInput value={filter} onChange={setFilter} placeholder="Filter hosts…" />
      </div>

      <ul className="divide-y divide-white/5">
        {filtered.slice(0, visible).map((record) => (
          <li key={record.host} className="flex items-center justify-between gap-3 py-1.5">
            <a
              href={`https://${record.host}`}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="min-w-0 truncate font-mono text-sm text-emerald-300/90 hover:text-emerald-200 hover:underline"
            >
              {record.host}
            </a>
            <span className="shrink-0 font-mono text-[11px] text-zinc-600">
              {record.sources.join(' · ')}
            </span>
          </li>
        ))}
      </ul>

      <ShowMore total={filtered.length} visible={visible} onMore={more} noun="hosts" />
      {data?.truncated && (
        <p className="pt-2 text-center text-[11px] text-amber-300/70">
          Upstream cap reached — some hosts were not returned.
        </p>
      )}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */

const STATUS_TONE: Record<HostResolution['status'], string> = {
  live: 'text-emerald-300',
  dangling: 'text-rose-300',
  nxdomain: 'text-zinc-500',
  error: 'text-amber-300',
};

export function TakeoverTab({
  state,
  data,
}: {
  state: ModuleState;
  data: { total: number; checked: number; live: number; hosts: HostResolution[] } | null;
}) {
  const [onlyInteresting, setOnlyInteresting] = useState(true);
  const [filter, setFilter] = useState('');
  const { visible, more } = useVisibleCount(150);

  const hosts = useMemo(() => data?.hosts ?? [], [data]);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return hosts.filter((host) => {
      if (needle && !host.host.includes(needle)) return false;
      // "Interesting" is anything that is not a plain, healthy A record: a
      // takeover candidate, a broken delegation, or a third-party service.
      if (onlyInteresting && host.status === 'live' && !host.service) return false;
      return true;
    });
  }, [hosts, filter, onlyInteresting]);

  if (hosts.length === 0) {
    return (
      <Panel title="Host resolution">
        <EmptyState state={state} label="Host resolution sweep" />
      </Panel>
    );
  }

  const dangling = hosts.filter((host) => host.status === 'dangling');
  const candidates = dangling.filter((host) => host.takeover);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Resolved" value={data?.checked ?? 0} hint={`of ${data?.total ?? 0} known`} />
        <StatTile label="Live" value={data?.live ?? 0} tone="accent" hint="answer with an address" />
        <StatTile
          label="Dangling"
          value={dangling.length}
          tone={dangling.length > 0 ? 'medium' : 'default'}
          hint="CNAME with no resolution"
        />
        <StatTile
          label="Takeover leads"
          value={candidates.length}
          tone={candidates.length > 0 ? 'high' : 'default'}
          hint="dangling at a known provider"
        />
      </div>

      <Panel
        title="Resolution detail"
        subtitle="Ordinary recursive lookups — nothing is sent to the target's web servers."
        action={
          <label className="flex cursor-pointer items-center gap-2 font-mono text-[11px] text-zinc-400">
            <input
              type="checkbox"
              checked={onlyInteresting}
              onChange={(event) => setOnlyInteresting(event.target.checked)}
              className="accent-emerald-500"
            />
            interesting only
          </label>
        }
      >
        <div className="mb-3">
          <FilterInput value={filter} onChange={setFilter} placeholder="Filter hosts…" />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="font-mono text-[11px] tracking-wider text-zinc-600 uppercase">
                <th className="py-2 pr-4 font-medium">Host</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Points at</th>
                <th className="py-2 font-medium">Note</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filtered.slice(0, visible).map((host) => (
                <tr key={host.host} className="align-top">
                  <td className="py-2 pr-4 font-mono text-xs break-all text-zinc-200">
                    {host.host}
                    {host.takeover && (
                      <span className="ml-2 inline-block align-middle">
                        <SeverityBadge severity={host.severity} />
                      </span>
                    )}
                  </td>
                  <td className={cx('py-2 pr-4 font-mono text-xs', STATUS_TONE[host.status])}>
                    {host.status}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs break-all text-zinc-400">
                    {host.cname ?? (host.addresses.slice(0, 2).join(', ') || '—')}
                    {host.service && (
                      <span className="mt-1 block">
                        <Pill tone="accent">{host.service}</Pill>
                      </span>
                    )}
                  </td>
                  <td className="py-2 text-xs text-zinc-500">{host.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <ShowMore total={filtered.length} visible={visible} onMore={more} noun="hosts" />
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function UrlIntelTab({
  state,
  data,
}: {
  state: ModuleState;
  data: UrlIntelPayload | null;
}) {
  const [bucketId, setBucketId] = useState<string | null>(null);
  const { visible, more } = useVisibleCount(100);

  if (!data) {
    return (
      <Panel title="URL intelligence">
        <EmptyState state={state} label="URL intelligence" />
      </Panel>
    );
  }

  const active = data.buckets.find((bucket) => bucket.id === (bucketId ?? data.buckets[0]?.id));

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="URLs analysed" value={data.analyzed.toLocaleString()} />
        <StatTile label="Parameters" value={data.parameters.length} tone="accent" />
        <StatTile
          label="Sensitive files"
          value={data.juicyFiles.length}
          tone={data.juicyFiles.length > 0 ? 'high' : 'default'}
        />
        <StatTile label="Cloud assets" value={data.cloudAssets.length} />
      </div>

      {data.buckets.length > 0 && (
        <Panel
          title="Pattern buckets"
          subtitle="gf-style classification. Every entry is a lead to verify, not a confirmed bug."
          action={
            active && (
              <CopyButton size="md" label="Copy bucket" text={() => active.urls.join('\n')} />
            )
          }
        >
          <div className="mb-4 flex flex-wrap gap-2">
            {data.buckets.map((bucket) => (
              <button
                key={bucket.id}
                type="button"
                onClick={() => setBucketId(bucket.id)}
                className={cx(
                  'rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors',
                  active?.id === bucket.id
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300'
                    : 'border-white/10 bg-white/5 text-zinc-400 hover:text-zinc-200',
                )}
              >
                {bucket.label}
                <span className="ml-2 text-zinc-600">{bucket.total}</span>
              </button>
            ))}
          </div>

          {active && (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={active.severity} />
                <p className="text-xs text-zinc-500">{active.description}</p>
              </div>
              <UrlList urls={active.urls} visible={visible} />
              <ShowMore total={active.urls.length} visible={visible} onMore={more} noun="URLs" />
            </>
          )}
        </Panel>
      )}

      <Panel
        title="Parameters"
        subtitle="Names seen in collected URLs, classified by the bug class they historically precede."
        action={
          <CopyButton
            size="md"
            label="Copy wordlist"
            text={() => data.parameters.map((parameter) => parameter.name).join('\n')}
          />
        }
      >
        {data.parameters.length === 0 ? (
          <p className="text-sm text-zinc-500">No parameters were seen in the collected URLs.</p>
        ) : (
          <div className="max-h-[28rem] overflow-y-auto">
            <table className="w-full text-left">
              <thead className="sticky top-0 bg-zinc-900/90 backdrop-blur">
                <tr className="font-mono text-[11px] tracking-wider text-zinc-600 uppercase">
                  <th className="py-2 pr-4 font-medium">Parameter</th>
                  <th className="py-2 pr-4 font-medium">Seen</th>
                  <th className="py-2 font-medium">Associated with</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {data.parameters.map((parameter) => (
                  <tr key={parameter.name}>
                    <td className="py-1.5 pr-4 font-mono text-xs break-all text-zinc-200">
                      {parameter.name}
                    </td>
                    <td className="py-1.5 pr-4 font-mono text-xs text-zinc-500">
                      {parameter.count}
                    </td>
                    <td className="py-1.5">
                      <span className="flex flex-wrap gap-1">
                        {parameter.classes.map((id) => (
                          <Pill key={id} tone="accent">
                            {classLabel(id)}
                          </Pill>
                        ))}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Cloud assets" subtitle="Storage and hosting identifiers referenced by the estate.">
          {data.cloudAssets.length === 0 ? (
            <p className="text-sm text-zinc-500">None referenced.</p>
          ) : (
            <ul className="divide-y divide-white/5">
              {data.cloudAssets.map((asset) => (
                <li key={`${asset.provider}-${asset.asset}`} className="flex items-center gap-2 py-1.5">
                  <Pill tone="accent">{asset.provider}</Pill>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-300">
                    {asset.asset}
                  </span>
                  <CopyButton text={asset.asset} label="copy" />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Third-party hosts" subtitle="Vendors and CDNs the estate depends on.">
          {data.thirdPartyHosts.length === 0 ? (
            <p className="text-sm text-zinc-500">None seen.</p>
          ) : (
            <ul className="max-h-80 divide-y divide-white/5 overflow-y-auto">
              {data.thirdPartyHosts.slice(0, 100).map((host) => (
                <li key={host.host} className="flex items-center justify-between gap-3 py-1.5">
                  <span className="min-w-0 truncate font-mono text-xs text-zinc-300">
                    {host.host}
                  </span>
                  <span className="font-mono text-[11px] text-zinc-600">×{host.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {data.juicyFiles.length > 0 && (
        <Panel
          title="Sensitive file references"
          subtitle="Config, backup, key and VCS paths recorded by crawlers. Confirm which still resolve."
          action={<CopyButton size="md" label="Copy all" text={() => data.juicyFiles.join('\n')} />}
        >
          <UrlList urls={data.juicyFiles} visible={200} />
        </Panel>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function ArchivedTab({
  state,
  data,
}: {
  state: ModuleState;
  data: ArchivedPayload | null;
}) {
  const [filter, setFilter] = useState('');
  const { visible, more } = useVisibleCount(200);

  const urls = useMemo(() => data?.urls ?? [], [data]);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return urls;
    return urls.filter((url) => url.toLowerCase().includes(needle));
  }, [urls, filter]);

  if (urls.length === 0) {
    return (
      <Panel title="Archived URLs">
        <SourceStats sources={data?.sources ?? []} />
        <EmptyState state={state} label="Archived URL aggregation" />
      </Panel>
    );
  }

  return (
    <Panel
      title={`${urls.length.toLocaleString()} archived URLs`}
      subtitle="Historical URLs from public crawls — many still resolve."
      action={<CopyButton size="md" label="Copy all" text={() => urls.join('\n')} />}
    >
      <SourceStats sources={data?.sources ?? []} />

      <div className="mb-3">
        <FilterInput
          value={filter}
          onChange={setFilter}
          placeholder="Search URLs (try: .json, /api/, ?token=)…"
        />
      </div>

      <UrlList urls={filtered} visible={visible} />
      <ShowMore total={filtered.length} visible={visible} onMore={more} noun="URLs" />

      {data?.truncated && (
        <p className="pt-2 text-center text-[11px] text-amber-300/70">
          Upstream cap reached — the archives hold more than this sample.
        </p>
      )}
    </Panel>
  );
}
