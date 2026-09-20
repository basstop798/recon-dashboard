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

import { ArrowUpRightIcon } from './icons';
import {
  CopyButton,
  DataList,
  DataRow,
  DataTable,
  EmptyState,
  FilterChip,
  FilterInput,
  MONO,
  Notice,
  Panel,
  Pill,
  SeverityBadge,
  ShowMore,
  SourceStats,
  StatTile,
  Td,
  Toggle,
  Tr,
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
      title={`${hosts.length.toLocaleString()} host${hosts.length === 1 ? '' : 's'} discovered`}
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

      <div className="mb-4">
        <FilterInput value={filter} onChange={setFilter} placeholder="Filter hosts…" />
      </div>

      <DataList>
        {filtered.slice(0, visible).map((record) => (
          <DataRow key={record.host} className="justify-between">
            <a
              href={`https://${record.host}`}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className={cx(
                MONO,
                'group/link inline-flex min-w-0 items-center gap-1.5 text-zinc-200 transition-colors hover:text-white',
              )}
            >
              <span className="truncate">{record.host}</span>
              <ArrowUpRightIcon className="size-3.5 shrink-0 text-zinc-500 opacity-0 transition-opacity group-hover/link:opacity-100" />
            </a>
            <span className="flex shrink-0 flex-wrap justify-end gap-1">
              {record.sources.map((source) => (
                <span
                  key={source}
                  className="rounded bg-white/5 px-1.5 py-0.5 text-[11px] font-medium text-zinc-400"
                >
                  {source}
                </span>
              ))}
            </span>
          </DataRow>
        ))}
      </DataList>

      <ShowMore total={filtered.length} visible={visible} onMore={more} noun="hosts" />
      {data?.truncated && <Notice>Upstream cap reached — some hosts were not returned.</Notice>}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */

const HOST_STATUS: Record<HostResolution['status'], { label: string; text: string; dot: string }> = {
  live: { label: 'Live', text: 'text-emerald-400', dot: 'bg-emerald-400' },
  dangling: { label: 'Dangling', text: 'text-rose-400', dot: 'bg-rose-500' },
  nxdomain: { label: 'NXDOMAIN', text: 'text-zinc-500', dot: 'bg-zinc-600' },
  error: { label: 'Error', text: 'text-amber-400', dot: 'bg-amber-400' },
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
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
          <Toggle checked={onlyInteresting} onChange={setOnlyInteresting} label="Interesting only" />
        }
      >
        <div className="mb-4">
          <FilterInput value={filter} onChange={setFilter} placeholder="Filter hosts…" />
        </div>

        <DataTable columns={['Host', 'Status', 'Points at', 'Note']}>
          {filtered.slice(0, visible).map((host) => {
            const status = HOST_STATUS[host.status];
            return (
              <Tr key={host.host}>
                <Td mono className="break-all text-zinc-100">
                  {host.host}
                  {host.takeover && (
                    <span className="ml-2 inline-block align-middle">
                      <SeverityBadge severity={host.severity} />
                    </span>
                  )}
                </Td>
                <Td className="whitespace-nowrap">
                  <span className={cx('inline-flex items-center gap-2 font-medium', status.text)}>
                    <span className={cx('size-1.5 rounded-full', status.dot)} />
                    {status.label}
                  </span>
                </Td>
                <Td mono className="break-all text-zinc-400">
                  {host.cname ?? (host.addresses.slice(0, 2).join(', ') || '—')}
                  {host.service && (
                    <span className="mt-1.5 block">
                      <Pill tone="accent">{host.service}</Pill>
                    </span>
                  )}
                </Td>
                <Td className="text-zinc-400">{host.note}</Td>
              </Tr>
            );
          })}
        </DataTable>

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
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
          <div className="mb-5 flex flex-wrap gap-2">
            {data.buckets.map((bucket) => (
              <FilterChip
                key={bucket.id}
                active={active?.id === bucket.id}
                onClick={() => setBucketId(bucket.id)}
                count={bucket.total}
              >
                {bucket.label}
              </FilterChip>
            ))}
          </div>

          {active && (
            <>
              <div className="mb-4 flex flex-wrap items-center gap-3">
                <SeverityBadge severity={active.severity} />
                <p className="text-sm text-zinc-400">{active.description}</p>
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
          <p className="text-sm text-zinc-400">No parameters were seen in the collected URLs.</p>
        ) : (
          <DataTable columns={['Parameter', 'Seen', 'Associated with']} maxHeight="max-h-112">
            {data.parameters.map((parameter) => (
              <Tr key={parameter.name}>
                <Td mono className="break-all text-zinc-100">
                  {parameter.name}
                </Td>
                <Td className="text-zinc-400 tabular-nums">{parameter.count.toLocaleString()}</Td>
                <Td>
                  <span className="flex flex-wrap gap-1.5">
                    {parameter.classes.map((id) => (
                      <Pill key={id} tone="accent">
                        {classLabel(id)}
                      </Pill>
                    ))}
                  </span>
                </Td>
              </Tr>
            ))}
          </DataTable>
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Cloud assets" subtitle="Storage and hosting identifiers referenced by the estate.">
          {data.cloudAssets.length === 0 ? (
            <p className="text-sm text-zinc-400">None referenced.</p>
          ) : (
            <DataList>
              {data.cloudAssets.map((asset) => (
                <DataRow key={`${asset.provider}-${asset.asset}`}>
                  <Pill tone="accent">{asset.provider}</Pill>
                  <span className={cx(MONO, 'min-w-0 flex-1 truncate text-zinc-300')}>
                    {asset.asset}
                  </span>
                  <CopyButton text={asset.asset} />
                </DataRow>
              ))}
            </DataList>
          )}
        </Panel>

        <Panel title="Third-party hosts" subtitle="Vendors and CDNs the estate depends on.">
          {data.thirdPartyHosts.length === 0 ? (
            <p className="text-sm text-zinc-400">None seen.</p>
          ) : (
            <DataList maxHeight="max-h-80">
              {data.thirdPartyHosts.slice(0, 100).map((host) => (
                <DataRow key={host.host} className="justify-between">
                  <span className={cx(MONO, 'min-w-0 truncate text-zinc-300')}>{host.host}</span>
                  <span className="text-xs text-zinc-500 tabular-nums">×{host.count}</span>
                </DataRow>
              ))}
            </DataList>
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

      <div className="mb-4">
        <FilterInput
          value={filter}
          onChange={setFilter}
          placeholder="Search URLs (try: .json, /api/, ?token=)…"
        />
      </div>

      <UrlList urls={filtered} visible={visible} />
      <ShowMore total={filtered.length} visible={visible} onMore={more} noun="URLs" />

      {data?.truncated && (
        <Notice>Upstream cap reached — the archives hold more than this sample.</Notice>
      )}
    </Panel>
  );
}
