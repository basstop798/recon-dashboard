'use client';

/**
 * Unified Passive Recon Dashboard.
 *
 * One input, one button. The route streams NDJSON, so each module's card flips
 * from pending -> running -> done/failed independently and results render the
 * moment they land rather than after the slowest upstream settles.
 */

import { useCallback, useMemo, useRef, useState } from 'react';

import { buildDorks } from '@/lib/passive-recon/dorks';
import { sanitizeDomain } from '@/lib/passive-recon/sanitize';
import {
  MODULE_DESCRIPTIONS,
  MODULE_IDS,
  MODULE_LABELS,
  type ModuleId,
  type ModuleState,
  type ScanEvent,
  type ScanReport,
  type SourceStat,
} from '@/lib/passive-recon/types';

/** Keeps the DOM manageable when an index returns thousands of rows. */
const MAX_VISIBLE_ROWS = 300;

type TabId = ModuleId | 'dorks';

const TABS: ReadonlyArray<{ id: TabId; label: string }> = [
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'tech', label: 'Tech Stack' },
  { id: 'archived', label: 'Archived Endpoints' },
  { id: 'js-endpoints', label: 'JS Endpoints' },
  { id: 'dorks', label: 'Dorks' },
];

function emptyModules(): ScanReport['modules'] {
  const base = {} as ScanReport['modules'];
  for (const id of MODULE_IDS) {
    // Each module starts pending; the stream advances it.
    (base as Record<ModuleId, ModuleState>)[id] = {
      status: 'pending',
      durationMs: null,
      error: null,
      data: null,
    };
  }
  return base;
}

function createReport(domain: string): ScanReport {
  return {
    domain,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    durationMs: null,
    modules: emptyModules(),
    dorks: buildDorks(domain),
  };
}

function formatDuration(ms: number | null): string {
  if (ms === null) return '';
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function downloadBlob(contents: string, filename: string, type: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/** Renders the aggregated report as a human-readable text file. */
function reportToText(report: ScanReport): string {
  const lines: string[] = [
    '='.repeat(72),
    ` PASSIVE RECON REPORT — ${report.domain}`,
    ` Started  : ${report.startedAt}`,
    ` Finished : ${report.finishedAt ?? 'incomplete'}`,
    ` Duration : ${formatDuration(report.durationMs) || 'n/a'}`,
    '='.repeat(72),
    '',
  ];

  const subdomains = report.modules.subdomains;
  lines.push(`[SUBDOMAINS] (${subdomains.data?.subdomains.length ?? 0})`);
  if (subdomains.error) lines.push(`  ! ${subdomains.error}`);
  for (const record of subdomains.data?.subdomains ?? []) {
    lines.push(`  ${record.host}  [${record.sources.join(', ')}]`);
  }
  lines.push('');

  const tech = report.modules.tech;
  lines.push(`[TECH STACK] (${tech.data?.technologies.length ?? 0})`);
  if (tech.error) lines.push(`  ! ${tech.error}`);
  if (tech.data) {
    lines.push(`  Final URL : ${tech.data.finalUrl} (HTTP ${tech.data.status})`);
    for (const item of tech.data.technologies) {
      lines.push(`  ${item.category.padEnd(16)} ${item.name}  <- ${item.evidence}`);
    }
    lines.push('', '  Response headers:');
    for (const header of tech.data.headers) {
      lines.push(`    ${header.name}: ${header.value}`);
    }
    if (tech.data.cookieNames.length > 0) {
      lines.push(`  Cookie names: ${tech.data.cookieNames.join(', ')}`);
    }
  }
  lines.push('');

  const archived = report.modules.archived;
  lines.push(`[ARCHIVED URLS] (${archived.data?.urls.length ?? 0})`);
  if (archived.error) lines.push(`  ! ${archived.error}`);
  for (const url of archived.data?.urls ?? []) lines.push(`  ${url}`);
  lines.push('');

  const js = report.modules['js-endpoints'];
  lines.push(`[JS ENDPOINT CANDIDATES] (${js.data?.endpoints.length ?? 0})`);
  if (js.error) lines.push(`  ! ${js.error}`);
  for (const endpoint of js.data?.endpoints ?? []) lines.push(`  ${endpoint}`);
  lines.push('');

  lines.push('[DORKS]');
  for (const group of report.dorks) {
    lines.push(`  -- ${group.engine} --`);
    for (const dork of group.dorks) {
      lines.push(`  ${dork.label}: ${dork.query}`);
      lines.push(`     ${dork.url}`);
    }
  }

  return lines.join('\n');
}

/* -------------------------------------------------------------------------- */
/* Presentational helpers                                                     */
/* -------------------------------------------------------------------------- */

function StatusDot({ status }: { status: ModuleState['status'] }) {
  if (status === 'running') {
    return (
      <span
        aria-label="running"
        className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent"
      />
    );
  }

  const styles: Record<Exclude<ModuleState['status'], 'running'>, string> = {
    pending: 'bg-gray-600',
    done: 'bg-emerald-400',
    error: 'bg-red-500',
  };

  return (
    <span
      aria-label={status}
      className={`inline-block h-3 w-3 rounded-full ${styles[status]}`}
    />
  );
}

function SourceStats({ sources }: { sources: SourceStat[] }) {
  if (sources.length === 0) return null;

  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {sources.map((source) => (
        <span
          key={source.source}
          title={source.error ?? `${source.count} result(s)`}
          className={`rounded border px-2 py-1 text-xs ${
            source.ok
              ? 'border-emerald-800 bg-emerald-950/50 text-emerald-300'
              : 'border-red-900 bg-red-950/40 text-red-300'
          }`}
        >
          {source.source}: {source.ok ? source.count : 'failed'}
        </span>
      ))}
    </div>
  );
}

function EmptyState({ state, label }: { state: ModuleState; label: string }) {
  if (state.status === 'error') {
    return (
      <p className="rounded border border-red-900 bg-red-950/40 p-4 text-sm text-red-300">
        {label} failed: {state.error}
      </p>
    );
  }
  if (state.status === 'running') {
    return <p className="p-4 text-sm text-gray-400">Collecting {label.toLowerCase()}…</p>;
  }
  if (state.status === 'pending') {
    return <p className="p-4 text-sm text-gray-500">Waiting for scan.</p>;
  }
  return <p className="p-4 text-sm text-gray-500">No results.</p>;
}

/* -------------------------------------------------------------------------- */
/* Page                                                                       */
/* -------------------------------------------------------------------------- */

export default function PassiveReconPage() {
  const [domain, setDomain] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [running, setRunning] = useState(false);
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>('subdomains');
  const [subdomainFilter, setSubdomainFilter] = useState('');
  const [urlFilter, setUrlFilter] = useState('');

  const abortRef = useRef<AbortController | null>(null);

  const applyEvent = useCallback((event: ScanEvent) => {
    setReport((current) => {
      if (!current) return current;

      switch (event.type) {
        case 'module_start':
          return {
            ...current,
            modules: {
              ...current.modules,
              [event.module]: {
                ...current.modules[event.module],
                status: 'running',
              },
            },
          };

        case 'module_done':
          return {
            ...current,
            modules: {
              ...current.modules,
              [event.module]: {
                status: 'done',
                durationMs: event.durationMs,
                error: null,
                data: event.data,
              },
            },
          };

        case 'module_error':
          return {
            ...current,
            modules: {
              ...current.modules,
              [event.module]: {
                status: 'error',
                durationMs: event.durationMs,
                error: event.error,
                data: null,
              },
            },
          };

        case 'scan_complete':
          return {
            ...current,
            finishedAt: event.finishedAt,
            durationMs: event.durationMs,
          };

        default:
          return current;
      }
    });

    if (event.type === 'scan_error') setFatalError(event.error);
  }, []);

  const handleScan = useCallback(
    async (formEvent: React.FormEvent) => {
      formEvent.preventDefault();
      if (running) return;

      // Same validator the server enforces — instant feedback, not a control.
      const validation = sanitizeDomain(domain);
      if (!validation.ok) {
        setFatalError(validation.error);
        return;
      }

      const target = validation.domain;
      setDomain(target);
      setFatalError(null);
      setReport(createReport(target));
      setRunning(true);
      setSubdomainFilter('');
      setUrlFilter('');

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const response = await fetch('/api/passive-recon', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: target }),
          signal: controller.signal,
        });

        if (!response.ok) {
          const detail = (await response.json().catch(() => null)) as
            | { error?: string }
            | null;
          setFatalError(detail?.error ?? `Scan rejected (HTTP ${response.status}).`);
          return;
        }

        if (!response.body) {
          setFatalError('Streaming is not supported by this browser.');
          return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });

          // A chunk can split a line, so only whole lines are parsed.
          let newline = buffer.indexOf('\n');
          while (newline >= 0) {
            const line = buffer.slice(0, newline).trim();
            buffer = buffer.slice(newline + 1);
            if (line) applyEvent(JSON.parse(line) as ScanEvent);
            newline = buffer.indexOf('\n');
          }
        }

        const tail = buffer.trim();
        if (tail) applyEvent(JSON.parse(tail) as ScanEvent);
      } catch (error) {
        if ((error as Error)?.name !== 'AbortError') {
          setFatalError((error as Error)?.message ?? 'Network failure.');
        }
      } finally {
        setRunning(false);
        abortRef.current = null;
      }
    },
    [applyEvent, domain, running],
  );

  const cancelScan = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  // The `?? []` fallback allocates a fresh array on every render, so these two
  // are memoised on `report` — otherwise the filter memos below would recompute
  // continuously and the identity check they rely on would be meaningless.
  const subdomains = useMemo(
    () => report?.modules.subdomains.data?.subdomains ?? [],
    [report],
  );
  const archivedUrls = useMemo(
    () => report?.modules.archived.data?.urls ?? [],
    [report],
  );
  const technologies = report?.modules.tech.data?.technologies ?? [];
  const jsEndpoints = report?.modules['js-endpoints'].data?.endpoints ?? [];

  const filteredSubdomains = useMemo(() => {
    const needle = subdomainFilter.trim().toLowerCase();
    if (!needle) return subdomains;
    return subdomains.filter((record) => record.host.includes(needle));
  }, [subdomains, subdomainFilter]);

  const filteredUrls = useMemo(() => {
    const needle = urlFilter.trim().toLowerCase();
    if (!needle) return archivedUrls;
    return archivedUrls.filter((url) => url.toLowerCase().includes(needle));
  }, [archivedUrls, urlFilter]);

  const tabCounts: Record<TabId, number> = {
    subdomains: subdomains.length,
    tech: technologies.length,
    archived: archivedUrls.length,
    'js-endpoints': jsEndpoints.length,
    dorks: report?.dorks.reduce((total, group) => total + group.dorks.length, 0) ?? 0,
  };

  const hasResults = report !== null;

  return (
    <div className="min-h-screen bg-gray-950 p-6 font-mono text-gray-100">
      <div className="mx-auto max-w-6xl space-y-6">
        <header className="border-b border-gray-800 pb-4">
          <h1 className="text-3xl font-bold text-emerald-400">
            Passive<span className="text-gray-100">Recon</span>
          </h1>
          <p className="mt-2 text-sm text-gray-400">
            OSINT aggregation with no active probing — public indexes plus a single
            passive request to the target.
          </p>
        </header>

        <form onSubmit={handleScan} className="flex flex-wrap gap-3">
          <input
            type="text"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder="target domain (e.g. example.com)"
            aria-label="Target domain"
            className="min-w-64 flex-1 rounded-md border border-gray-700 bg-gray-900 px-4 py-3 transition-colors focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 focus:outline-none"
          />

          <button
            type="submit"
            disabled={running}
            className={`rounded-md px-6 py-3 font-semibold transition-colors ${
              running
                ? 'cursor-not-allowed bg-gray-700 text-gray-400'
                : 'bg-emerald-600 text-white shadow-[0_0_15px_rgba(5,150,105,0.4)] hover:bg-emerald-500'
            }`}
          >
            {running ? 'Scanning…' : 'Launch Full Passive Scan'}
          </button>

          {running && (
            <button
              type="button"
              onClick={cancelScan}
              className="rounded-md border border-red-700 px-4 py-3 font-semibold text-red-300 transition-colors hover:bg-red-950"
            >
              Cancel
            </button>
          )}

          <button
            type="button"
            onClick={() => report && downloadBlob(JSON.stringify(report, null, 2), `passive-recon-${report.domain}.json`, 'application/json')}
            disabled={!hasResults}
            className="rounded-md border border-emerald-600 px-4 py-3 font-semibold text-emerald-300 transition-colors enabled:hover:bg-emerald-950 disabled:cursor-not-allowed disabled:border-gray-700 disabled:text-gray-600"
          >
            JSON
          </button>

          <button
            type="button"
            onClick={() => report && downloadBlob(reportToText(report), `passive-recon-${report.domain}.txt`, 'text/plain')}
            disabled={!hasResults}
            className="rounded-md border border-emerald-600 px-4 py-3 font-semibold text-emerald-300 transition-colors enabled:hover:bg-emerald-950 disabled:cursor-not-allowed disabled:border-gray-700 disabled:text-gray-600"
          >
            TXT
          </button>
        </form>

        {fatalError && (
          <div className="rounded-md border border-red-900 bg-red-950/50 px-4 py-3 text-sm text-red-300">
            {fatalError}
          </div>
        )}

        {/* Real-time per-module status */}
        <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {MODULE_IDS.map((id) => {
            const state = report?.modules[id];
            return (
              <div
                key={id}
                className="rounded-md border border-gray-800 bg-gray-900 p-4"
              >
                <div className="flex items-center gap-2">
                  <StatusDot status={state?.status ?? 'pending'} />
                  <span className="text-sm font-semibold">{MODULE_LABELS[id]}</span>
                </div>
                <p className="mt-2 text-xs text-gray-500">{MODULE_DESCRIPTIONS[id]}</p>
                <p className="mt-2 text-xs text-gray-400">
                  {state?.status === 'done' && `Completed in ${formatDuration(state.durationMs)}`}
                  {state?.status === 'error' && (
                    <span className="text-red-400">{state.error}</span>
                  )}
                  {state?.status === 'running' && 'In progress…'}
                  {(!state || state.status === 'pending') && 'Idle'}
                </p>
              </div>
            );
          })}
        </section>

        {/* Tabs */}
        <nav className="flex flex-wrap gap-2 border-b border-gray-800">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`rounded-t-md px-4 py-2 text-sm transition-colors ${
                tab === item.id
                  ? 'border border-b-0 border-gray-800 bg-gray-900 text-emerald-400'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {item.label}
              <span className="ml-2 rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-300">
                {tabCounts[item.id]}
              </span>
            </button>
          ))}
        </nav>

        <section className="min-h-64 rounded-md border border-gray-800 bg-gray-900 p-4">
          {!report && (
            <p className="p-4 text-sm text-gray-500">
              Enter a domain and launch a scan to populate every module.
            </p>
          )}

          {report && tab === 'subdomains' && (
            <div>
              <SourceStats sources={report.modules.subdomains.data?.sources ?? []} />
              {subdomains.length === 0 ? (
                <EmptyState state={report.modules.subdomains} label="Subdomain aggregation" />
              ) : (
                <>
                  <input
                    type="text"
                    value={subdomainFilter}
                    onChange={(event) => setSubdomainFilter(event.target.value)}
                    placeholder="Filter subdomains…"
                    className="mb-3 w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm focus:border-emerald-500 focus:outline-none"
                  />
                  <p className="mb-2 text-xs text-gray-500">
                    Showing {Math.min(filteredSubdomains.length, MAX_VISIBLE_ROWS)} of{' '}
                    {filteredSubdomains.length} ({subdomains.length} total)
                  </p>
                  <ul className="divide-y divide-gray-800">
                    {filteredSubdomains.slice(0, MAX_VISIBLE_ROWS).map((record) => (
                      <li
                        key={record.host}
                        className="flex items-center justify-between gap-3 py-2 text-sm"
                      >
                        <a
                          href={`https://${record.host}`}
                          target="_blank"
                          rel="noopener noreferrer nofollow"
                          className="truncate text-emerald-300 hover:underline"
                        >
                          {record.host}
                        </a>
                        <span className="shrink-0 text-xs text-gray-500">
                          {record.sources.join(' · ')}
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}

          {report && tab === 'tech' && (
            <div>
              {technologies.length === 0 ? (
                <EmptyState state={report.modules.tech} label="Technology fingerprint" />
              ) : (
                <>
                  <p className="mb-3 text-xs text-gray-500">
                    {report.modules.tech.data?.finalUrl} — HTTP{' '}
                    {report.modules.tech.data?.status}
                  </p>
                  <div className="mb-6 flex flex-wrap gap-2">
                    {technologies.map((item) => (
                      <span
                        key={`${item.category}-${item.name}`}
                        title={item.evidence}
                        className="rounded-full border border-emerald-800 bg-emerald-950/50 px-3 py-1 text-xs text-emerald-300"
                      >
                        {item.name}
                        <span className="ml-1 text-emerald-600">({item.category})</span>
                      </span>
                    ))}
                  </div>

                  {(report.modules.tech.data?.cookieNames.length ?? 0) > 0 && (
                    <div className="mb-6">
                      <h3 className="mb-2 text-sm font-semibold text-gray-300">
                        Cookie names
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {report.modules.tech.data?.cookieNames.map((name) => (
                          <span
                            key={name}
                            className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-gray-300"
                          >
                            {name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <h3 className="mb-2 text-sm font-semibold text-gray-300">
                    Response headers
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <tbody className="divide-y divide-gray-800">
                        {report.modules.tech.data?.headers.map((header) => (
                          <tr key={header.name}>
                            <td className="py-2 pr-4 align-top font-semibold text-emerald-400">
                              {header.name}
                            </td>
                            <td className="py-2 break-all text-gray-300">{header.value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {report && tab === 'archived' && (
            <div>
              <SourceStats sources={report.modules.archived.data?.sources ?? []} />
              {archivedUrls.length === 0 ? (
                <EmptyState state={report.modules.archived} label="Archived URL aggregation" />
              ) : (
                <>
                  <input
                    type="text"
                    value={urlFilter}
                    onChange={(event) => setUrlFilter(event.target.value)}
                    placeholder="Search archived URLs…"
                    className="mb-3 w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm focus:border-emerald-500 focus:outline-none"
                  />
                  <p className="mb-2 text-xs text-gray-500">
                    Showing {Math.min(filteredUrls.length, MAX_VISIBLE_ROWS)} of{' '}
                    {filteredUrls.length} ({archivedUrls.length} total)
                    {report.modules.archived.data?.truncated && ' — upstream limit reached'}
                  </p>
                  <div className="max-h-128 overflow-auto">
                    <table className="w-full text-left text-xs">
                      <tbody className="divide-y divide-gray-800">
                        {filteredUrls.slice(0, MAX_VISIBLE_ROWS).map((url) => (
                          <tr key={url}>
                            <td className="py-2">
                              <a
                                href={url}
                                target="_blank"
                                rel="noopener noreferrer nofollow"
                                className="break-all text-gray-300 hover:text-emerald-300 hover:underline"
                              >
                                {url}
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {report && tab === 'js-endpoints' && (
            <div>
              {jsEndpoints.length === 0 ? (
                <EmptyState state={report.modules['js-endpoints']} label="Static JS parsing" />
              ) : (
                <>
                  <p className="mb-3 text-xs text-gray-500">
                    Parsed {report.modules['js-endpoints'].data?.scanned} of{' '}
                    {report.modules['js-endpoints'].data?.scripts.length} referenced
                    scripts. These are heuristic candidates — verify before acting.
                  </p>
                  <ul className="divide-y divide-gray-800">
                    {jsEndpoints.slice(0, MAX_VISIBLE_ROWS).map((endpoint) => (
                      <li key={endpoint} className="py-2 text-sm break-all text-gray-300">
                        {endpoint}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}

          {report && tab === 'dorks' && (
            <div className="space-y-6">
              {report.dorks.map((group) => (
                <div key={group.engine}>
                  <h3 className="mb-3 text-sm font-semibold text-emerald-400">
                    {group.engine}
                  </h3>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {group.dorks.map((dork) => (
                      <a
                        key={dork.query}
                        href={dork.url}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        className="rounded border border-gray-800 bg-gray-950 p-3 transition-colors hover:border-emerald-700"
                      >
                        <span className="block text-sm text-emerald-300">{dork.label}</span>
                        <code className="mt-1 block text-xs break-all text-gray-500">
                          {dork.query}
                        </code>
                      </a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
