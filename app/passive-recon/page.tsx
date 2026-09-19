'use client';

/**
 * Unified Passive Recon Dashboard.
 *
 * One input, one button, ten modules. The route streams NDJSON, so each
 * module's card flips from pending -> running -> done/failed independently and
 * results render the moment they land rather than after the slowest upstream
 * settles.
 *
 * The page owns the scan lifecycle and the derived views; every tab is a
 * presentational component in ./components.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { buildDorks } from '@/lib/passive-recon/dorks';
import { buildFindings, countBySeverity } from '@/lib/passive-recon/findings';
import { buildPivots } from '@/lib/passive-recon/pivots';
import { formatDuration } from '@/lib/passive-recon/report';
import { sanitizeDomain } from '@/lib/passive-recon/sanitize';
import {
  MODULE_DESCRIPTIONS,
  MODULE_GROUPS,
  MODULE_IDS,
  MODULE_LABELS,
  type ModuleId,
  type ModuleState,
  type ScanEvent,
  type ScanReport,
} from '@/lib/passive-recon/types';

import { ArchivedTab, SubdomainsTab, TakeoverTab, UrlIntelTab } from './components/surface-tabs';
import { DnsTab, MailTab, WhoisTab } from './components/infra-tabs';
import { JsTab, MetaTab, TechTab } from './components/app-tabs';
import { OverviewTab } from './components/overview';
import { DorksTab, ExportTab, PivotsTab } from './components/toolkit';
import { Panel, StatTile, StatusDot, cx } from './components/ui';

type TabId = 'overview' | ModuleId | 'dorks' | 'pivots' | 'export';

const TABS: ReadonlyArray<{ id: TabId; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'takeover', label: 'Hosts' },
  { id: 'url-intel', label: 'URL Intel' },
  { id: 'dns', label: 'DNS' },
  { id: 'mail', label: 'Email' },
  { id: 'whois', label: 'Domain' },
  { id: 'tech', label: 'Tech' },
  { id: 'js-endpoints', label: 'JavaScript' },
  { id: 'archived', label: 'Archive' },
  { id: 'meta', label: 'Extras' },
  { id: 'dorks', label: 'Dorks' },
  { id: 'pivots', label: 'Pivots' },
  { id: 'export', label: 'Export' },
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
  };
}

export default function PassiveReconPage() {
  const [domain, setDomain] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [running, setRunning] = useState(false);
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>('overview');

  const abortRef = useRef<AbortController | null>(null);

  // A scan that is still streaming when the operator navigates away should stop
  // rather than keep the connection (and the server's work) alive.
  useEffect(() => () => abortRef.current?.abort(), []);

  const applyEvent = useCallback((event: ScanEvent) => {
    setReport((current) => {
      if (!current) return current;

      switch (event.type) {
        case 'module_start':
          return {
            ...current,
            modules: {
              ...current.modules,
              [event.module]: { ...current.modules[event.module], status: 'running' },
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
          return { ...current, finishedAt: event.finishedAt, durationMs: event.durationMs };

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
      setTab('overview');

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
          const detail = (await response.json().catch(() => null)) as { error?: string } | null;
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

  const cancelScan = useCallback(() => abortRef.current?.abort(), []);

  const findings = useMemo(() => (report ? buildFindings(report) : []), [report]);
  const counts = useMemo(() => countBySeverity(findings), [findings]);

  const dorks = useMemo(() => (report ? buildDorks(report.domain) : []), [report]);
  const pivots = useMemo(
    () =>
      report
        ? buildPivots({
            domain: report.domain,
            faviconHash: report.modules.meta.data?.favicon.hash ?? null,
            asn: report.modules.whois.data?.networks[0]?.asn ?? null,
          })
        : [],
    [report],
  );

  const modules = report?.modules;
  const subdomains = modules?.subdomains.data;
  const takeover = modules?.takeover.data;
  const urlIntel = modules?.['url-intel'].data;
  const js = modules?.['js-endpoints'].data;
  const meta = modules?.meta.data;

  const completed = report
    ? MODULE_IDS.filter((id) => report.modules[id].status === 'done' || report.modules[id].status === 'error')
        .length
    : 0;

  const tabCounts: Record<TabId, number> = {
    overview: findings.length,
    subdomains: subdomains?.subdomains.length ?? 0,
    takeover: takeover?.hosts.filter((host) => host.status === 'dangling').length ?? 0,
    'url-intel': urlIntel?.parameters.length ?? 0,
    dns: modules?.dns.data?.records.length ?? 0,
    mail: modules?.mail.data ? (modules.mail.data.spf.found ? 1 : 0) + (modules.mail.data.dmarc.found ? 1 : 0) : 0,
    whois: modules?.whois.data?.networks.length ?? 0,
    tech: modules?.tech.data?.technologies.length ?? 0,
    'js-endpoints': js?.endpoints.length ?? 0,
    archived: modules?.archived.data?.urls.length ?? 0,
    meta:
      (meta?.favicon.found ? 1 : 0) +
      (meta?.securityTxt.fields.length ?? 0) +
      (meta?.robots.disallowed.length ?? 0) +
      (meta?.wellKnown.filter((file) => file.found).length ?? 0),
    dorks: dorks.reduce((total, group) => total + group.dorks.length, 0),
    pivots: pivots.reduce((total, group) => total + group.links.length, 0),
    export: 0,
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Backdrop: one subtle emerald wash so the page reads as a tool, not a form. */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 bg-[radial-gradient(60rem_40rem_at_50%_-10%,rgba(16,185,129,0.10),transparent)]"
      />

      <div className="relative mx-auto max-w-7xl px-4 py-6 sm:px-6">
        <header className="mb-6">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
                <span className="text-emerald-400">Passive</span>Recon
              </h1>
              <p className="mt-1 text-sm text-zinc-400">
                One click, ten OSINT modules, zero active probing.
              </p>
            </div>

            {report && (
              <div className="text-right font-mono text-xs text-zinc-500">
                <p className="text-emerald-300">{report.domain}</p>
                <p>
                  {completed}/{MODULE_IDS.length} modules
                  {report.durationMs !== null && ` · ${formatDuration(report.durationMs)}`}
                </p>
              </div>
            )}
          </div>

          <form onSubmit={handleScan} className="mt-4 flex flex-wrap gap-2">
            <input
              type="text"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="target domain — example.com"
              aria-label="Target domain"
              autoComplete="off"
              spellCheck={false}
              className="min-w-64 flex-1 rounded-xl border border-white/10 bg-black/40 px-4 py-3 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/40 focus:outline-none"
            />

            <button
              type="submit"
              disabled={running}
              className={cx(
                'rounded-xl px-6 py-3 text-sm font-semibold transition-colors',
                running
                  ? 'cursor-not-allowed bg-zinc-800 text-zinc-500'
                  : 'bg-emerald-500 text-zinc-950 shadow-[0_0_24px_rgba(16,185,129,0.25)] hover:bg-emerald-400',
              )}
            >
              {running ? 'Scanning…' : 'Run full passive scan'}
            </button>

            {running && (
              <button
                type="button"
                onClick={cancelScan}
                className="rounded-xl border border-rose-500/40 px-4 py-3 text-sm font-semibold text-rose-300 transition-colors hover:bg-rose-500/10"
              >
                Cancel
              </button>
            )}
          </form>

          {report && (
            <div className="mt-3 h-1 w-full overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full bg-emerald-500 transition-[width] duration-500"
                style={{ width: `${(completed / MODULE_IDS.length) * 100}%` }}
              />
            </div>
          )}

          {fatalError && (
            <div className="mt-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
              {fatalError}
            </div>
          )}
        </header>

        {!report ? (
          <IntroPanels />
        ) : (
          <>
            <section className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
              <StatTile
                label="Findings"
                value={findings.length}
                tone={counts.critical + counts.high > 0 ? 'high' : 'default'}
                hint={`${counts.critical + counts.high} high or worse`}
              />
              <StatTile label="Hosts" value={subdomains?.subdomains.length ?? 0} tone="accent" />
              <StatTile label="Live hosts" value={takeover?.live ?? 0} hint={`${takeover?.checked ?? 0} resolved`} />
              <StatTile
                label="URLs"
                value={(modules?.archived.data?.urls.length ?? 0).toLocaleString()}
                hint={`${urlIntel?.analyzed.toLocaleString() ?? 0} analysed`}
              />
              <StatTile label="Parameters" value={urlIntel?.parameters.length ?? 0} />
              <StatTile
                label="Secrets"
                value={js?.secrets.length ?? 0}
                tone={(js?.secrets.length ?? 0) > 0 ? 'critical' : 'default'}
              />
            </section>

            <ModuleStrip report={report} />

            <nav className="sticky top-0 z-10 -mx-4 mb-4 overflow-x-auto border-b border-white/10 bg-zinc-950/85 px-4 backdrop-blur sm:-mx-6 sm:px-6">
              <div className="flex gap-1">
                {TABS.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setTab(item.id)}
                    className={cx(
                      'relative shrink-0 px-3 py-3 text-sm transition-colors',
                      tab === item.id
                        ? 'font-semibold text-emerald-300'
                        : 'text-zinc-500 hover:text-zinc-300',
                    )}
                  >
                    {item.label}
                    {tabCounts[item.id] > 0 && (
                      <span className="ml-1.5 rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                        {tabCounts[item.id]}
                      </span>
                    )}
                    {tab === item.id && (
                      <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-emerald-400" />
                    )}
                  </button>
                ))}
              </div>
            </nav>

            <main className="pb-16">
              {tab === 'overview' && (
                <OverviewTab
                  report={report}
                  findings={findings}
                  counts={counts}
                  onJump={setTab}
                  running={running}
                />
              )}
              {tab === 'subdomains' && (
                <SubdomainsTab state={report.modules.subdomains} data={subdomains ?? null} />
              )}
              {tab === 'takeover' && (
                <TakeoverTab state={report.modules.takeover} data={takeover ?? null} />
              )}
              {tab === 'url-intel' && (
                <UrlIntelTab state={report.modules['url-intel']} data={urlIntel ?? null} />
              )}
              {tab === 'dns' && <DnsTab state={report.modules.dns} data={report.modules.dns.data} />}
              {tab === 'mail' && (
                <MailTab state={report.modules.mail} data={report.modules.mail.data} />
              )}
              {tab === 'whois' && (
                <WhoisTab state={report.modules.whois} data={report.modules.whois.data} />
              )}
              {tab === 'tech' && (
                <TechTab state={report.modules.tech} data={report.modules.tech.data} />
              )}
              {tab === 'js-endpoints' && (
                <JsTab state={report.modules['js-endpoints']} data={js ?? null} />
              )}
              {tab === 'archived' && (
                <ArchivedTab state={report.modules.archived} data={report.modules.archived.data} />
              )}
              {tab === 'meta' && <MetaTab state={report.modules.meta} data={meta ?? null} />}
              {tab === 'dorks' && <DorksTab groups={dorks} />}
              {tab === 'pivots' && <PivotsTab groups={pivots} />}
              {tab === 'export' && <ExportTab report={report} />}
            </main>
          </>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Static sections                                                            */
/* -------------------------------------------------------------------------- */

function ModuleStrip({ report }: { report: ScanReport }) {
  return (
    <section className="mb-5 grid gap-3 lg:grid-cols-3">
      {MODULE_GROUPS.map((group) => (
        <div key={group.label} className="rounded-xl border border-white/8 bg-zinc-900/40 p-3">
          <p className="mb-2 text-[11px] font-medium tracking-wider text-zinc-500 uppercase">
            {group.label}
          </p>
          <ul className="space-y-1.5">
            {group.modules.map((id) => {
              const state = report.modules[id];
              return (
                <li key={id} className="flex items-center gap-2">
                  <StatusDot status={state.status} />
                  <span className="text-xs text-zinc-300">{MODULE_LABELS[id]}</span>
                  <span className="ml-auto shrink-0 font-mono text-[10px] text-zinc-600">
                    {state.status === 'done' && formatDuration(state.durationMs)}
                    {state.status === 'running' && 'running'}
                    {state.status === 'error' && <span className="text-rose-400">failed</span>}
                    {state.status === 'pending' && 'queued'}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </section>
  );
}

function IntroPanels() {
  return (
    <div className="space-y-4">
      <Panel
        title="What one click does"
        subtitle="Every module runs in parallel and streams its result as it lands."
      >
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {MODULE_IDS.map((id) => (
            <div key={id} className="rounded-lg border border-white/5 bg-black/20 p-3">
              <p className="text-sm font-medium text-zinc-200">{MODULE_LABELS[id]}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-zinc-500">
                {MODULE_DESCRIPTIONS[id]}
              </p>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Passive means passive">
        <ul className="space-y-2 text-sm leading-relaxed text-zinc-400">
          <li>
            <span className="text-emerald-300">OSINT indexes</span> are queried for data they
            already hold — certificate transparency, passive DNS, web archives, RDAP.
          </li>
          <li>
            <span className="text-emerald-300">DNS resolution</span> covers the apex and a capped
            sweep of discovered hosts. These are ordinary recursive lookups, the same ones a
            browser makes before opening any connection.
          </li>
          <li>
            <span className="text-emerald-300">The target</span> receives one homepage GET, the
            same-origin scripts it advertises, and a short fixed list of published files
            (robots.txt, sitemap, security.txt, favicon, <code>/.well-known/*</code>). That is a
            browser&apos;s first visit — never a wordlist.
          </li>
          <li>
            <span className="text-rose-300">No</span> port scanning, directory brute-forcing or
            parameter fuzzing. Wordlists are exported for your own tooling, because you own the
            authorisation that makes active testing legal.
          </li>
        </ul>
      </Panel>
    </div>
  );
}
