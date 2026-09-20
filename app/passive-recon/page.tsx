'use client';

/**
 * BulletRecon dashboard.
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
import { AlertIcon, GlobeIcon, LogoMark } from './components/icons';
import { OverviewTab } from './components/overview';
import { TabBar } from './components/tab-bar';
import { DorksTab, ExportTab, PivotsTab } from './components/toolkit';
import { CARD, CheckMark, INSET, LABEL, Panel, StatTile, StatusDot, cx } from './components/ui';

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

/** Shared by the app bar and the content column so their edges line up. */
const CONTAINER = 'mx-auto w-full max-w-[96rem] px-4 sm:px-6 lg:px-8';

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

function isSettled(state: ModuleState): boolean {
  return state.status === 'done' || state.status === 'error';
}

export default function BulletReconPage() {
  const [domain, setDomain] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [running, setRunning] = useState(false);
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>('overview');

  const abortRef = useRef<AbortController | null>(null);
  const resultsRef = useRef<HTMLElement>(null);

  // A scan that is still streaming when the operator navigates away should stop
  // rather than keep the connection (and the server's work) alive.
  useEffect(() => () => abortRef.current?.abort(), []);

  /**
   * Switches tab. Tabs differ wildly in length, so once the operator has
   * scrolled past the tab bar the view returns to the top of the new tab
   * instead of wherever the old one left it. `reveal` forces that scroll, for
   * jumps that start outside the tab area.
   */
  const selectTab = useCallback((id: TabId, reveal = false) => {
    setTab(id);
    const section = resultsRef.current;
    if (section && (reveal || section.getBoundingClientRect().top < 0)) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, []);

  const jumpTo = useCallback((id: ModuleId) => selectTab(id, true), [selectTab]);

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

  const completed = report ? MODULE_IDS.filter((id) => isSettled(report.modules[id])).length : 0;
  const severe = counts.critical + counts.high;

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
    <div className="relative min-h-screen bg-zinc-950 text-zinc-100">
      {/* One faint, neutral light source at the top — depth without colour. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-144 bg-[radial-gradient(ellipse_60%_50%_at_50%_-10%,rgb(255_255_255/0.06),transparent)]"
      />

      <header className="relative border-b border-white/10">
        <div className={cx(CONTAINER, 'flex h-16 items-center justify-between gap-4')}>
          <div className="flex items-center gap-3">
            <span className="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/25 ring-inset">
              <LogoMark className="size-5" />
            </span>
            <h1 className="text-lg font-semibold tracking-tight text-zinc-50">
              Bullet<span className="text-zinc-400">Recon</span>
            </h1>
            <span className="hidden rounded-full bg-white/5 px-2.5 py-0.5 text-xs font-medium text-zinc-400 ring-1 ring-white/10 ring-inset sm:inline-flex">
              Passive OSINT
            </span>
          </div>
          <p className="hidden text-sm text-zinc-500 md:block">
            One click, ten OSINT modules, zero active probing.
          </p>
        </div>
      </header>

      <div className={cx(CONTAINER, 'relative space-y-6 py-8')}>
        <section className={cx(CARD, 'p-5 sm:p-6')}>
          <form onSubmit={handleScan}>
            <label htmlFor="target-domain" className={cx(LABEL, 'mb-2.5 block')}>
              Target domain
            </label>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative min-w-0 flex-1">
                <GlobeIcon className="pointer-events-none absolute top-1/2 left-4 size-4 -translate-y-1/2 text-zinc-500" />
                <input
                  id="target-domain"
                  type="text"
                  value={domain}
                  onChange={(event) => setDomain(event.target.value)}
                  placeholder="example.com"
                  autoComplete="off"
                  spellCheck={false}
                  className="h-12 w-full rounded-lg bg-zinc-950 pr-4 pl-11 font-mono text-sm text-zinc-100 ring-1 ring-white/10 transition-shadow ring-inset placeholder:text-zinc-600 focus:ring-2 focus:ring-emerald-500/50 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={running}
                className="inline-flex h-12 items-center justify-center gap-2.5 rounded-lg bg-zinc-100 px-6 text-sm font-semibold text-zinc-900 shadow-sm transition-colors hover:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:cursor-not-allowed disabled:bg-zinc-800 disabled:text-zinc-400"
              >
                {running && (
                  <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                )}
                {running ? 'Scanning…' : 'Run full passive scan'}
              </button>

              {running && (
                <button
                  type="button"
                  onClick={cancelScan}
                  className="h-12 rounded-lg px-5 text-sm font-medium text-zinc-300 ring-1 ring-white/10 transition-colors ring-inset hover:bg-rose-500/10 hover:text-rose-300 hover:ring-rose-500/30"
                >
                  Cancel
                </button>
              )}
            </div>
          </form>

          {fatalError && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-3 rounded-lg bg-rose-500/10 px-4 py-3 text-sm text-rose-300 ring-1 ring-rose-500/20 ring-inset"
            >
              <AlertIcon className="mt-0.5 size-4 shrink-0" />
              {fatalError}
            </div>
          )}
        </section>

        {!report ? (
          <IntroPanels />
        ) : (
          <>
            <section className="grid gap-4 lg:grid-cols-3">
              <TargetCard report={report} completed={completed} running={running} />

              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:col-span-2">
                <StatTile
                  label="Findings"
                  value={findings.length}
                  tone={severe > 0 ? 'high' : 'default'}
                  hint={`${severe} high or worse`}
                />
                <StatTile
                  label="Hosts"
                  value={(subdomains?.subdomains.length ?? 0).toLocaleString()}
                  tone="accent"
                  hint="unique subdomains"
                />
                <StatTile
                  label="Live hosts"
                  value={(takeover?.live ?? 0).toLocaleString()}
                  hint={`${takeover?.checked ?? 0} resolved`}
                />
                <StatTile
                  label="URLs"
                  value={(modules?.archived.data?.urls.length ?? 0).toLocaleString()}
                  hint={`${urlIntel?.analyzed.toLocaleString() ?? 0} analysed`}
                />
                <StatTile
                  label="Parameters"
                  value={(urlIntel?.parameters.length ?? 0).toLocaleString()}
                  hint="unique names"
                />
                <StatTile
                  label="Secrets"
                  value={js?.secrets.length ?? 0}
                  tone={(js?.secrets.length ?? 0) > 0 ? 'critical' : 'default'}
                  hint="credential patterns"
                />
              </div>
            </section>

            <ModuleGroups report={report} onJump={jumpTo} />

            <section ref={resultsRef} className="scroll-mt-2">
              <div className="sticky top-0 z-20 -mx-4 mb-6 bg-zinc-950/80 px-4 py-3 backdrop-blur-md sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8">
                <TabBar
                  tabs={TABS.map((item) => ({ ...item, count: tabCounts[item.id] }))}
                  active={tab}
                  onChange={selectTab}
                />
              </div>

              <main role="tabpanel" className="pb-16">
                {tab === 'overview' && (
                  <OverviewTab
                    report={report}
                    findings={findings}
                    counts={counts}
                    onJump={jumpTo}
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
                {tab === 'dns' && (
                  <DnsTab state={report.modules.dns} data={report.modules.dns.data} />
                )}
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
            </section>
          </>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Summary cards                                                              */
/* -------------------------------------------------------------------------- */

function TargetCard({
  report,
  completed,
  running,
}: {
  report: ScanReport;
  completed: number;
  running: boolean;
}) {
  const status = running
    ? { label: 'Scanning', chip: 'bg-sky-500/10 text-sky-300 ring-sky-500/20', dot: 'bg-sky-400 animate-pulse' }
    : report.finishedAt
      ? { label: 'Complete', chip: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20', dot: 'bg-emerald-400' }
      : { label: 'Incomplete', chip: 'bg-amber-500/10 text-amber-300 ring-amber-500/20', dot: 'bg-amber-400' };

  const started = new Date(report.startedAt).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });

  return (
    <div className={cx(CARD, 'flex flex-col p-6')}>
      <div className="flex items-center justify-between gap-3">
        <p className={LABEL}>Target</p>
        <span
          className={cx(
            'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset',
            status.chip,
          )}
        >
          <span className={cx('size-1.5 rounded-full', status.dot)} />
          {status.label}
        </span>
      </div>

      <p className="mt-3 font-mono text-2xl font-semibold tracking-tight break-all text-zinc-50">
        {report.domain}
      </p>

      <dl className="mt-6 grid grid-cols-3 gap-4">
        <div>
          <dt className={LABEL}>Modules</dt>
          <dd className="mt-1.5 text-lg font-semibold text-zinc-100 tabular-nums">
            {completed}
            <span className="text-zinc-500">/{MODULE_IDS.length}</span>
          </dd>
        </div>
        <div>
          <dt className={LABEL}>Duration</dt>
          <dd className="mt-1.5 text-lg font-semibold text-zinc-100 tabular-nums">
            {report.durationMs !== null ? formatDuration(report.durationMs) : '—'}
          </dd>
        </div>
        <div>
          <dt className={LABEL}>Started</dt>
          <dd className="mt-1.5 text-lg font-semibold text-zinc-100 tabular-nums">{started}</dd>
        </div>
      </dl>

      <div className="mt-auto pt-6">
        <div
          role="progressbar"
          aria-label="Modules completed"
          aria-valuemin={0}
          aria-valuemax={MODULE_IDS.length}
          aria-valuenow={completed}
          className="h-1.5 overflow-hidden rounded-full bg-white/5"
        >
          <div
            className="h-full rounded-full bg-emerald-400/80 transition-[width] duration-500"
            style={{ width: `${(completed / MODULE_IDS.length) * 100}%` }}
          />
        </div>
      </div>
    </div>
  );
}

function ModuleGroups({
  report,
  onJump,
}: {
  report: ScanReport;
  onJump: (id: ModuleId) => void;
}) {
  return (
    <section className="grid gap-4 lg:grid-cols-3">
      {MODULE_GROUPS.map((group) => {
        const settled = group.modules.filter((id) => isSettled(report.modules[id])).length;

        return (
          <div key={group.label} className={cx(CARD, 'p-5')}>
            <div className="mb-3 flex items-center justify-between">
              <h2 className={LABEL}>{group.label}</h2>
              <span className="text-xs text-zinc-500 tabular-nums">
                {settled}/{group.modules.length}
              </span>
            </div>

            <ul className="-mx-2 space-y-0.5">
              {group.modules.map((id) => {
                const state = report.modules[id];
                return (
                  <li key={id}>
                    <button
                      type="button"
                      onClick={() => onJump(id)}
                      className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-white/5"
                    >
                      <StatusDot status={state.status} />
                      <span className="text-sm text-zinc-200">{MODULE_LABELS[id]}</span>
                      <span className="ml-auto shrink-0 text-xs tabular-nums">
                        {state.status === 'done' && (
                          <span className="text-zinc-500">{formatDuration(state.durationMs)}</span>
                        )}
                        {state.status === 'running' && (
                          <span className="text-emerald-400">Running</span>
                        )}
                        {state.status === 'error' && <span className="text-rose-400">Failed</span>}
                        {state.status === 'pending' && <span className="text-zinc-600">Queued</span>}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Static sections                                                            */
/* -------------------------------------------------------------------------- */

function IntroPanels() {
  return (
    <div className="space-y-6">
      <Panel
        title="What one click does"
        subtitle="Every module runs in parallel and streams its result as it lands."
      >
        <div className="grid gap-6 lg:grid-cols-3">
          {MODULE_GROUPS.map((group) => (
            <div key={group.label}>
              <h4 className={cx(LABEL, 'mb-3')}>{group.label}</h4>
              <ul className="space-y-3">
                {group.modules.map((id) => (
                  <li key={id} className={cx(INSET, 'p-4')}>
                    <p className="text-sm font-medium text-zinc-100">{MODULE_LABELS[id]}</p>
                    <p className="mt-1 text-xs leading-relaxed text-zinc-400">
                      {MODULE_DESCRIPTIONS[id]}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Passive means passive">
        <ul className="space-y-4 text-sm leading-relaxed text-zinc-400">
          <li className="flex gap-3">
            <CheckMark ok />
            <p>
              <span className="font-medium text-zinc-100">OSINT indexes</span> are queried for
              data they already hold — certificate transparency, passive DNS, web archives, RDAP.
            </p>
          </li>
          <li className="flex gap-3">
            <CheckMark ok />
            <p>
              <span className="font-medium text-zinc-100">DNS resolution</span> covers the apex
              and a capped sweep of discovered hosts. These are ordinary recursive lookups, the
              same ones a browser makes before opening any connection.
            </p>
          </li>
          <li className="flex gap-3">
            <CheckMark ok />
            <p>
              <span className="font-medium text-zinc-100">The target</span> receives one homepage
              GET, the same-origin scripts it advertises, and a short fixed list of published
              files (robots.txt, sitemap, security.txt, favicon,{' '}
              <code className="font-mono text-[13px] text-zinc-300">/.well-known/*</code>). That
              is a browser&apos;s first visit — never a wordlist.
            </p>
          </li>
          <li className="flex gap-3">
            <CheckMark ok={false} />
            <p>
              <span className="font-medium text-rose-300">No</span> port scanning, directory
              brute-forcing or parameter fuzzing. Wordlists are exported for your own tooling,
              because you own the authorisation that makes active testing legal.
            </p>
          </li>
        </ul>
      </Panel>
    </div>
  );
}
