'use client';

/**
 * The findings feed — the first thing an operator should read after a scan.
 *
 * Ten modules produce a lot of true, uninteresting data; this answers "what
 * here is worth my next hour?" and links each answer back to the tab holding
 * the raw evidence.
 */

import { useMemo, useState } from 'react';

import {
  MODULE_LABELS,
  SEVERITIES,
  type Finding,
  type ModuleId,
  type ScanReport,
  type Severity,
} from '@/lib/passive-recon/types';

import { ArrowRightIcon } from './icons';
import {
  CopyButton,
  DataList,
  DataRow,
  FilterChip,
  INSET,
  Panel,
  SEVERITY_STYLES,
  SeverityBadge,
  cx,
} from './ui';

export function OverviewTab({
  report,
  findings,
  counts,
  onJump,
  running,
}: {
  report: ScanReport;
  findings: readonly Finding[];
  counts: Record<Severity, number>;
  onJump: (module: ModuleId) => void;
  running: boolean;
}) {
  const [filter, setFilter] = useState<Severity | null>(null);

  const visible = useMemo(
    () => (filter ? findings.filter((finding) => finding.severity === filter) : findings),
    [findings, filter],
  );

  const errored = Object.entries(report.modules).filter(
    ([, state]) => state.status === 'error',
  ) as Array<[ModuleId, ScanReport['modules'][ModuleId]]>;

  return (
    <div className="space-y-6">
      <Panel
        title={`${findings.length} finding${findings.length === 1 ? '' : 's'}`}
        subtitle="Derived from module output. Everything here is a lead to verify — nothing was actively tested."
        action={
          findings.length > 0 && (
            <CopyButton
              size="md"
              label="Copy summary"
              text={() =>
                findings
                  .map((finding) => `[${finding.severity.toUpperCase()}] ${finding.title} — ${finding.detail}`)
                  .join('\n')
              }
            />
          )
        }
      >
        <div className="mb-5 flex flex-wrap gap-2" role="group" aria-label="Filter by severity">
          <FilterChip active={filter === null} onClick={() => setFilter(null)} count={findings.length}>
            All
          </FilterChip>
          {SEVERITIES.map((severity) => (
            <FilterChip
              key={severity}
              active={filter === severity}
              disabled={counts[severity] === 0}
              onClick={() => setFilter(severity)}
              count={counts[severity]}
              activeClassName={SEVERITY_STYLES[severity].chip}
            >
              <span className="capitalize">{severity}</span>
            </FilterChip>
          ))}
        </div>

        {visible.length === 0 ? (
          <p className="py-10 text-center text-sm text-zinc-400">
            {running
              ? 'Modules are still reporting — findings appear as their data lands.'
              : findings.length === 0
                ? 'No findings were derived. That is a good sign for the target, not a failed scan — the raw data is still in every other tab.'
                : 'No findings at this severity.'}
          </p>
        ) : (
          <ul className="space-y-3">
            {visible.map((finding) => (
              <li
                key={finding.id}
                className={cx(INSET, 'p-4 transition-colors hover:border-white/10')}
              >
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <SeverityBadge severity={finding.severity} />
                  <h4 className="text-sm font-semibold text-zinc-100">{finding.title}</h4>
                  <button
                    type="button"
                    onClick={() => onJump(finding.module)}
                    className="ml-auto inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-zinc-400 transition-colors hover:bg-white/5 hover:text-zinc-100"
                  >
                    {MODULE_LABELS[finding.module]}
                    <ArrowRightIcon className="size-3.5" />
                  </button>
                </div>
                <p className="mt-2 text-sm leading-relaxed text-zinc-400">{finding.detail}</p>
                {finding.evidence && (
                  <pre className="mt-3 max-h-32 overflow-auto rounded-md bg-zinc-950 p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-zinc-400 ring-1 ring-white/5 ring-inset">
                    {finding.evidence}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {errored.length > 0 && (
        <Panel
          title="Degraded modules"
          subtitle="One dead upstream never aborts a scan — these modules reported nothing usable."
        >
          <DataList>
            {errored.map(([id, state]) => (
              <DataRow key={id} className="flex-wrap gap-y-1">
                <span className="text-sm font-medium text-rose-300">{MODULE_LABELS[id]}</span>
                <span className="text-sm text-zinc-400">{state.error}</span>
              </DataRow>
            ))}
          </DataList>
        </Panel>
      )}
    </div>
  );
}
