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

import { CopyButton, Panel, SEVERITY_STYLES, SeverityBadge, cx } from './ui';

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
    <div className="space-y-4">
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
        <div className="mb-4 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setFilter(null)}
            className={cx(
              'rounded-lg border px-3 py-1 font-mono text-xs transition-colors',
              filter === null
                ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300'
                : 'border-white/10 bg-white/5 text-zinc-400 hover:text-zinc-200',
            )}
          >
            all <span className="ml-1 text-zinc-600">{findings.length}</span>
          </button>
          {SEVERITIES.map((severity) => (
            <button
              key={severity}
              type="button"
              disabled={counts[severity] === 0}
              onClick={() => setFilter(severity)}
              className={cx(
                'rounded-lg border px-3 py-1 font-mono text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-30',
                filter === severity
                  ? SEVERITY_STYLES[severity].chip
                  : 'border-white/10 bg-white/5 text-zinc-400 hover:text-zinc-200',
              )}
            >
              {severity} <span className="ml-1 text-zinc-600">{counts[severity]}</span>
            </button>
          ))}
        </div>

        {visible.length === 0 ? (
          <p className="p-4 text-sm text-zinc-500">
            {running
              ? 'Modules are still reporting — findings appear as their data lands.'
              : findings.length === 0
                ? 'No findings were derived. That is a good sign for the target, not a failed scan — the raw data is still in every other tab.'
                : 'No findings at this severity.'}
          </p>
        ) : (
          <ul className="space-y-2">
            {visible.map((finding) => (
              <li
                key={finding.id}
                className={cx(
                  'rounded-lg border-l-2 border-y border-r border-white/5 bg-black/20 p-3',
                  finding.severity === 'critical'
                    ? 'border-l-rose-500'
                    : finding.severity === 'high'
                      ? 'border-l-orange-500'
                      : finding.severity === 'medium'
                        ? 'border-l-amber-400'
                        : finding.severity === 'low'
                          ? 'border-l-sky-400'
                          : 'border-l-zinc-600',
                )}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <h4 className="text-sm font-semibold text-zinc-100">{finding.title}</h4>
                  <button
                    type="button"
                    onClick={() => onJump(finding.module)}
                    className="ml-auto rounded-md border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[11px] text-zinc-400 transition-colors hover:border-emerald-500/40 hover:text-emerald-300"
                  >
                    {MODULE_LABELS[finding.module]} →
                  </button>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">{finding.detail}</p>
                {finding.evidence && (
                  <pre className="mt-2 max-h-32 overflow-auto rounded bg-black/40 p-2 font-mono text-[11px] whitespace-pre-wrap text-zinc-500">
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
          <ul className="space-y-1.5">
            {errored.map(([id, state]) => (
              <li key={id} className="flex flex-wrap items-baseline gap-2 text-xs">
                <span className="font-mono text-rose-300">{MODULE_LABELS[id]}</span>
                <span className="text-zinc-500">{state.error}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
