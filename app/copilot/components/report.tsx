'use client';

/**
 * AI Security Co-pilot — presentational components.
 *
 * Reuses the BulletRecon visual language (severity palette, card recipes, mono
 * rule) so the co-pilot reads as one product with the dashboard rather than a
 * bolted-on demo. Kept dependency-light: no chart library, just Tailwind, so it
 * builds and renders identically online and offline (demo mode).
 */

import { useState } from 'react';

import type { Severity } from '@/lib/passive-recon/types';
import type { Assessment, CopilotReport } from '@/lib/ai/types';

export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ');
}

const CARD = 'rounded-xl border border-white/10 bg-zinc-900 shadow-lg shadow-black/20';
const INSET = 'rounded-lg border border-white/5 bg-zinc-950/40';
const LABEL = 'text-xs font-medium tracking-wider text-zinc-400 uppercase';

const SEVERITY_STYLES: Record<Severity, { chip: string; dot: string; text: string; bar: string }> = {
  critical: { chip: 'bg-rose-500/10 text-rose-300 ring-rose-500/25', dot: 'bg-rose-500', text: 'text-rose-400', bar: 'bg-rose-500' },
  high: { chip: 'bg-orange-500/10 text-orange-300 ring-orange-500/25', dot: 'bg-orange-400', text: 'text-orange-400', bar: 'bg-orange-400' },
  medium: { chip: 'bg-amber-500/10 text-amber-300 ring-amber-500/25', dot: 'bg-amber-400', text: 'text-amber-400', bar: 'bg-amber-400' },
  low: { chip: 'bg-sky-500/10 text-sky-300 ring-sky-500/25', dot: 'bg-sky-400', text: 'text-sky-400', bar: 'bg-sky-400' },
  info: { chip: 'bg-zinc-500/10 text-zinc-300 ring-zinc-500/25', dot: 'bg-zinc-500', text: 'text-zinc-300', bar: 'bg-zinc-500' },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cx(
        'inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold tracking-wider uppercase ring-1 ring-inset',
        SEVERITY_STYLES[severity].chip,
      )}
    >
      <span className={cx('size-1.5 rounded-full', SEVERITY_STYLES[severity].dot)} />
      {severity}
    </span>
  );
}

/** Risk score gauge, coloured by band. Non-expert reads the number + label. */
export function RiskScore({ score }: { score: number }) {
  const band: Severity =
    score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
  const label =
    score >= 75 ? 'Critical exposure' : score >= 50 ? 'High exposure' : score >= 25 ? 'Moderate exposure' : 'Low exposure';

  return (
    <div className={cx(CARD, 'p-6')}>
      <p className={LABEL}>Overall risk score</p>
      <div className="mt-4 flex items-end gap-3">
        <span className={cx('text-6xl font-bold leading-none tabular-nums', SEVERITY_STYLES[band].text)}>
          {score}
        </span>
        <span className="mb-1 text-lg text-zinc-500">/ 100</span>
      </div>
      <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-white/5">
        <div
          className={cx('h-full rounded-full transition-all duration-700', SEVERITY_STYLES[band].bar)}
          style={{ width: `${score}%` }}
        />
      </div>
      <p className={cx('mt-3 text-sm font-medium', SEVERITY_STYLES[band].text)}>{label}</p>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard blocked; no-op */
        }
      }}
      className="rounded-md bg-white/5 px-2 py-1 text-[11px] font-medium text-zinc-400 ring-1 ring-inset ring-white/10 transition-colors hover:bg-white/10 hover:text-white"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

/** One assessment card: plain-language impact + reviewed remediation steps. */
export function AssessmentCard({ assessment }: { assessment: Assessment }) {
  return (
    <article className={cx(CARD, 'overflow-hidden')}>
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-white/5 px-5 py-4">
        <div className="min-w-0">
          <h3 className="text-base font-semibold tracking-tight text-zinc-50">{assessment.title}</h3>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={assessment.severity} />
            {assessment.grounded ? (
              <span className="inline-flex items-center gap-1 rounded-md bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-300 ring-1 ring-inset ring-emerald-500/25">
                ✓ Grounded in advisory
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-md bg-zinc-500/10 px-2 py-0.5 text-[11px] font-medium text-zinc-400 ring-1 ring-inset ring-zinc-500/25">
                AI assessment (unverified)
              </span>
            )}
          </div>
        </div>
      </header>

      <div className="space-y-4 px-5 py-4">
        <div>
          <p className={LABEL}>What this means for your business</p>
          <p className="mt-1.5 text-sm leading-relaxed text-zinc-300">{assessment.businessImpact}</p>
        </div>

        <div>
          <p className={LABEL}>How to fix it</p>
          <ol className="mt-2 space-y-1.5">
            {assessment.remediation.map((step, i) => (
              <li key={i} className="flex gap-2.5 text-sm leading-relaxed text-zinc-300">
                <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-white/5 text-[11px] font-semibold text-zinc-400 ring-1 ring-inset ring-white/10">
                  {i + 1}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
          <p className="mt-3 rounded-md bg-amber-500/5 px-3 py-2 text-[12px] leading-relaxed text-amber-300/80 ring-1 ring-inset ring-amber-500/15">
            ⚠️ Review these steps with whoever manages the system before running anything. AI-suggested fixes require human oversight.
          </p>
        </div>

        {assessment.reference && (
          <div className="flex items-center justify-between gap-3 border-t border-white/5 pt-3">
            <a
              href={assessment.reference}
              target="_blank"
              rel="noopener noreferrer"
              className="truncate font-mono text-[12px] text-emerald-400/80 hover:text-emerald-300 hover:underline"
            >
              {assessment.reference}
            </a>
            <CopyButton text={assessment.reference} />
          </div>
        )}
      </div>
    </article>
  );
}

/** The redaction banner — the visible privacy moment for the demo. */
export function RedactionBanner({ total, counts }: { total: number; counts: Record<string, number> }) {
  if (total === 0) return null;
  const parts = Object.entries(counts).map(([k, v]) => `${v} ${k}`);
  return (
    <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-300">
      🛡️ Redacted <span className="font-semibold tabular-nums">{total}</span> sensitive value{total === 1 ? '' : 's'} before analysis
      <span className="text-emerald-300/60"> ({parts.join(', ')})</span> — internal IPs, hostnames and secrets never leave your browser unmasked.
    </div>
  );
}

/** Provider / grounding meta strip — the reliability + AI-quality story. */
export function ReportMeta({ report }: { report: CopilotReport }) {
  const { meta } = report;
  return (
    <div className={cx(INSET, 'flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 text-xs text-zinc-400')}>
      <span>
        Provider: <span className="font-medium text-zinc-200">{meta.provider}</span>
        {meta.usedFallback && <span className="ml-1 text-amber-400">(fallback engaged)</span>}
      </span>
      <span>
        Grounded: <span className="font-medium text-emerald-300 tabular-nums">{meta.groundedCount}/{meta.totalFindings}</span> findings cite a real advisory
      </span>
    </div>
  );
}
