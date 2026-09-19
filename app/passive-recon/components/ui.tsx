'use client';

/**
 * Presentational primitives shared by every tab.
 *
 * Kept in one file because they are small, purely visual and only meaningful
 * together — the point is that ten very different datasets render as one
 * interface instead of ten bespoke tables.
 */

import { useCallback, useState, type ReactNode } from 'react';

import {
  type ModuleState,
  type Severity,
  type SourceStat,
} from '@/lib/passive-recon/types';

export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ');
}

/* -------------------------------------------------------------------------- */
/* Severity                                                                   */
/* -------------------------------------------------------------------------- */

export const SEVERITY_STYLES: Record<Severity, { chip: string; dot: string; text: string }> = {
  critical: {
    chip: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
    dot: 'bg-rose-500',
    text: 'text-rose-300',
  },
  high: {
    chip: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    dot: 'bg-orange-500',
    text: 'text-orange-300',
  },
  medium: {
    chip: 'border-amber-400/40 bg-amber-400/10 text-amber-200',
    dot: 'bg-amber-400',
    text: 'text-amber-200',
  },
  low: {
    chip: 'border-sky-400/40 bg-sky-400/10 text-sky-300',
    dot: 'bg-sky-400',
    text: 'text-sky-300',
  },
  info: {
    chip: 'border-zinc-600/60 bg-zinc-700/20 text-zinc-300',
    dot: 'bg-zinc-500',
    text: 'text-zinc-300',
  },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cx(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] tracking-wide uppercase',
        SEVERITY_STYLES[severity].chip,
      )}
    >
      <span className={cx('h-1.5 w-1.5 rounded-full', SEVERITY_STYLES[severity].dot)} />
      {severity}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Layout                                                                     */
/* -------------------------------------------------------------------------- */

export function Panel({
  title,
  subtitle,
  action,
  children,
  className,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cx(
        'rounded-xl border border-white/8 bg-zinc-900/40 backdrop-blur-sm',
        className,
      )}
    >
      {(title || action) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-white/5 px-4 py-3">
          <div className="min-w-0">
            {title && <h3 className="text-sm font-semibold text-zinc-100">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-zinc-500">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = 'default',
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: 'default' | 'accent' | Severity;
}) {
  const toneClass =
    tone === 'default'
      ? 'text-zinc-100'
      : tone === 'accent'
        ? 'text-emerald-300'
        : SEVERITY_STYLES[tone].text;

  return (
    <div className="rounded-xl border border-white/8 bg-zinc-900/40 px-4 py-3">
      <p className="text-[11px] font-medium tracking-wider text-zinc-500 uppercase">{label}</p>
      <p className={cx('mt-1 font-mono text-2xl leading-none font-semibold', toneClass)}>
        {value}
      </p>
      {hint && <p className="mt-1.5 truncate text-[11px] text-zinc-600">{hint}</p>}
    </div>
  );
}

export function Pill({
  children,
  tone = 'neutral',
  title,
}: {
  children: ReactNode;
  tone?: 'neutral' | 'good' | 'bad' | 'accent';
  title?: string;
}) {
  const tones = {
    neutral: 'border-white/10 bg-white/5 text-zinc-300',
    good: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    bad: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
    accent: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300',
  } as const;

  return (
    <span
      title={title}
      className={cx(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs',
        tones[tone],
      )}
    >
      {children}
    </span>
  );
}

/** A definition list that keeps long values readable and copyable. */
export function KeyValue({
  rows,
}: {
  rows: ReadonlyArray<{ key: string; value: ReactNode } | null>;
}) {
  const visible = rows.filter((row): row is { key: string; value: ReactNode } => row !== null);

  return (
    <dl className="divide-y divide-white/5">
      {visible.map((row) => (
        <div key={row.key} className="grid grid-cols-1 gap-1 py-2 sm:grid-cols-[180px_1fr] sm:gap-4">
          <dt className="font-mono text-xs text-zinc-500">{row.key}</dt>
          <dd className="font-mono text-xs break-all text-zinc-200">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      // `noreferrer` matters here: the referrer would otherwise announce which
      // target the operator is researching to every site they open.
      rel="noopener noreferrer nofollow"
      className="text-emerald-300 underline-offset-2 hover:underline"
    >
      {children}
    </a>
  );
}

/* -------------------------------------------------------------------------- */
/* Status                                                                     */
/* -------------------------------------------------------------------------- */

export function StatusDot({ status }: { status: ModuleState['status'] }) {
  if (status === 'running') {
    return (
      <span
        aria-label="running"
        className="inline-block h-2.5 w-2.5 shrink-0 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent"
      />
    );
  }

  const styles: Record<Exclude<ModuleState['status'], 'running'>, string> = {
    pending: 'bg-zinc-700',
    done: 'bg-emerald-400',
    error: 'bg-rose-500',
  };

  return (
    <span
      aria-label={status}
      className={cx('inline-block h-2.5 w-2.5 shrink-0 rounded-full', styles[status])}
    />
  );
}

export function SourceStats({ sources }: { sources: readonly SourceStat[] }) {
  if (sources.length === 0) return null;

  return (
    <div className="mb-4 flex flex-wrap gap-1.5">
      {sources.map((source) => (
        <span
          key={source.source}
          title={source.error ?? `${source.count} result(s)`}
          className={cx(
            'rounded-md border px-2 py-0.5 font-mono text-[11px]',
            source.ok
              ? 'border-emerald-500/25 bg-emerald-500/5 text-emerald-300/90'
              : 'border-rose-500/25 bg-rose-500/5 text-rose-300/90',
          )}
        >
          {source.source}
          <span className="ml-1 text-zinc-500">{source.ok ? source.count : 'failed'}</span>
        </span>
      ))}
    </div>
  );
}

export function EmptyState({ state, label }: { state: ModuleState; label: string }) {
  if (state.status === 'error') {
    return (
      <p className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-300">
        {label} failed: {state.error}
      </p>
    );
  }
  if (state.status === 'running') {
    return (
      <p className="flex items-center gap-2 p-4 text-sm text-zinc-400">
        <StatusDot status="running" /> Collecting {label.toLowerCase()}…
      </p>
    );
  }
  if (state.status === 'pending') {
    return <p className="p-4 text-sm text-zinc-500">Waiting for the scan to reach this module.</p>;
  }
  return <p className="p-4 text-sm text-zinc-500">No results.</p>;
}

/* -------------------------------------------------------------------------- */
/* Controls                                                                   */
/* -------------------------------------------------------------------------- */

export function FilterInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <input
      type="search"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      aria-label={placeholder}
      className="w-full rounded-lg border border-white/10 bg-black/30 px-3 py-2 font-mono text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/40 focus:outline-none"
    />
  );
}

/** Copies text to the clipboard and confirms it inline. */
export function CopyButton({
  text,
  label = 'Copy',
  size = 'sm',
}: {
  text: string | (() => string);
  label?: string;
  size?: 'sm' | 'md';
}) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    const value = typeof text === 'function' ? text() : text;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      // Reverting after two seconds keeps the button honest if the operator
      // copies something else in between.
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }, [text]);

  return (
    <button
      type="button"
      onClick={copy}
      className={cx(
        'shrink-0 rounded-md border border-white/10 bg-white/5 font-mono text-zinc-300 transition-colors hover:border-emerald-500/40 hover:text-emerald-300',
        size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-3 py-1.5 text-xs',
      )}
    >
      {copied ? 'copied ✓' : label}
    </button>
  );
}

/**
 * Caps how many rows reach the DOM, with an explicit "show more" step.
 *
 * A scan can return thousands of URLs; rendering them all makes the tab janky
 * for no benefit, and silently truncating would hide data the operator needs.
 */
export function useVisibleCount(step = 200): {
  visible: number;
  more: () => void;
  reset: () => void;
} {
  const [visible, setVisible] = useState(step);

  return {
    visible,
    more: useCallback(() => setVisible((current) => current + step), [step]),
    reset: useCallback(() => setVisible(step), [step]),
  };
}

export function ShowMore({
  total,
  visible,
  onMore,
  noun = 'rows',
}: {
  total: number;
  visible: number;
  onMore: () => void;
  noun?: string;
}) {
  if (total <= visible) {
    return (
      <p className="pt-3 text-center font-mono text-[11px] text-zinc-600">
        {total} {noun}
      </p>
    );
  }

  return (
    <div className="pt-3 text-center">
      <button
        type="button"
        onClick={onMore}
        className="rounded-lg border border-white/10 bg-white/5 px-4 py-1.5 font-mono text-xs text-zinc-300 transition-colors hover:border-emerald-500/40 hover:text-emerald-300"
      >
        Show more — {visible} of {total} {noun}
      </button>
    </div>
  );
}

/** A scrollable, monospaced list of URLs or paths. */
export function UrlList({
  urls,
  visible,
  linkify = true,
}: {
  urls: readonly string[];
  visible: number;
  linkify?: boolean;
}) {
  return (
    <ul className="divide-y divide-white/5">
      {urls.slice(0, visible).map((url) => (
        <li key={url} className="flex items-start gap-2 py-1.5">
          {linkify && /^https?:\/\//.test(url) ? (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="min-w-0 flex-1 font-mono text-xs break-all text-zinc-300 hover:text-emerald-300"
            >
              {url}
            </a>
          ) : (
            <span className="min-w-0 flex-1 font-mono text-xs break-all text-zinc-300">{url}</span>
          )}
          <CopyButton text={url} label="copy" />
        </li>
      ))}
    </ul>
  );
}
