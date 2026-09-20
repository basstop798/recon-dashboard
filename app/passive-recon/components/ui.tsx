'use client';

/**
 * Presentational primitives shared by every tab.
 *
 * Kept in one file because they are small, purely visual and only meaningful
 * together — the point is that ten very different datasets render as one
 * interface instead of ten bespoke tables.
 *
 * Typography rule: interface text is sans-serif; monospace is reserved for
 * technical values an operator reads character by character or copies — hosts,
 * URLs, IPs, hashes, header and record values.
 */

import { Children, useCallback, useState, type ReactNode } from 'react';

import {
  type ModuleState,
  type Severity,
  type SourceStat,
} from '@/lib/passive-recon/types';

import { AlertIcon, CheckIcon, CopyIcon, SearchIcon, XIcon } from './icons';

export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ');
}

/* -------------------------------------------------------------------------- */
/* Shared class recipes                                                       */
/* -------------------------------------------------------------------------- */

/** Small, uppercase, widely tracked — every field and column label. */
export const LABEL = 'text-xs font-medium tracking-wider text-zinc-400 uppercase';

/** Technical values: slightly under body size, since monospace sets wide. */
export const MONO = 'font-mono text-[13px]';

export const CARD = 'rounded-xl border border-white/10 bg-zinc-900 shadow-lg shadow-black/20';

/** An item nested inside a card: one step darker, one step quieter. */
export const INSET = 'rounded-lg border border-white/5 bg-zinc-950/40';

export const BUTTON_SECONDARY =
  'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5 text-xs font-medium text-zinc-300 ring-1 ring-white/10 ring-inset transition-colors hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-40';

/* -------------------------------------------------------------------------- */
/* Severity                                                                   */
/* -------------------------------------------------------------------------- */

/** `chip` pairs with `ring-1 ring-inset`; `text` is for standalone values. */
export const SEVERITY_STYLES: Record<Severity, { chip: string; dot: string; text: string }> = {
  critical: {
    chip: 'bg-rose-500/10 text-rose-300 ring-rose-500/25',
    dot: 'bg-rose-500',
    text: 'text-rose-400',
  },
  high: {
    chip: 'bg-orange-500/10 text-orange-300 ring-orange-500/25',
    dot: 'bg-orange-400',
    text: 'text-orange-400',
  },
  medium: {
    chip: 'bg-amber-500/10 text-amber-300 ring-amber-500/25',
    dot: 'bg-amber-400',
    text: 'text-amber-400',
  },
  low: {
    chip: 'bg-sky-500/10 text-sky-300 ring-sky-500/25',
    dot: 'bg-sky-400',
    text: 'text-sky-400',
  },
  info: {
    chip: 'bg-zinc-500/10 text-zinc-300 ring-zinc-500/25',
    dot: 'bg-zinc-500',
    text: 'text-zinc-300',
  },
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
    <section className={cx(CARD, className)}>
      {(title || action) && (
        <header className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3 border-b border-white/5 px-5 py-5 sm:px-6">
          <div className="min-w-0">
            {title && (
              <h3 className="text-base font-semibold tracking-tight text-zinc-50">{title}</h3>
            )}
            {subtitle && (
              <p className="mt-1 text-sm leading-relaxed text-zinc-400">{subtitle}</p>
            )}
          </div>
          {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
        </header>
      )}
      <div className="p-5 sm:p-6">{children}</div>
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
      ? 'text-zinc-50'
      : tone === 'accent'
        ? 'text-emerald-400'
        : SEVERITY_STYLES[tone].text;

  return (
    <div className={cx(CARD, 'p-5')}>
      <p className={LABEL}>{label}</p>
      <p
        className={cx(
          'mt-3 text-3xl leading-none font-bold tracking-tight tabular-nums',
          toneClass,
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-2.5 truncate text-sm text-zinc-500">{hint}</p>}
    </div>
  );
}

export function Pill({
  children,
  tone = 'neutral',
  mono = false,
  title,
}: {
  children: ReactNode;
  tone?: 'neutral' | 'accent';
  /** Set for technical values (hostnames, EPP codes, MIME types). */
  mono?: boolean;
  title?: string;
}) {
  const tones = {
    neutral: 'bg-zinc-800 text-zinc-300 ring-white/10',
    accent: 'bg-indigo-500/10 text-indigo-300 ring-indigo-500/20',
  } as const;

  return (
    <span
      title={title}
      className={cx(
        'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs ring-1 ring-inset',
        mono ? 'font-mono' : 'font-medium',
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
  rows: ReadonlyArray<{ key: string; value: ReactNode; mono?: boolean } | null>;
}) {
  const visible = rows.filter(
    (row): row is { key: string; value: ReactNode; mono?: boolean } => row !== null,
  );

  return (
    <dl className="divide-y divide-white/5">
      {visible.map((row, index) => (
        <div
          key={`${row.key}-${index}`}
          className="grid grid-cols-1 gap-1.5 py-3 first:pt-0 last:pb-0 sm:grid-cols-[180px_1fr] sm:gap-6"
        >
          <dt className={cx(LABEL, 'sm:pt-0.5')}>{row.key}</dt>
          <dd
            className={cx(
              'min-w-0 text-zinc-200',
              row.mono ? cx(MONO, 'break-all') : 'text-sm wrap-break-word',
            )}
          >
            {row.value}
          </dd>
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
      className="text-zinc-100 underline decoration-zinc-600 underline-offset-4 transition-colors hover:text-white hover:decoration-zinc-300"
    >
      {children}
    </a>
  );
}

/* -------------------------------------------------------------------------- */
/* Data lists and tables                                                      */
/* -------------------------------------------------------------------------- */

const ROW = 'transition-colors even:bg-zinc-800/40 hover:bg-zinc-800/70';

/** A bordered list with zebra rows. Renders nothing when empty. */
export function DataList({
  children,
  maxHeight,
}: {
  children: ReactNode;
  /** A `max-h-*` class; the list scrolls inside it instead of growing. */
  maxHeight?: string;
}) {
  if (Children.count(children) === 0) return null;

  return (
    <ul
      className={cx(
        'rounded-lg border border-white/5',
        maxHeight ? cx('overflow-y-auto', maxHeight) : 'overflow-hidden',
      )}
    >
      {children}
    </ul>
  );
}

export function DataRow({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <li className={cx('flex items-center gap-3 px-4 py-2.5', ROW, className)}>{children}</li>
  );
}

export function DataTable({
  columns,
  children,
  maxHeight,
}: {
  columns: readonly string[];
  children: ReactNode;
  /** A `max-h-*` class; the header stays pinned while the body scrolls. */
  maxHeight?: string;
}) {
  return (
    <div className={cx('overflow-auto rounded-lg border border-white/5', maxHeight)}>
      <table className="w-full text-left">
        <thead className="sticky top-0 z-10 bg-zinc-900 shadow-[inset_0_-1px_0_rgb(255_255_255/0.08)]">
          <tr>
            {columns.map((column) => (
              <th key={column} scope="col" className={cx(LABEL, 'px-4 py-3 whitespace-nowrap')}>
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Tr({ children }: { children: ReactNode }) {
  return <tr className={cx('align-top text-zinc-300', ROW)}>{children}</tr>;
}

export function Td({
  children,
  mono = false,
  className,
}: {
  children: ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <td className={cx('px-4 py-3', mono ? MONO : 'text-sm', className)}>{children}</td>
  );
}

/** A value-free check or cross, for pass/fail rows. */
export function CheckMark({ ok }: { ok: boolean }) {
  return (
    <span
      className={cx(
        'inline-flex size-6 shrink-0 items-center justify-center rounded-full ring-1 ring-inset',
        ok
          ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20'
          : 'bg-rose-500/10 text-rose-400 ring-rose-500/20',
      )}
    >
      {ok ? <CheckIcon className="size-3.5" /> : <XIcon className="size-3.5" />}
      <span className="sr-only">{ok ? 'pass' : 'fail'}</span>
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Status                                                                     */
/* -------------------------------------------------------------------------- */

export function StatusDot({ status }: { status: ModuleState['status'] }) {
  if (status === 'running') {
    return (
      <span
        role="img"
        aria-label="running"
        className="inline-block size-2.5 shrink-0 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent"
      />
    );
  }

  const styles: Record<Exclude<ModuleState['status'], 'running'>, string> = {
    pending: 'bg-zinc-600',
    done: 'bg-emerald-400',
    error: 'bg-rose-500',
  };

  return (
    <span
      role="img"
      aria-label={status}
      className={cx('inline-block size-2.5 shrink-0 rounded-full', styles[status])}
    />
  );
}

export function SourceStats({ sources }: { sources: readonly SourceStat[] }) {
  if (sources.length === 0) return null;

  return (
    <div className="mb-5 flex flex-wrap gap-2">
      {sources.map((source) => (
        <span
          key={source.source}
          title={source.error ?? `${source.count} result(s)`}
          className={cx(
            'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset',
            source.ok
              ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20'
              : 'bg-rose-500/10 text-rose-300 ring-rose-500/20',
          )}
        >
          <span
            className={cx('size-1.5 rounded-full', source.ok ? 'bg-emerald-400' : 'bg-rose-400')}
          />
          {source.source}
          <span className="text-zinc-400 tabular-nums">
            {source.ok ? source.count.toLocaleString() : 'failed'}
          </span>
        </span>
      ))}
    </div>
  );
}

export function EmptyState({ state, label }: { state: ModuleState; label: string }) {
  if (state.status === 'error') {
    return (
      <div className="flex items-start gap-3 rounded-lg bg-rose-500/10 p-4 text-sm text-rose-300 ring-1 ring-rose-500/20 ring-inset">
        <AlertIcon className="mt-0.5 size-4 shrink-0" />
        <p>
          <span className="font-medium">{label} failed:</span> {state.error}
        </p>
      </div>
    );
  }
  if (state.status === 'running') {
    return (
      <p className="flex items-center justify-center gap-3 py-10 text-sm text-zinc-400">
        <StatusDot status="running" /> Collecting {label.toLowerCase()}…
      </p>
    );
  }
  if (state.status === 'pending') {
    return (
      <p className="py-10 text-center text-sm text-zinc-500">
        Waiting for the scan to reach this module.
      </p>
    );
  }
  return <p className="py-10 text-center text-sm text-zinc-500">No results.</p>;
}

/** A small amber note under a list, for upstream caps and partial data. */
export function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="mt-4 flex items-center justify-center gap-2 text-center text-xs text-amber-300/80">
      <AlertIcon className="size-3.5 shrink-0" />
      {children}
    </p>
  );
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
    <div className="relative">
      <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-zinc-500" />
      <input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="w-full rounded-lg bg-zinc-950/60 py-2.5 pr-3 pl-9 text-sm text-zinc-100 ring-1 ring-white/10 transition-shadow ring-inset placeholder:text-zinc-500 focus:ring-2 focus:ring-emerald-500/50 focus:outline-none"
      />
    </div>
  );
}

/** A rounded toggle chip, for filters that narrow a list to one category. */
export function FilterChip({
  active,
  onClick,
  count,
  disabled = false,
  activeClassName = 'bg-zinc-100 text-zinc-900 ring-zinc-100',
  children,
}: {
  active: boolean;
  onClick: () => void;
  count?: number;
  disabled?: boolean;
  /** Background, text and ring colours for the selected state. */
  activeClassName?: string;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      disabled={disabled}
      onClick={onClick}
      className={cx(
        'inline-flex items-center gap-2 rounded-full px-3.5 py-1.5 text-sm font-medium ring-1 ring-inset transition-colors disabled:cursor-not-allowed disabled:opacity-40',
        active
          ? activeClassName
          : 'bg-white/5 text-zinc-400 ring-white/10 enabled:hover:bg-white/10 enabled:hover:text-zinc-100',
      )}
    >
      {children}
      {count !== undefined && (
        <span className={cx('text-xs tabular-nums', active ? 'opacity-70' : 'text-zinc-500')}>
          {count.toLocaleString()}
        </span>
      )}
    </button>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
}) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2.5 text-sm text-zinc-300 select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="peer sr-only"
      />
      <span
        aria-hidden
        className="relative h-5 w-9 rounded-full bg-zinc-700 transition-colors peer-checked:bg-emerald-500/80 peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-emerald-400 after:absolute after:top-0.5 after:left-0.5 after:size-4 after:rounded-full after:bg-white after:shadow after:transition-transform peer-checked:after:translate-x-4"
      />
      {label}
    </label>
  );
}

/**
 * Copies text to the clipboard and confirms it inline.
 *
 * `sm` is an icon-only button for per-row use; `md` carries its label and sits
 * in panel headers.
 */
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

  const icon = copied ? (
    <CheckIcon className="size-3.5 text-emerald-400" />
  ) : (
    <CopyIcon className="size-3.5" />
  );

  if (size === 'sm') {
    return (
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? 'Copied' : label}
        title={copied ? 'Copied' : label}
        className="inline-flex size-7 shrink-0 items-center justify-center rounded-md text-zinc-500 transition-colors hover:bg-white/10 hover:text-zinc-100"
      >
        {icon}
      </button>
    );
  }

  return (
    <button type="button" onClick={copy} className={BUTTON_SECONDARY}>
      {icon}
      {copied ? 'Copied' : label}
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
      <p className="pt-4 text-center text-xs text-zinc-500 tabular-nums">
        {total.toLocaleString()} {noun}
      </p>
    );
  }

  return (
    <div className="pt-4 text-center">
      <button type="button" onClick={onMore} className={cx(BUTTON_SECONDARY, 'px-4 py-2 text-sm')}>
        Show more
        <span className="text-zinc-500 tabular-nums">
          · {visible.toLocaleString()} of {total.toLocaleString()} {noun}
        </span>
      </button>
    </div>
  );
}

/** A zebra-striped, monospaced list of URLs or paths. */
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
    <DataList>
      {urls.slice(0, visible).map((url) => (
        <DataRow key={url}>
          {linkify && /^https?:\/\//.test(url) ? (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className={cx(
                MONO,
                'min-w-0 flex-1 break-all text-zinc-300 decoration-zinc-500 underline-offset-4 transition-colors hover:text-white hover:underline',
              )}
            >
              {url}
            </a>
          ) : (
            <span className={cx(MONO, 'min-w-0 flex-1 break-all text-zinc-300')}>{url}</span>
          )}
          <CopyButton text={url} />
        </DataRow>
      ))}
    </DataList>
  );
}
