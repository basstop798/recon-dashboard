'use client';

/**
 * Operator-driven tabs: search dorks, OSINT pivot links and exports.
 *
 * Nothing in here runs automatically. These are the queries and downloads the
 * operator chooses to open, which keeps third-party lookups on their account
 * and their timeline instead of the server's.
 */

import type { DorkGroup, PivotGroup, ScanReport } from '@/lib/passive-recon/types';
import {
  buildReportBundle,
  collectWordlists,
  findingsToCsv,
  reportToMarkdown,
  reportToText,
} from '@/lib/passive-recon/report';

import { ArrowUpRightIcon, DownloadIcon } from './icons';
import { BUTTON_SECONDARY, CopyButton, INSET, Panel, cx } from './ui';

/** A nested card that lifts slightly on hover — dorks, pivots and exports. */
const TILE = cx(INSET, 'transition-colors hover:border-white/15 hover:bg-zinc-800/40');

export function DorksTab({ groups }: { groups: readonly DorkGroup[] }) {
  return (
    <div className="space-y-6">
      {groups.map((group) => (
        <Panel key={group.engine} title={group.engine} subtitle={group.description}>
          <div className="grid gap-3 lg:grid-cols-2">
            {group.dorks.map((dork) => (
              <div key={dork.query} className={cx(TILE, 'flex items-start gap-3 p-4')}>
                <a
                  href={dork.url}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="group min-w-0 flex-1"
                >
                  <span className="flex items-center gap-1.5 text-sm font-medium text-zinc-100 group-hover:text-white">
                    {dork.label}
                    <ArrowUpRightIcon className="size-3.5 shrink-0 text-zinc-500 transition-colors group-hover:text-zinc-300" />
                  </span>
                  <code className="mt-1.5 block font-mono text-xs break-all text-zinc-500">
                    {dork.query}
                  </code>
                </a>
                <CopyButton text={dork.query} label="Copy query" />
              </div>
            ))}
          </div>
        </Panel>
      ))}
    </div>
  );
}

export function PivotsTab({ groups }: { groups: readonly PivotGroup[] }) {
  return (
    <div className="space-y-6">
      {groups.map((group) => (
        <Panel key={group.category} title={group.category}>
          <ul className="grid gap-3 lg:grid-cols-2">
            {group.links.map((link) => (
              <li key={link.url}>
                <a
                  href={link.url}
                  target="_blank"
                  // `noreferrer` keeps the target under research out of every
                  // pivot site's referrer logs.
                  rel="noopener noreferrer nofollow"
                  className={cx(TILE, 'group block h-full p-4')}
                >
                  <span className="flex items-center gap-1.5 text-sm font-medium text-zinc-100 group-hover:text-white">
                    {link.label}
                    <ArrowUpRightIcon className="size-3.5 shrink-0 text-zinc-500 transition-colors group-hover:text-zinc-300" />
                  </span>
                  <p className="mt-1.5 text-sm leading-relaxed text-zinc-400">{link.note}</p>
                </a>
              </li>
            ))}
          </ul>
        </Panel>
      ))}
    </div>
  );
}

/** Triggers a client-side download without a round trip to the server. */
function download(contents: string, filename: string, type: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function ExportButton({
  label,
  hint,
  filename,
  onClick,
}: {
  label: string;
  hint: string;
  filename: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx(TILE, 'group flex flex-col items-start p-5 text-left')}
    >
      <span className="flex w-full items-center justify-between gap-3">
        <span className="text-sm font-semibold text-zinc-100">{label}</span>
        <DownloadIcon className="size-4 text-zinc-500 transition-colors group-hover:text-emerald-400" />
      </span>
      <span className="mt-1.5 text-sm text-zinc-400">{hint}</span>
      <span className="mt-3 font-mono text-xs break-all text-zinc-500">{filename}</span>
    </button>
  );
}

export function ExportTab({ report }: { report: ScanReport }) {
  const bundle = buildReportBundle(report);
  const wordlists = collectWordlists(report);
  const stem = `bulletrecon-${report.domain}`;

  const lists: ReadonlyArray<{ name: keyof typeof wordlists; label: string; hint: string }> = [
    { name: 'hosts', label: 'hosts.txt', hint: 'Every in-scope hostname discovered, one per line.' },
    { name: 'urls', label: 'urls.txt', hint: 'Archived and sitemap URLs — feed to your own tooling.' },
    { name: 'parameters', label: 'params.txt', hint: 'Parameter names seen in real URLs.' },
    { name: 'endpoints', label: 'endpoints.txt', hint: 'Endpoint candidates mined from JavaScript.' },
  ];

  return (
    <div className="space-y-6">
      <Panel title="Reports" subtitle="Everything the scan produced, plus the derived findings.">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <ExportButton
            label="JSON"
            hint="Full machine-readable bundle."
            filename={`${stem}.json`}
            onClick={() =>
              download(JSON.stringify(bundle, null, 2), `${stem}.json`, 'application/json')
            }
          />
          <ExportButton
            label="Markdown"
            hint="Write-up ready, with a findings table."
            filename={`${stem}.md`}
            onClick={() => download(reportToMarkdown(bundle), `${stem}.md`, 'text/markdown')}
          />
          <ExportButton
            label="Text"
            hint="Terminal-friendly transcript."
            filename={`${stem}.txt`}
            onClick={() => download(reportToText(bundle), `${stem}.txt`, 'text/plain')}
          />
          <ExportButton
            label="CSV"
            hint="Findings only, for a tracker import."
            filename={`${stem}-findings.csv`}
            onClick={() => download(findingsToCsv(bundle.findings), `${stem}-findings.csv`, 'text/csv')}
          />
        </div>
      </Panel>

      <Panel
        title="Wordlists"
        subtitle="This dashboard never sends traffic at a target. Exporting the list is the handoff point — you own the decision to test, and the authorisation that makes it legal."
      >
        <div className="grid gap-3 sm:grid-cols-2">
          {lists.map((list) => {
            const items = wordlists[list.name];
            return (
              <div key={list.name} className={cx(INSET, 'flex items-center gap-4 px-5 py-4')}>
                <div className="min-w-0 flex-1">
                  <p className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-mono text-sm font-semibold text-zinc-100">
                      {list.label}
                    </span>
                    <span className="text-xs text-zinc-500 tabular-nums">
                      {items.length.toLocaleString()} lines
                    </span>
                  </p>
                  <p className="mt-1 text-sm text-zinc-400">{list.hint}</p>
                </div>
                <CopyButton size="md" text={() => items.join('\n')} />
                <button
                  type="button"
                  disabled={items.length === 0}
                  onClick={() =>
                    download(items.join('\n'), `${stem}-${list.label}`, 'text/plain')
                  }
                  className={BUTTON_SECONDARY}
                >
                  <DownloadIcon className="size-3.5" />
                  Save
                </button>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}
