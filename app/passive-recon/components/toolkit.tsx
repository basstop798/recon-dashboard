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

import { CopyButton, ExternalLink, Panel } from './ui';

export function DorksTab({ groups }: { groups: readonly DorkGroup[] }) {
  return (
    <div className="space-y-4">
      {groups.map((group) => (
        <Panel key={group.engine} title={group.engine} subtitle={group.description}>
          <div className="grid gap-2 lg:grid-cols-2">
            {group.dorks.map((dork) => (
              <div
                key={dork.query}
                className="group flex items-start gap-2 rounded-lg border border-white/5 bg-black/20 p-2.5 transition-colors hover:border-emerald-500/30"
              >
                <a
                  href={dork.url}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="min-w-0 flex-1"
                >
                  <span className="block text-xs font-medium text-emerald-300/90">
                    {dork.label}
                  </span>
                  <code className="mt-1 block font-mono text-[11px] break-all text-zinc-500">
                    {dork.query}
                  </code>
                </a>
                <CopyButton text={dork.query} label="copy" />
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
    <div className="space-y-4">
      {groups.map((group) => (
        <Panel key={group.category} title={group.category}>
          <ul className="grid gap-2 lg:grid-cols-2">
            {group.links.map((link) => (
              <li
                key={link.url}
                className="rounded-lg border border-white/5 bg-black/20 p-2.5 transition-colors hover:border-emerald-500/30"
              >
                <ExternalLink href={link.url}>
                  <span className="text-xs font-medium">{link.label}</span>
                </ExternalLink>
                <p className="mt-1 text-[11px] leading-relaxed text-zinc-500">{link.note}</p>
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
  onClick,
}: {
  label: string;
  hint: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col items-start rounded-lg border border-white/10 bg-white/5 px-4 py-3 text-left transition-colors hover:border-emerald-500/40 hover:bg-emerald-500/5"
    >
      <span className="font-mono text-sm font-semibold text-emerald-300">{label}</span>
      <span className="mt-1 text-[11px] text-zinc-500">{hint}</span>
    </button>
  );
}

export function ExportTab({ report }: { report: ScanReport }) {
  const bundle = buildReportBundle(report);
  const wordlists = collectWordlists(report);
  const stem = `passive-recon-${report.domain}`;

  const lists: ReadonlyArray<{ name: keyof typeof wordlists; label: string; hint: string }> = [
    { name: 'hosts', label: 'hosts.txt', hint: 'Every in-scope hostname discovered, one per line.' },
    { name: 'urls', label: 'urls.txt', hint: 'Archived and sitemap URLs — feed to your own tooling.' },
    { name: 'parameters', label: 'params.txt', hint: 'Parameter names seen in real URLs.' },
    { name: 'endpoints', label: 'endpoints.txt', hint: 'Endpoint candidates mined from JavaScript.' },
  ];

  return (
    <div className="space-y-4">
      <Panel title="Reports" subtitle="Everything the scan produced, plus the derived findings.">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <ExportButton
            label="JSON"
            hint="Full machine-readable bundle."
            onClick={() =>
              download(JSON.stringify(bundle, null, 2), `${stem}.json`, 'application/json')
            }
          />
          <ExportButton
            label="Markdown"
            hint="Write-up ready, with a findings table."
            onClick={() => download(reportToMarkdown(bundle), `${stem}.md`, 'text/markdown')}
          />
          <ExportButton
            label="Text"
            hint="Terminal-friendly transcript."
            onClick={() => download(reportToText(bundle), `${stem}.txt`, 'text/plain')}
          />
          <ExportButton
            label="CSV"
            hint="Findings only, for a tracker import."
            onClick={() => download(findingsToCsv(bundle.findings), `${stem}-findings.csv`, 'text/csv')}
          />
        </div>
      </Panel>

      <Panel
        title="Wordlists"
        subtitle="This dashboard never sends traffic at a target. Exporting the list is the handoff point — you own the decision to test, and the authorisation that makes it legal."
      >
        <div className="grid gap-2 sm:grid-cols-2">
          {lists.map((list) => {
            const items = wordlists[list.name];
            return (
              <div
                key={list.name}
                className="flex items-center gap-3 rounded-lg border border-white/10 bg-white/5 px-4 py-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-sm font-semibold text-zinc-100">
                    {list.label}
                    <span className="ml-2 text-xs font-normal text-zinc-500">
                      {items.length.toLocaleString()} lines
                    </span>
                  </p>
                  <p className="mt-1 text-[11px] text-zinc-500">{list.hint}</p>
                </div>
                <CopyButton text={() => items.join('\n')} label="copy" />
                <button
                  type="button"
                  disabled={items.length === 0}
                  onClick={() =>
                    download(items.join('\n'), `${stem}-${list.label}`, 'text/plain')
                  }
                  className="shrink-0 rounded-md border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[11px] text-zinc-300 transition-colors hover:border-emerald-500/40 hover:text-emerald-300 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  save
                </button>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}
