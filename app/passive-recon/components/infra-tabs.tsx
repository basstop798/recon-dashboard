'use client';

/**
 * Infrastructure tabs: DNS records, the mail-authentication posture built from
 * them, and who actually owns the domain and the netblock behind it.
 */

import { useMemo, useState } from 'react';

import {
  NULL_MX,
  type DnsPayload,
  type MailPayload,
  type ModuleState,
  type WhoisPayload,
} from '@/lib/passive-recon/types';

import {
  CopyButton,
  EmptyState,
  FilterInput,
  KeyValue,
  Panel,
  Pill,
  SourceStats,
  cx,
} from './ui';

const RECORD_TONE: Record<string, string> = {
  A: 'text-emerald-300',
  AAAA: 'text-emerald-300',
  CNAME: 'text-cyan-300',
  MX: 'text-violet-300',
  TXT: 'text-amber-200',
  NS: 'text-sky-300',
  SOA: 'text-zinc-400',
  CAA: 'text-rose-300',
};

export function DnsTab({ state, data }: { state: ModuleState; data: DnsPayload | null }) {
  const [filter, setFilter] = useState('');
  const records = useMemo(() => data?.records ?? [], [data]);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return records;
    return records.filter(
      (record) =>
        record.type.toLowerCase().includes(needle) ||
        record.value.toLowerCase().includes(needle),
    );
  }, [records, filter]);

  if (records.length === 0) {
    return (
      <Panel title="DNS records">
        <SourceStats sources={data?.sources ?? []} />
        <EmptyState state={state} label="DNS resolution" />
      </Panel>
    );
  }

  return (
    <Panel
      title={`${records.length} DNS records`}
      subtitle="Apex resolution across every record type this tool queries."
      action={
        <CopyButton
          size="md"
          label="Copy zone view"
          text={() =>
            records
              .map((record) => `${record.type}\t${record.value}`)
              .join('\n')
          }
        />
      }
    >
      <SourceStats sources={data?.sources ?? []} />

      <div className="mb-3">
        <FilterInput value={filter} onChange={setFilter} placeholder="Filter records…" />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="font-mono text-[11px] tracking-wider text-zinc-600 uppercase">
              <th className="py-2 pr-4 font-medium">Type</th>
              <th className="py-2 pr-4 font-medium">Value</th>
              <th className="py-2 font-medium">Priority</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filtered.map((record, index) => (
              <tr key={`${record.type}-${record.value}-${index}`} className="align-top">
                <td
                  className={cx(
                    'py-2 pr-4 font-mono text-xs font-semibold',
                    RECORD_TONE[record.type] ?? 'text-zinc-300',
                  )}
                >
                  {record.type}
                </td>
                <td className="py-2 pr-4 font-mono text-xs break-all text-zinc-300">
                  {record.value}
                </td>
                <td className="py-2 font-mono text-xs text-zinc-600">
                  {record.priority ?? ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */

function PolicyRow({
  label,
  ok,
  value,
  note,
}: {
  label: string;
  ok: boolean;
  value: string;
  note: string;
}) {
  return (
    <div className="flex flex-wrap items-start gap-3 border-b border-white/5 py-3 last:border-0">
      <span
        className={cx(
          'mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold',
          ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300',
        )}
      >
        {ok ? '✓' : '✗'}
      </span>
      <div className="min-w-0 flex-1">
        <p className="font-mono text-xs font-semibold text-zinc-200">{label}</p>
        <p className="mt-0.5 font-mono text-xs break-all text-zinc-400">{value}</p>
        <p className="mt-1 text-xs text-zinc-500">{note}</p>
      </div>
    </div>
  );
}

export function MailTab({ state, data }: { state: ModuleState; data: MailPayload | null }) {
  if (!data) {
    return (
      <Panel title="Email security">
        <EmptyState state={state} label="Email security" />
      </Panel>
    );
  }

  const { spf, dmarc, mx, caa, dkim } = data;
  const foundSelectors = dkim.filter((entry) => entry.found);
  const revokedSelectors = dkim.filter((entry) => entry.revoked);
  const nullMx = mx.length === 1 && mx[0].value === NULL_MX;

  const spfStrong = spf.found && (spf.all === '-all' || spf.all === '~all');
  const dmarcStrong =
    dmarc.found && (dmarc.policy === 'reject' || dmarc.policy === 'quarantine');

  return (
    <div className="space-y-4">
      <Panel
        title="Spoofing posture"
        subtitle="Whether a stranger can send mail that claims to come from this domain."
      >
        <PolicyRow
          label="SPF"
          ok={spfStrong}
          value={spf.raw ?? 'not published'}
          note={
            !spf.found
              ? 'No SPF record: receivers have no list of authorised senders.'
              : `Terminates in ${spf.all ?? 'no "all" mechanism'}; ${spf.includes.length} include(s), ${spf.lookups} DNS-querying mechanism(s) of the 10 allowed.`
          }
        />
        <PolicyRow
          label="DMARC"
          ok={dmarcStrong}
          value={dmarc.raw ?? 'not published'}
          note={
            !dmarc.found
              ? 'No DMARC record: nothing tells receivers what to do with a forgery.'
              : `p=${dmarc.policy ?? '?'}${dmarc.subdomainPolicy ? `, sp=${dmarc.subdomainPolicy}` : ''}${
                  dmarc.percent !== null ? `, applied to ${dmarc.percent}% of mail` : ''
                }. Reports to ${dmarc.rua.join(', ') || 'nobody'}.`
          }
        />
        <PolicyRow
          label="DKIM (common selectors)"
          ok={foundSelectors.length > 0}
          value={
            foundSelectors.map((entry) => entry.selector).join(', ') ||
            (revokedSelectors.length > 0
              ? `published but revoked (empty p=): ${revokedSelectors.map((entry) => entry.selector).join(', ')}`
              : 'none of the probed selectors carry a key')
          }
          note="Selectors cannot be enumerated, so a miss is inconclusive — it only means none of the conventional names hold a usable key."
        />
        <PolicyRow
          label="CAA"
          ok={caa.length > 0}
          value={caa.join(' · ') || 'not published'}
          note="CAA restricts which certificate authorities may issue for this domain."
        />
      </Panel>

      <Panel title="Mail exchangers" subtitle="In preference order — lower wins.">
        {nullMx ? (
          <p className="text-sm text-zinc-500">
            Null MX (<code className="font-mono text-xs">MX 0 .</code>, RFC 7505): the domain
            explicitly declares that it accepts no mail.
          </p>
        ) : mx.length === 0 ? (
          <p className="text-sm text-zinc-500">No MX records: this domain does not receive mail.</p>
        ) : (
          <ul className="divide-y divide-white/5">
            {mx.map((record) => (
              <li key={record.value} className="flex items-center gap-3 py-2">
                <Pill>{record.priority ?? '—'}</Pill>
                <span className="font-mono text-xs break-all text-zinc-300">{record.value}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {spf.includes.length > 0 && (
        <Panel
          title="SPF delegation chain"
          subtitle="Every include hands sending authority to another party."
        >
          <ul className="flex flex-wrap gap-2">
            {spf.includes.map((include) => (
              <li key={include}>
                <Pill tone="accent">{include}</Pill>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function WhoisTab({ state, data }: { state: ModuleState; data: WhoisPayload | null }) {
  if (!data) {
    return (
      <Panel title="Domain & network intel">
        <EmptyState state={state} label="Registration lookup" />
      </Panel>
    );
  }

  const { domain, networks } = data;

  return (
    <div className="space-y-4">
      <Panel title="Registration (RDAP)" subtitle="Structured registry data — the modern WHOIS.">
        <SourceStats sources={data.sources} />
        {!domain.found ? (
          <p className="text-sm text-zinc-500">
            No RDAP record was returned. Some ccTLD registries do not run an RDAP service.
          </p>
        ) : (
          <KeyValue
            rows={[
              { key: 'Registrar', value: domain.registrar ?? '—' },
              { key: 'Created', value: domain.createdAt ?? '—' },
              { key: 'Last changed', value: domain.updatedAt ?? '—' },
              { key: 'Expires', value: domain.expiresAt ?? '—' },
              {
                key: 'DNSSEC',
                value:
                  domain.dnssec === null ? '—' : domain.dnssec ? 'signed' : 'not signed',
              },
              {
                key: 'Statuses',
                value: (
                  <span className="flex flex-wrap gap-1">
                    {domain.statuses.map((status) => (
                      <Pill key={status}>{status}</Pill>
                    ))}
                  </span>
                ),
              },
              {
                key: 'Nameservers',
                value: domain.nameservers.join(', ') || '—',
              },
              {
                key: 'Abuse contact',
                value: domain.abuseContacts.join(', ') || '—',
              },
            ]}
          />
        )}
      </Panel>

      <Panel
        title="Network ownership"
        subtitle="Origin AS for each apex address — the netblock is where the rest of the estate usually lives."
      >
        {networks.length === 0 ? (
          <p className="text-sm text-zinc-500">No IPv4 addresses were resolved for the apex.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="font-mono text-[11px] tracking-wider text-zinc-600 uppercase">
                  <th className="py-2 pr-4 font-medium">IP</th>
                  <th className="py-2 pr-4 font-medium">ASN</th>
                  <th className="py-2 pr-4 font-medium">Network</th>
                  <th className="py-2 pr-4 font-medium">Prefix</th>
                  <th className="py-2 font-medium">Country</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {networks.map((network) => (
                  <tr key={network.ip}>
                    <td className="py-2 pr-4 font-mono text-xs text-zinc-200">{network.ip}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-emerald-300">
                      {network.asn ? `AS${network.asn}` : '—'}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs text-zinc-300">
                      {network.asnName ?? '—'}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs text-zinc-400">
                      {network.prefix ?? '—'}
                    </td>
                    <td className="py-2 font-mono text-xs text-zinc-400">
                      {network.country ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
