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
  CheckMark,
  CopyButton,
  DataList,
  DataRow,
  DataTable,
  EmptyState,
  FilterInput,
  KeyValue,
  MONO,
  Panel,
  Pill,
  SourceStats,
  Td,
  Tr,
  cx,
} from './ui';

const RECORD_TONE: Record<string, string> = {
  A: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20',
  AAAA: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20',
  CNAME: 'bg-cyan-500/10 text-cyan-300 ring-cyan-500/20',
  MX: 'bg-violet-500/10 text-violet-300 ring-violet-500/20',
  TXT: 'bg-amber-500/10 text-amber-300 ring-amber-500/20',
  NS: 'bg-sky-500/10 text-sky-300 ring-sky-500/20',
  SOA: 'bg-zinc-500/10 text-zinc-300 ring-zinc-500/20',
  CAA: 'bg-rose-500/10 text-rose-300 ring-rose-500/20',
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

      <div className="mb-4">
        <FilterInput value={filter} onChange={setFilter} placeholder="Filter records…" />
      </div>

      <DataTable columns={['Type', 'Value', 'Priority']}>
        {filtered.map((record, index) => (
          <Tr key={`${record.type}-${record.value}-${index}`}>
            <Td className="w-px whitespace-nowrap">
              <span
                className={cx(
                  'inline-flex rounded-md px-2 py-0.5 font-mono text-xs font-semibold ring-1 ring-inset',
                  RECORD_TONE[record.type] ?? 'bg-white/5 text-zinc-300 ring-white/10',
                )}
              >
                {record.type}
              </span>
            </Td>
            <Td mono className="break-all text-zinc-200">
              {record.value}
            </Td>
            <Td className="w-px text-zinc-400 tabular-nums">{record.priority ?? ''}</Td>
          </Tr>
        ))}
      </DataTable>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */

function PolicyRow({
  label,
  ok,
  value,
  missing,
  note,
}: {
  label: string;
  ok: boolean;
  /** The raw record, shown verbatim; null when there is nothing to show. */
  value: string | null;
  /** Plain-language stand-in for a missing value. */
  missing: string;
  note: string;
}) {
  return (
    <div className="flex items-start gap-4 border-b border-white/5 py-5 first:pt-0 last:border-0 last:pb-0">
      <CheckMark ok={ok} />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-zinc-100">{label}</p>
        {value ? (
          <p
            className={cx(
              MONO,
              'mt-2 rounded-md bg-zinc-950/60 px-3 py-2 break-all text-zinc-300 ring-1 ring-white/5 ring-inset',
            )}
          >
            {value}
          </p>
        ) : (
          <p className="mt-1 text-sm text-zinc-500">{missing}</p>
        )}
        <p className="mt-2 text-sm leading-relaxed text-zinc-400">{note}</p>
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
    <div className="space-y-6">
      <Panel
        title="Spoofing posture"
        subtitle="Whether a stranger can send mail that claims to come from this domain."
      >
        <PolicyRow
          label="SPF"
          ok={spfStrong}
          value={spf.raw}
          missing="Not published."
          note={
            !spf.found
              ? 'No SPF record: receivers have no list of authorised senders.'
              : `Terminates in ${spf.all ?? 'no "all" mechanism'}; ${spf.includes.length} include(s), ${spf.lookups} DNS-querying mechanism(s) of the 10 allowed.`
          }
        />
        <PolicyRow
          label="DMARC"
          ok={dmarcStrong}
          value={dmarc.raw}
          missing="Not published."
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
          value={foundSelectors.map((entry) => entry.selector).join(', ') || null}
          missing={
            revokedSelectors.length > 0
              ? `Published but revoked (empty p=): ${revokedSelectors.map((entry) => entry.selector).join(', ')}.`
              : 'None of the probed selectors carry a key.'
          }
          note="Selectors cannot be enumerated, so a miss is inconclusive — it only means none of the conventional names hold a usable key."
        />
        <PolicyRow
          label="CAA"
          ok={caa.length > 0}
          value={caa.join(' · ') || null}
          missing="Not published."
          note="CAA restricts which certificate authorities may issue for this domain."
        />
      </Panel>

      <Panel title="Mail exchangers" subtitle="In preference order — lower wins.">
        {nullMx ? (
          <p className="text-sm text-zinc-400">
            Null MX (<code className="font-mono text-[13px] text-zinc-300">MX 0 .</code>, RFC
            7505): the domain explicitly declares that it accepts no mail.
          </p>
        ) : mx.length === 0 ? (
          <p className="text-sm text-zinc-400">No MX records: this domain does not receive mail.</p>
        ) : (
          <DataList>
            {mx.map((record) => (
              <DataRow key={record.value}>
                <span className="w-10 shrink-0">
                  <Pill>
                    <span className="tabular-nums">{record.priority ?? '—'}</span>
                  </Pill>
                </span>
                <span className={cx(MONO, 'break-all text-zinc-200')}>{record.value}</span>
              </DataRow>
            ))}
          </DataList>
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
                <Pill tone="accent" mono>
                  {include}
                </Pill>
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
    <div className="space-y-6">
      <Panel title="Registration (RDAP)" subtitle="Structured registry data — the modern WHOIS.">
        <SourceStats sources={data.sources} />
        {!domain.found ? (
          <p className="text-sm text-zinc-400">
            No RDAP record was returned. Some ccTLD registries do not run an RDAP service.
          </p>
        ) : (
          <KeyValue
            rows={[
              { key: 'Registrar', value: domain.registrar ?? '—' },
              { key: 'Created', value: domain.createdAt ?? '—', mono: true },
              { key: 'Last changed', value: domain.updatedAt ?? '—', mono: true },
              { key: 'Expires', value: domain.expiresAt ?? '—', mono: true },
              {
                key: 'DNSSEC',
                value:
                  domain.dnssec === null ? '—' : domain.dnssec ? 'Signed' : 'Not signed',
              },
              {
                key: 'Statuses',
                value:
                  domain.statuses.length === 0 ? (
                    '—'
                  ) : (
                    <span className="flex flex-wrap gap-1.5">
                      {domain.statuses.map((status) => (
                        <Pill key={status} mono>
                          {status}
                        </Pill>
                      ))}
                    </span>
                  ),
              },
              {
                key: 'Nameservers',
                value: domain.nameservers.join(', ') || '—',
                mono: true,
              },
              {
                key: 'Abuse contact',
                value: domain.abuseContacts.join(', ') || '—',
                mono: true,
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
          <p className="text-sm text-zinc-400">No IPv4 addresses were resolved for the apex.</p>
        ) : (
          <DataTable columns={['IP', 'ASN', 'Network', 'Prefix', 'Country']}>
            {networks.map((network) => (
              <Tr key={network.ip}>
                <Td mono className="text-zinc-100">
                  {network.ip}
                </Td>
                <Td mono className="text-emerald-400">
                  {network.asn ? `AS${network.asn}` : '—'}
                </Td>
                <Td className="text-zinc-300">{network.asnName ?? '—'}</Td>
                <Td mono className="text-zinc-400">
                  {network.prefix ?? '—'}
                </Td>
                <Td className="text-zinc-400">{network.country ?? '—'}</Td>
              </Tr>
            ))}
          </DataTable>
        )}
      </Panel>
    </div>
  );
}
