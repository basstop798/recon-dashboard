/**
 * Export builders.
 *
 * A scan is only useful if it leaves the browser in the shape the next tool
 * expects, so the same report is rendered five ways:
 *   - JSON     — the full machine-readable bundle (report + derived views).
 *   - Markdown — what gets pasted into notes or a write-up.
 *   - Text     — the terminal-friendly transcript.
 *   - CSV      — findings only, for a spreadsheet or a tracker import.
 *   - Wordlist — plain newline-delimited hosts / URLs / parameters.
 *
 * Kept out of the page component so the formatting is testable on its own and
 * every export is guaranteed to be built from the identical derived data.
 */

import { buildDorks } from './dorks';
import { buildFindings } from './findings';
import { buildPivots } from './pivots';
import { classLabel } from './url-intel';
import type { DorkGroup, Finding, PivotGroup, ScanReport } from './types';

export interface ReportBundle {
  scan: ScanReport;
  findings: Finding[];
  dorks: DorkGroup[];
  pivots: PivotGroup[];
}

export function formatDuration(ms: number | null): string {
  if (ms === null) return 'n/a';
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

/** Assembles the report plus everything derived from it. */
export function buildReportBundle(report: ScanReport): ReportBundle {
  return {
    scan: report,
    findings: buildFindings(report),
    dorks: buildDorks(report.domain),
    pivots: buildPivots({
      domain: report.domain,
      faviconHash: report.modules.meta.data?.favicon.hash ?? null,
      asn: report.modules.whois.data?.networks[0]?.asn ?? null,
    }),
  };
}

/* -------------------------------------------------------------------------- */
/* Wordlists                                                                  */
/* -------------------------------------------------------------------------- */

export interface Wordlists {
  hosts: string[];
  urls: string[];
  parameters: string[];
  endpoints: string[];
}

/**
 * The four lists an operator feeds into their own tooling afterwards.
 *
 * This dashboard never fuzzes anything itself — generating the wordlist is the
 * correct handoff point, because the operator owns the decision to send traffic
 * and the authorisation that makes it legal.
 */
export function collectWordlists(report: ScanReport): Wordlists {
  const hosts = new Set<string>();
  const urls = new Set<string>();

  for (const record of report.modules.subdomains.data?.subdomains ?? []) {
    hosts.add(record.host);
  }
  for (const host of report.modules['url-intel'].data?.inScopeHosts ?? []) {
    hosts.add(host.host);
  }
  for (const host of report.modules['js-endpoints'].data?.hosts ?? []) {
    hosts.add(host);
  }

  for (const url of report.modules.archived.data?.urls ?? []) urls.add(url);
  for (const url of report.modules.meta.data?.sitemap.urls ?? []) urls.add(url);

  return {
    hosts: [...hosts].sort(),
    urls: [...urls].sort(),
    parameters: (report.modules['url-intel'].data?.parameters ?? []).map(
      (parameter) => parameter.name,
    ),
    endpoints: [...(report.modules['js-endpoints'].data?.endpoints ?? [])].sort(),
  };
}

/* -------------------------------------------------------------------------- */
/* CSV                                                                        */
/* -------------------------------------------------------------------------- */

function csvCell(value: string): string {
  // Quote unconditionally and double any embedded quote — the simple rule that
  // survives commas, newlines and the quotes inside evidence blobs.
  return `"${value.replace(/"/g, '""')}"`;
}

export function findingsToCsv(findings: readonly Finding[]): string {
  const rows = [['severity', 'module', 'title', 'detail', 'evidence'].join(',')];

  for (const finding of findings) {
    rows.push(
      [
        finding.severity,
        finding.module,
        finding.title,
        finding.detail,
        finding.evidence ?? '',
      ]
        .map(csvCell)
        .join(','),
    );
  }

  return rows.join('\n');
}

/* -------------------------------------------------------------------------- */
/* Markdown                                                                   */
/* -------------------------------------------------------------------------- */

function section(lines: string[], title: string): void {
  lines.push('', `## ${title}`, '');
}

function list(lines: string[], items: readonly string[], limit = 100): void {
  for (const item of items.slice(0, limit)) lines.push(`- ${item}`);
  if (items.length > limit) lines.push(`- _…and ${items.length - limit} more_`);
}

export function reportToMarkdown(bundle: ReportBundle): string {
  const { scan, findings } = bundle;
  const lines: string[] = [
    `# BulletRecon report — ${scan.domain}`,
    '',
    `- **Started:** ${scan.startedAt}`,
    `- **Finished:** ${scan.finishedAt ?? 'incomplete'}`,
    `- **Duration:** ${formatDuration(scan.durationMs)}`,
    `- **Findings:** ${findings.length}`,
  ];

  section(lines, 'Findings');
  if (findings.length === 0) {
    lines.push('_No findings._');
  } else {
    lines.push('| Severity | Module | Finding |', '| --- | --- | --- |');
    for (const finding of findings) {
      // Pipes inside evidence would break the table, so the row keeps to the
      // title and the detail goes underneath.
      lines.push(
        `| ${finding.severity.toUpperCase()} | ${finding.module} | ${finding.title.replace(/\|/g, '\\|')} |`,
      );
    }
    lines.push('');
    for (const finding of findings) {
      lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`, '');
      lines.push(finding.detail, '');
      if (finding.evidence) {
        lines.push('```', finding.evidence, '```', '');
      }
    }
  }

  const subdomains = scan.modules.subdomains.data;
  section(lines, `Subdomains (${subdomains?.subdomains.length ?? 0})`);
  list(
    lines,
    (subdomains?.subdomains ?? []).map(
      (record) => `\`${record.host}\` — ${record.sources.join(', ')}`,
    ),
    200,
  );

  const takeover = scan.modules.takeover.data;
  if (takeover) {
    section(lines, `Host resolution (${takeover.live}/${takeover.checked} live)`);
    list(
      lines,
      takeover.hosts
        .filter((host) => host.status !== 'live' || host.service)
        .map(
          (host) =>
            `\`${host.host}\` — ${host.status}${host.cname ? ` → ${host.cname}` : ''}${
              host.service ? ` (${host.service})` : ''
            }`,
        ),
      200,
    );
  }

  const dns = scan.modules.dns.data;
  section(lines, `DNS records (${dns?.records.length ?? 0})`);
  list(
    lines,
    (dns?.records ?? []).map(
      (record) =>
        `\`${record.type}\` ${record.value}${
          record.priority === undefined ? '' : ` (priority ${record.priority})`
        }`,
    ),
    200,
  );

  const mail = scan.modules.mail.data;
  if (mail) {
    section(lines, 'Email security');
    lines.push(`- **SPF:** ${mail.spf.found ? `\`${mail.spf.raw}\`` : 'not published'}`);
    lines.push(`- **DMARC:** ${mail.dmarc.found ? `\`${mail.dmarc.raw}\`` : 'not published'}`);
    lines.push(`- **MX:** ${mail.mx.map((record) => record.value).join(', ') || 'none'}`);
    lines.push(`- **CAA:** ${mail.caa.join(', ') || 'none'}`);
    const dkim = mail.dkim.filter((entry) => entry.found).map((entry) => entry.selector);
    const revoked = mail.dkim.filter((entry) => entry.revoked).map((entry) => entry.selector);
    lines.push(
      `- **DKIM selectors with a key:** ${dkim.join(', ') || 'none of the common set'}${
        revoked.length > 0 ? ` (revoked: ${revoked.join(', ')})` : ''
      }`,
    );
  }

  const whois = scan.modules.whois.data;
  if (whois?.domain.found) {
    section(lines, 'Registration & network');
    lines.push(`- **Registrar:** ${whois.domain.registrar ?? 'unknown'}`);
    lines.push(`- **Created:** ${whois.domain.createdAt ?? 'unknown'}`);
    lines.push(`- **Expires:** ${whois.domain.expiresAt ?? 'unknown'}`);
    lines.push(`- **Statuses:** ${whois.domain.statuses.join(', ') || 'none'}`);
    for (const network of whois.networks) {
      lines.push(
        `- **${network.ip}:** AS${network.asn ?? '?'} ${network.asnName ?? ''} ${
          network.prefix ?? ''
        } ${network.country ?? ''}`.trimEnd(),
      );
    }
  }

  const tech = scan.modules.tech.data;
  if (tech) {
    section(lines, `Technology (grade ${tech.grade})`);
    lines.push(`\`${tech.finalUrl}\` — HTTP ${tech.status}`, '');
    list(
      lines,
      tech.technologies.map((item) => `**${item.name}** (${item.category}) — ${item.evidence}`),
      100,
    );
    lines.push('', '### Security headers', '');
    for (const check of tech.security) {
      lines.push(`- ${check.present ? '✓' : '✗'} \`${check.header}\` — ${check.advice}`);
    }
  }

  const js = scan.modules['js-endpoints'].data;
  if (js) {
    section(lines, `JavaScript (${js.scanned}/${js.scripts.length} bundles parsed)`);
    if (js.secrets.length > 0) {
      lines.push('### Secret patterns', '');
      list(
        lines,
        js.secrets.map(
          (secret) => `**${secret.rule}** \`${secret.match}\` — ${secret.source}`,
        ),
      );
      lines.push('');
    }
    if (js.sourceMaps.length > 0) {
      lines.push('### Source maps', '');
      list(lines, js.sourceMaps);
      lines.push('');
    }
    lines.push('### Endpoint candidates', '');
    list(lines, js.endpoints, 200);
  }

  const urlIntel = scan.modules['url-intel'].data;
  if (urlIntel) {
    section(lines, `URL intelligence (${urlIntel.analyzed} URLs analysed)`);
    for (const bucket of urlIntel.buckets) {
      lines.push(`### ${bucket.label} (${bucket.total})`, '');
      list(lines, bucket.urls, 50);
      lines.push('');
    }

    lines.push('### Parameters', '');
    list(
      lines,
      urlIntel.parameters.map(
        (parameter) =>
          `\`${parameter.name}\` ×${parameter.count}${
            parameter.classes.length > 0
              ? ` — ${parameter.classes.map(classLabel).join(', ')}`
              : ''
          }`,
      ),
      150,
    );

    if (urlIntel.cloudAssets.length > 0) {
      lines.push('', '### Cloud assets', '');
      list(
        lines,
        urlIntel.cloudAssets.map((asset) => `**${asset.provider}** \`${asset.asset}\``),
      );
    }
  }

  const archived = scan.modules.archived.data;
  section(lines, `Archived URLs (${archived?.urls.length ?? 0})`);
  list(lines, archived?.urls ?? [], 200);

  const meta = scan.modules.meta.data;
  if (meta) {
    section(lines, 'Recon extras');
    lines.push(
      `- **Favicon:** ${
        meta.favicon.found
          ? `\`http.favicon.hash:${meta.favicon.hash}\` (${meta.favicon.bytes} bytes)`
          : 'not retrieved'
      }`,
    );
    lines.push(`- **security.txt:** ${meta.securityTxt.found ? meta.securityTxt.url : 'not published'}`);
    lines.push(`- **robots.txt:** ${meta.robots.found ? meta.robots.url : 'not published'}`);
    lines.push(
      `- **Sitemap:** ${meta.sitemap.urls.length} URLs from ${meta.sitemap.documents.length} document(s)`,
    );
    const wellKnown = meta.wellKnown.filter((file) => file.found).map((file) => file.path);
    lines.push(`- **Well-known files:** ${wellKnown.join(', ') || 'none found'}`);
    if (meta.robots.disallowed.length > 0) {
      lines.push('', '### robots.txt disallowed', '');
      list(lines, meta.robots.disallowed, 100);
    }
  }

  section(lines, 'Dorks');
  for (const group of bundle.dorks) {
    lines.push(`### ${group.engine}`, '');
    for (const dork of group.dorks) {
      lines.push(`- [${dork.label}](${dork.url}) — \`${dork.query}\``);
    }
    lines.push('');
  }

  section(lines, 'Pivots');
  for (const group of bundle.pivots) {
    lines.push(`### ${group.category}`, '');
    for (const link of group.links) {
      lines.push(`- [${link.label}](${link.url}) — ${link.note}`);
    }
    lines.push('');
  }

  lines.push(
    '',
    '---',
    '',
    '_Generated by BulletRecon. Every module is passive OSINT; verify each lead against the programme scope before testing._',
  );

  return lines.join('\n');
}

/* -------------------------------------------------------------------------- */
/* Plain text                                                                 */
/* -------------------------------------------------------------------------- */

const RULE = '='.repeat(74);

export function reportToText(bundle: ReportBundle): string {
  const { scan, findings } = bundle;
  const lines: string[] = [
    RULE,
    ` BULLETRECON REPORT — ${scan.domain}`,
    ` Started  : ${scan.startedAt}`,
    ` Finished : ${scan.finishedAt ?? 'incomplete'}`,
    ` Duration : ${formatDuration(scan.durationMs)}`,
    RULE,
    '',
    `[FINDINGS] (${findings.length})`,
  ];

  for (const finding of findings) {
    lines.push(`  ${finding.severity.toUpperCase().padEnd(8)} ${finding.title}`);
    lines.push(`           ${finding.detail}`);
    if (finding.evidence) {
      for (const line of finding.evidence.split('\n')) {
        lines.push(`           > ${line}`);
      }
    }
  }
  lines.push('');

  const push = (title: string, items: readonly string[]) => {
    lines.push(`[${title}] (${items.length})`);
    for (const item of items) lines.push(`  ${item}`);
    lines.push('');
  };

  const modules = scan.modules;

  push(
    'SUBDOMAINS',
    (modules.subdomains.data?.subdomains ?? []).map(
      (record) => `${record.host}  [${record.sources.join(', ')}]`,
    ),
  );

  push(
    'HOST RESOLUTION',
    (modules.takeover.data?.hosts ?? []).map(
      (host) =>
        `${host.host.padEnd(48)} ${host.status}${host.cname ? ` -> ${host.cname}` : ''}${
          host.service ? ` (${host.service})` : ''
        }`,
    ),
  );

  push(
    'DNS RECORDS',
    (modules.dns.data?.records ?? []).map(
      (record) =>
        `${record.type.padEnd(6)} ${record.value}${
          record.priority === undefined ? '' : ` priority=${record.priority}`
        }`,
    ),
  );

  const mail = modules.mail.data;
  if (mail) {
    push('EMAIL SECURITY', [
      `SPF   : ${mail.spf.raw ?? 'not published'}`,
      `DMARC : ${mail.dmarc.raw ?? 'not published'}`,
      `MX    : ${mail.mx.map((record) => record.value).join(', ') || 'none'}`,
      `CAA   : ${mail.caa.join(', ') || 'none'}`,
    ]);
  }

  const whois = modules.whois.data;
  if (whois) {
    push('REGISTRATION', [
      `Registrar : ${whois.domain.registrar ?? 'unknown'}`,
      `Created   : ${whois.domain.createdAt ?? 'unknown'}`,
      `Expires   : ${whois.domain.expiresAt ?? 'unknown'}`,
      `Statuses  : ${whois.domain.statuses.join(', ') || 'none'}`,
      ...whois.networks.map(
        (network) =>
          `${network.ip} AS${network.asn ?? '?'} ${network.asnName ?? ''} ${network.prefix ?? ''}`,
      ),
    ]);
  }

  const tech = modules.tech.data;
  if (tech) {
    push('TECHNOLOGY', [
      `${tech.finalUrl} (HTTP ${tech.status}) — header grade ${tech.grade}`,
      ...tech.technologies.map(
        (item) => `${item.category.padEnd(16)} ${item.name}  <- ${item.evidence}`,
      ),
    ]);
    push(
      'SECURITY HEADERS',
      tech.security.map(
        (check) => `${check.present ? '[+]' : '[-]'} ${check.header.padEnd(32)} ${check.advice}`,
      ),
    );
    push(
      'RESPONSE HEADERS',
      tech.headers.map((header) => `${header.name}: ${header.value}`),
    );
  }

  const js = modules['js-endpoints'].data;
  if (js) {
    push(
      'JS SECRETS',
      js.secrets.map((secret) => `${secret.rule}: ${secret.match}  <- ${secret.source}`),
    );
    push('SOURCE MAPS', js.sourceMaps);
    push('JS ENDPOINT CANDIDATES', js.endpoints);
  }

  const urlIntel = modules['url-intel'].data;
  if (urlIntel) {
    for (const bucket of urlIntel.buckets) {
      push(`URLS — ${bucket.label.toUpperCase()}`, bucket.urls);
    }
    push(
      'PARAMETERS',
      urlIntel.parameters.map(
        (parameter) =>
          `${parameter.name.padEnd(32)} x${parameter.count}  ${parameter.classes
            .map(classLabel)
            .join(', ')}`,
      ),
    );
    push(
      'CLOUD ASSETS',
      urlIntel.cloudAssets.map((asset) => `${asset.provider.padEnd(24)} ${asset.asset}`),
    );
  }

  push('ARCHIVED URLS', modules.archived.data?.urls ?? []);

  const meta = modules.meta.data;
  if (meta) {
    push('RECON EXTRAS', [
      `Favicon      : ${
        meta.favicon.found
          ? `${meta.favicon.url} (http.favicon.hash:${meta.favicon.hash}, ${meta.favicon.bytes} bytes)`
          : 'not retrieved'
      }`,
      `security.txt : ${meta.securityTxt.found ? meta.securityTxt.url : 'not published'}`,
      ...meta.securityTxt.fields.map((field) => `  ${field.name}: ${field.value}`),
      `robots.txt   : ${meta.robots.found ? meta.robots.url : 'not published'}`,
      ...meta.robots.disallowed.map((path) => `  Disallow: ${path}`),
      `Sitemap URLs : ${meta.sitemap.urls.length} from ${meta.sitemap.documents.length} document(s)`,
      ...meta.wellKnown
        .filter((file) => file.found)
        .map((file) => `Well-known   : ${file.url} (${file.contentType ?? 'unknown type'})`),
    ]);
  }

  lines.push('[DORKS]');
  for (const group of bundle.dorks) {
    lines.push(`  -- ${group.engine} --`);
    for (const dork of group.dorks) {
      lines.push(`  ${dork.label}: ${dork.query}`);
      lines.push(`     ${dork.url}`);
    }
  }
  lines.push('');

  lines.push('[PIVOTS]');
  for (const group of bundle.pivots) {
    lines.push(`  -- ${group.category} --`);
    for (const link of group.links) {
      lines.push(`  ${link.label}: ${link.url}`);
    }
  }

  return lines.join('\n');
}
