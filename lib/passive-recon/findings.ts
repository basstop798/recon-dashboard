/**
 * Finding aggregation — the triage layer the dashboard leads with.
 *
 * Ten modules produce a lot of true, uninteresting data. This walks the whole
 * report and answers the only question an operator actually has after a scan:
 * *what here is worth my next hour?*
 *
 * Derived, never streamed. The dashboard, the Markdown export and the JSON
 * export all call this, so they can never disagree about what the scan said.
 * It is also tolerant of a partial report: modules that errored or have not
 * finished simply contribute nothing.
 */

import {
  SEVERITY_ORDER,
  type Finding,
  type ScanReport,
  type Severity,
} from './types';

/** Third-party verification tokens map a TXT record to a SaaS vendor in use. */
const VERIFICATION_TOKENS: ReadonlyArray<{ pattern: RegExp; vendor: string }> = [
  { pattern: /^google-site-verification=/i, vendor: 'Google Search Console' },
  { pattern: /^ms=|^msvalidate/i, vendor: 'Microsoft 365 / Bing' },
  { pattern: /^facebook-domain-verification=/i, vendor: 'Meta Business' },
  { pattern: /^atlassian-domain-verification=/i, vendor: 'Atlassian' },
  { pattern: /^docusign=/i, vendor: 'DocuSign' },
  { pattern: /^adobe-idp-site-verification=/i, vendor: 'Adobe' },
  { pattern: /^dropbox-domain-verification=/i, vendor: 'Dropbox' },
  { pattern: /^stripe-verification=/i, vendor: 'Stripe' },
  { pattern: /^zoom-domain-verification=/i, vendor: 'Zoom' },
  { pattern: /^slack-domain-verification=/i, vendor: 'Slack' },
  { pattern: /^shopify-verification|^shops-verification/i, vendor: 'Shopify' },
  { pattern: /^apple-domain-verification=/i, vendor: 'Apple Business' },
  { pattern: /^cisco-ci-domain-verification=/i, vendor: 'Cisco' },
  { pattern: /^miro-verification=/i, vendor: 'Miro' },
  { pattern: /^mongodb-site-verification=/i, vendor: 'MongoDB Atlas' },
  { pattern: /^workplace-domain-verification=/i, vendor: 'Workplace' },
  { pattern: /^brevo-code|^sendinblue-code/i, vendor: 'Brevo' },
  { pattern: /^mailru-verification|^yandex-verification/i, vendor: 'Mail.ru / Yandex' },
];

/** robots.txt paths that are worth a look precisely because they are hidden. */
const SENSITIVE_ROBOTS_RE =
  /admin|internal|private|backup|config|api|graphql|debug|test|staging|dev|secret|token|upload|export|download|\.git|\.env|db|sql|log/i;

/** Cookie names that almost certainly carry a session. */
const SESSION_COOKIE_RE =
  /sess|sid$|^sid|auth|token|jwt|login|remember|csrf|xsrf/i;

const DAY_MS = 86_400_000;

function daysUntil(iso: string): number | null {
  const timestamp = Date.parse(iso);
  if (Number.isNaN(timestamp)) return null;
  return Math.round((timestamp - Date.now()) / DAY_MS);
}

/**
 * Walks a (possibly partial) report and returns findings, worst first.
 */
export function buildFindings(report: ScanReport): Finding[] {
  const findings: Finding[] = [];

  const push = (finding: Finding) => {
    findings.push(finding);
  };

  /* ---------------------------------------------------------------- hosts */

  const takeover = report.modules.takeover.data;
  if (takeover) {
    for (const host of takeover.hosts) {
      if (host.status !== 'dangling') continue;

      push({
        id: `takeover:${host.host}`,
        module: 'takeover',
        severity: host.severity,
        title: host.takeover
          ? `Possible subdomain takeover: ${host.host}`
          : `Dangling CNAME: ${host.host}`,
        detail: host.note,
        evidence: host.cname ? `${host.host} CNAME ${host.cname}` : host.host,
      });
    }
  }

  /* ----------------------------------------------------------------- mail */

  const mail = report.modules.mail.data;
  if (mail) {
    if (!mail.spf.found) {
      push({
        id: 'mail:spf-missing',
        module: 'mail',
        severity: 'medium',
        title: 'No SPF record',
        detail:
          'Nothing declares which hosts may send mail as this domain, so receivers have no basis to reject a forgery.',
      });
    } else {
      if (mail.spf.all === '+all' || mail.spf.all === 'all') {
        push({
          id: 'mail:spf-permissive',
          module: 'mail',
          severity: 'high',
          title: 'SPF allows any sender (+all)',
          detail: 'The policy explicitly authorises every host on the internet to send as this domain.',
          evidence: mail.spf.raw ?? undefined,
        });
      } else if (mail.spf.all === '?all' || mail.spf.all === null) {
        push({
          id: 'mail:spf-neutral',
          module: 'mail',
          severity: 'medium',
          title: mail.spf.all ? 'SPF ends in a neutral qualifier (?all)' : 'SPF has no terminating "all"',
          detail: 'Unauthorised senders are neither rejected nor marked, which defeats the point of publishing SPF.',
          evidence: mail.spf.raw ?? undefined,
        });
      }

      if (mail.spf.lookups > 10) {
        push({
          id: 'mail:spf-lookups',
          module: 'mail',
          severity: 'low',
          title: `SPF exceeds the 10-lookup limit (${mail.spf.lookups})`,
          detail:
            'RFC 7208 requires receivers to return PermError past ten DNS-querying mechanisms, so the record may be ignored entirely.',
          evidence: mail.spf.raw ?? undefined,
        });
      }
    }

    if (!mail.dmarc.found) {
      push({
        id: 'mail:dmarc-missing',
        module: 'mail',
        severity: 'medium',
        title: 'No DMARC record',
        detail:
          'Without DMARC there is no published handling for mail that fails SPF/DKIM, and no reporting when someone tries.',
      });
    } else if (mail.dmarc.policy === 'none') {
      push({
        id: 'mail:dmarc-none',
        module: 'mail',
        severity: 'medium',
        title: 'DMARC policy is p=none',
        detail: 'The domain monitors spoofing but instructs receivers to deliver it anyway.',
        evidence: mail.dmarc.raw ?? undefined,
      });
    } else if (mail.dmarc.percent !== null && mail.dmarc.percent < 100) {
      push({
        id: 'mail:dmarc-pct',
        module: 'mail',
        severity: 'low',
        title: `DMARC applies to only ${mail.dmarc.percent}% of mail`,
        detail: 'The remaining share is delivered without the policy being enforced.',
        evidence: mail.dmarc.raw ?? undefined,
      });
    }

    if (mail.dmarc.found && mail.dmarc.subdomainPolicy === 'none') {
      push({
        id: 'mail:dmarc-sp-none',
        module: 'mail',
        severity: 'low',
        title: 'DMARC subdomain policy is sp=none',
        detail: 'Subdomains are exempt from the parent policy — a common spoofing route.',
        evidence: mail.dmarc.raw ?? undefined,
      });
    }

    if (mail.caa.length === 0) {
      push({
        id: 'mail:caa-missing',
        module: 'mail',
        severity: 'low',
        title: 'No CAA record',
        detail: 'Any public CA may issue a certificate for this domain; CAA restricts that to named issuers.',
      });
    }
  }

  /* ----------------------------------------------------------------- tech */

  const tech = report.modules.tech.data;
  if (tech) {
    for (const check of tech.security) {
      if (check.severity === 'info') continue;

      push({
        id: `header:${check.header}`,
        module: 'tech',
        severity: check.severity,
        title: check.present
          ? `Weak ${check.header}`
          : `Missing ${check.header}`,
        detail: check.advice,
        evidence: check.value ? `${check.header}: ${check.value}` : undefined,
      });
    }

    for (const cookie of tech.cookies) {
      if (!SESSION_COOKIE_RE.test(cookie.name)) continue;

      const flaws: string[] = [];
      if (!cookie.secure) flaws.push('no Secure');
      if (!cookie.httpOnly) flaws.push('no HttpOnly');
      if (!cookie.sameSite) flaws.push('no SameSite');
      if (flaws.length === 0) continue;

      push({
        id: `cookie:${cookie.name}`,
        module: 'tech',
        // Missing HttpOnly on a session cookie is the one that turns an XSS
        // into an account takeover, so it outranks the other two.
        severity: cookie.httpOnly ? 'low' : 'medium',
        title: `Session-like cookie "${cookie.name}" is missing flags`,
        detail: `Set-Cookie for ${cookie.name} has ${flaws.join(', ')}.`,
      });
    }
  }

  /* ------------------------------------------------------------ javascript */

  const js = report.modules['js-endpoints'].data;
  if (js) {
    for (const secret of js.secrets) {
      push({
        id: `secret:${secret.rule}:${secret.match}:${secret.source}`,
        module: 'js-endpoints',
        severity: secret.severity,
        title: `${secret.rule} in client-side JavaScript`,
        detail:
          'Pattern matched in a bundle served to every visitor. Confirm whether the value is live before reporting.',
        evidence: `${secret.match} — ${secret.source}`,
      });
    }

    if (js.sourceMaps.length > 0) {
      push({
        id: 'js:sourcemaps',
        module: 'js-endpoints',
        severity: 'medium',
        title: `${js.sourceMaps.length} source map${js.sourceMaps.length === 1 ? '' : 's'} referenced`,
        detail:
          'Source maps usually reconstruct original, unminified source — including comments, internal paths and dead code.',
        evidence: js.sourceMaps.slice(0, 3).join('\n'),
      });
    }
  }

  /* ------------------------------------------------------------ url intel */

  const urlIntel = report.modules['url-intel'].data;
  if (urlIntel) {
    for (const bucket of urlIntel.buckets) {
      if (bucket.severity === 'info' || bucket.urls.length === 0) continue;

      push({
        id: `urls:${bucket.id}`,
        module: 'url-intel',
        severity: bucket.severity,
        title: `${bucket.total} URL${bucket.total === 1 ? '' : 's'} — ${bucket.label}`,
        detail: bucket.description,
        evidence: bucket.urls.slice(0, 3).join('\n'),
      });
    }

    if (urlIntel.cloudAssets.length > 0) {
      const providers = [...new Set(urlIntel.cloudAssets.map((asset) => asset.provider))];
      push({
        id: 'urls:cloud',
        module: 'url-intel',
        severity: 'low',
        title: `${urlIntel.cloudAssets.length} cloud asset${urlIntel.cloudAssets.length === 1 ? '' : 's'} referenced`,
        detail: `Storage and hosting identifiers found across ${providers.join(', ')}. Check each one's ACL and whether the name is still claimed.`,
        evidence: urlIntel.cloudAssets
          .slice(0, 3)
          .map((asset) => `${asset.provider}: ${asset.asset}`)
          .join('\n'),
      });
    }
  }

  /* ----------------------------------------------------------------- meta */

  const meta = report.modules.meta.data;
  if (meta) {
    const sensitive = meta.robots.disallowed.filter((path) => SENSITIVE_ROBOTS_RE.test(path));
    if (sensitive.length > 0) {
      push({
        id: 'meta:robots-sensitive',
        module: 'meta',
        severity: 'low',
        title: `robots.txt names ${sensitive.length} sensitive-looking path${sensitive.length === 1 ? '' : 's'}`,
        detail:
          'Disallow entries are a curated list of what the operator would rather nobody visited — start there.',
        evidence: sensitive.slice(0, 8).join('\n'),
      });
    }

    for (const file of meta.wellKnown) {
      if (!file.found) continue;
      push({
        id: `meta:wellknown:${file.path}`,
        module: 'meta',
        severity: 'info',
        title: `${file.path} is published`,
        detail: 'Standard metadata file — useful for mapping the app’s platform integrations.',
        evidence: file.preview ?? file.url,
      });
    }

    if (!meta.securityTxt.found) {
      push({
        id: 'meta:security-txt',
        module: 'meta',
        severity: 'info',
        title: 'No security.txt',
        detail:
          'No machine-readable disclosure contact (RFC 9116). Find the programme policy before reporting anything.',
      });
    }
  }

  /* ---------------------------------------------------------------- whois */

  const whois = report.modules.whois.data;
  if (whois?.domain.found) {
    if (whois.domain.expiresAt) {
      const days = daysUntil(whois.domain.expiresAt);
      if (days !== null && days <= 60) {
        push({
          id: 'whois:expiring',
          module: 'whois',
          severity: days <= 0 ? 'high' : 'medium',
          title:
            days <= 0
              ? 'Domain registration has expired'
              : `Domain expires in ${days} day${days === 1 ? '' : 's'}`,
          detail: 'An expiring registration is a hijack window; report it before somebody else registers it.',
          evidence: whois.domain.expiresAt,
        });
      }
    }

    if (whois.domain.dnssec === false) {
      push({
        id: 'whois:dnssec',
        module: 'whois',
        severity: 'info',
        title: 'DNSSEC is not enabled',
        detail: 'Responses for this zone are not signed, so cache-poisoning defences rely on transport alone.',
      });
    }
  }

  /* ------------------------------------------------------------------ dns */

  const dns = report.modules.dns.data;
  if (dns) {
    const txt = dns.records.filter((record) => record.type === 'TXT');
    const vendors = new Set<string>();

    for (const record of txt) {
      for (const { pattern, vendor } of VERIFICATION_TOKENS) {
        if (pattern.test(record.value.trim())) vendors.add(vendor);
      }
    }

    if (vendors.size > 0) {
      push({
        id: 'dns:vendors',
        module: 'dns',
        severity: 'info',
        title: `${vendors.size} third-party service${vendors.size === 1 ? '' : 's'} identified from TXT records`,
        detail:
          'Verification tokens name the SaaS platforms the organisation uses — each one is its own login surface and takeover candidate.',
        evidence: [...vendors].sort().join(', '),
      });
    }
  }

  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.title.localeCompare(b.title),
  );
}

/** Counts findings per severity, for the dashboard's summary tiles. */
export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}
