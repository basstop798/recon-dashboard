/**
 * OSINT pivot links.
 *
 * Every hunter keeps a bookmark folder of "paste the domain in here next".
 * This builds that folder for the current target, pre-filled — including the
 * pivots that only become possible *after* a scan, such as searching Shodan and
 * FOFA for every other host serving the same favicon.
 *
 * Deliberately link-only. Several of these services require an account or sell
 * API access; sending the operator's target list through a server-side key they
 * did not choose would be the wrong trade. The query runs in their browser.
 */

import type { PivotGroup } from './types';

/**
 * FOFA takes its query base64-encoded in the URL. `btoa` is global in both the
 * browser and Node 18+, so this stays isomorphic without a Buffer polyfill.
 */
function fofa(query: string): string {
  return `https://en.fofa.info/result?qbase64=${encodeURIComponent(btoa(query))}`;
}

export interface PivotContext {
  domain: string;
  /** Shodan-style favicon hash from the meta module, when available. */
  faviconHash?: number | null;
  /** ASN discovered by the whois module, e.g. "15169". */
  asn?: string | null;
}

export function buildPivots({ domain, faviconHash, asn }: PivotContext): PivotGroup[] {
  const q = encodeURIComponent(domain);

  const groups: PivotGroup[] = [
    {
      category: 'Certificate transparency',
      links: [
        {
          label: 'crt.sh',
          url: `https://crt.sh/?q=%25.${q}`,
          note: 'Every certificate ever issued for the domain and its subdomains.',
        },
        {
          label: 'Censys certificates',
          url: `https://search.censys.io/search?resource=certificates&q=${q}`,
          note: 'Certificate search with pivoting on issuer and key material.',
        },
        {
          label: 'Cert Spotter',
          url: `https://sslmate.com/certspotter/api/v1/issuances?domain=${q}`,
          note: 'SSLMate CT feed — JSON, no key required for light use.',
        },
        {
          label: 'Google CT search',
          url: `https://transparencyreport.google.com/https/certificates?cert_search_auth=&cert_search_cert=&cert_search=include_expired:false;include_subdomains:true;domain:${q}`,
          note: 'Google’s own CT log viewer.',
        },
      ],
    },
    {
      category: 'Passive DNS & subdomains',
      links: [
        {
          label: 'SecurityTrails',
          url: `https://securitytrails.com/domain/${q}/dns`,
          note: 'Historical DNS — old A records often expose origin IPs behind a CDN.',
        },
        {
          label: 'ViewDNS history',
          url: `https://viewdns.info/iphistory/?domain=${q}`,
          note: 'IP history for the apex.',
        },
        {
          label: 'DNSDumpster',
          url: 'https://dnsdumpster.com/',
          note: 'Subdomain map and network graph (paste the domain).',
        },
        {
          label: 'AlienVault OTX',
          url: `https://otx.alienvault.com/indicator/domain/${q}`,
          note: 'Passive DNS, URL history and threat context.',
        },
        {
          label: 'DNSlytics',
          url: `https://dnslytics.com/domain/${q}`,
          note: 'Reverse IP, reverse NS and reverse analytics-ID pivots.',
        },
        {
          label: 'Netcraft site report',
          url: `https://sitereport.netcraft.com/?url=https://${q}`,
          note: 'Hosting history, netblock owner and technology timeline.',
        },
      ],
    },
    {
      category: 'Internet-wide scanners',
      links: [
        {
          label: 'Shodan — hostname',
          url: `https://www.shodan.io/search?query=hostname%3A${q}`,
          note: 'Services already indexed for this hostname — no packets from you.',
        },
        {
          label: 'Shodan — certificate CN',
          url: `https://www.shodan.io/search?query=ssl.cert.subject.CN%3A%22${q}%22`,
          note: 'Finds origin servers whose certificate still names the domain.',
        },
        {
          label: 'Censys hosts',
          url: `https://search.censys.io/search?resource=hosts&q=${q}`,
          note: 'Host-level service data with certificate and ASN pivots.',
        },
        {
          label: 'ZoomEye',
          url: `https://www.zoomeye.org/searchResult?q=${q}`,
          note: 'Alternative scan index with good APAC coverage.',
        },
        {
          label: 'Netlas',
          url: `https://app.netlas.io/responses/?q=${q}`,
          note: 'Response-body search across the scanned internet.',
        },
        {
          label: 'FOFA',
          url: fofa(`domain="${domain}"`),
          note: 'Query is base64-encoded in the URL, as FOFA expects.',
        },
      ],
    },
    {
      category: 'Archives & crawled content',
      links: [
        {
          label: 'Wayback Machine',
          url: `https://web.archive.org/web/*/${q}/*`,
          note: 'Browse the raw URL history this scan sampled.',
        },
        {
          label: 'urlscan.io',
          url: `https://urlscan.io/search/#${q}`,
          note: 'Submitted scans: DOM, requests, screenshots and redirect chains.',
        },
        {
          label: 'Common Crawl index',
          url: `https://index.commoncrawl.org/`,
          note: 'Full CDX index if you need more than the scan’s sample.',
        },
        {
          label: 'archive.today',
          url: `https://archive.ph/${q}`,
          note: 'Snapshots the Wayback Machine often lacks.',
        },
      ],
    },
    {
      category: 'Code, APIs & secrets',
      links: [
        {
          label: 'GitHub code search',
          url: `https://github.com/search?type=code&q=%22${q}%22`,
          note: 'Requires a logged-in account for code results.',
        },
        {
          label: 'GitHub org lookup',
          url: `https://github.com/search?type=users&q=${q}`,
          note: 'Find the org, then enumerate members and their personal repos.',
        },
        {
          label: 'grep.app',
          url: `https://grep.app/search?q=${q}`,
          note: 'Fast regex search across public repositories, no login.',
        },
        {
          label: 'SwaggerHub',
          url: `https://app.swaggerhub.com/search?query=${q}`,
          note: 'Published API definitions — full endpoint lists, for free.',
        },
        {
          label: 'Postman public API network',
          url: `https://www.postman.com/search?q=${q}&type=all`,
          note: 'Collections regularly ship with working tokens.',
        },
      ],
    },
    {
      category: 'Cloud & storage exposure',
      links: [
        {
          label: 'GrayHatWarfare buckets',
          url: `https://buckets.grayhatwarfare.com/results/${q}`,
          note: 'Indexed public S3 / Azure / GCS buckets matching the name.',
        },
        {
          label: 'Shodan — S3 buckets',
          url: `https://www.shodan.io/search?query=${q}+s3.amazonaws.com`,
          note: 'Bucket hostnames seen in the wild.',
        },
      ],
    },
    {
      category: 'Reputation & breach data',
      links: [
        {
          label: 'VirusTotal domain report',
          url: `https://www.virustotal.com/gui/domain/${q}/relations`,
          note: 'The relations tab lists subdomains, sibling domains and URLs.',
        },
        {
          label: 'Have I Been Pwned (domain)',
          url: 'https://haveibeenpwned.com/DomainSearch',
          note: 'Domain-wide breach exposure; requires domain verification.',
        },
        {
          label: 'Hunter.io',
          url: `https://hunter.io/search/${q}`,
          note: 'Email-address format and known addresses for the org.',
        },
        {
          label: 'Intelligence X',
          url: `https://intelx.io/?s=${q}`,
          note: 'Leaks, pastes and dark-web mentions.',
        },
      ],
    },
    {
      category: 'Technology & organisation',
      links: [
        {
          label: 'BuiltWith',
          url: `https://builtwith.com/${q}`,
          note: 'Technology profile plus other domains sharing its tracking IDs.',
        },
        {
          label: 'Wappalyzer lookup',
          url: `https://www.wappalyzer.com/lookup/${q}`,
          note: 'Second opinion on the fingerprint this scan produced.',
        },
        {
          label: 'RDAP record',
          url: `https://rdap.org/domain/${q}`,
          note: 'The raw registration JSON behind the Domain Intel tab.',
        },
        {
          label: 'bgp.he.net',
          url: `https://bgp.he.net/dns/${q}`,
          note: 'DNS, netblock and peering view of the hosting network.',
        },
      ],
    },
    {
      category: 'Programme scope',
      links: [
        {
          label: 'HackerOne directory',
          url: `https://hackerone.com/directory/programs?query=${q}`,
          note: 'Confirm the target is in scope before you touch anything.',
        },
        {
          label: 'Bugcrowd programs',
          url: `https://bugcrowd.com/engagements?q=${q}`,
          note: 'Public engagement list.',
        },
        {
          label: 'disclose.io policies',
          url: `https://github.com/disclose/diodb/search?q=${q}`,
          note: 'Open database of vulnerability disclosure policies.',
        },
        {
          label: 'security.txt lookup',
          url: `https://${domain}/.well-known/security.txt`,
          note: 'The target’s own reporting instructions, if it publishes them.',
        },
      ],
    },
  ];

  if (typeof faviconHash === 'number') {
    groups.splice(3, 0, {
      category: 'Favicon pivots',
      links: [
        {
          label: `Shodan http.favicon.hash:${faviconHash}`,
          url: `https://www.shodan.io/search?query=http.favicon.hash%3A${faviconHash}`,
          note: 'Every indexed host serving this exact icon — finds origins behind a CDN.',
        },
        {
          label: `FOFA icon_hash="${faviconHash}"`,
          url: fofa(`icon_hash="${faviconHash}"`),
          note: 'Same pivot on a different scan corpus.',
        },
        {
          label: `ZoomEye iconhash:"${faviconHash}"`,
          url: `https://www.zoomeye.org/searchResult?q=${encodeURIComponent(
            `iconhash:"${faviconHash}"`,
          )}`,
          note: 'Third corpus; coverage varies by region.',
        },
      ],
    });
  }

  if (asn) {
    const asNumber = asn.replace(/^AS/i, '');
    groups.push({
      category: 'Network pivots',
      links: [
        {
          label: `bgp.he.net AS${asNumber}`,
          url: `https://bgp.he.net/AS${asNumber}`,
          note: 'Every prefix announced by the hosting AS.',
        },
        {
          label: `Shodan asn:AS${asNumber}`,
          url: `https://www.shodan.io/search?query=asn%3AAS${asNumber}`,
          note: 'Indexed services across the whole AS — scope-check before using.',
        },
        {
          label: `Censys autonomous_system.asn:${asNumber}`,
          url: `https://search.censys.io/search?resource=hosts&q=autonomous_system.asn%3A${asNumber}`,
          note: 'Host inventory for the AS.',
        },
      ],
    });
  }

  return groups;
}
