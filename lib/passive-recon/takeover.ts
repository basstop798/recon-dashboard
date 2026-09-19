/**
 * Subdomain-takeover fingerprints.
 *
 * Pure lookup tables plus the classification rule; the DNS work itself lives in
 * `dns-records.ts` (which owns `node:dns`) so this file stays isomorphic and the
 * dashboard can render the same service names and notes the sweep produced.
 *
 * Fingerprints follow the community `can-i-take-over-xyz` catalogue: a CNAME
 * pointing at a provider is normal, the finding is a CNAME pointing at a
 * provider that *no longer claims the name*. `status` records whether that
 * situation is known-exploitable, provider-dependent, or a false lead.
 */

import type { HostResolution, Severity } from './types';

export type TakeoverStatus = 'confirmed' | 'edge-case' | 'not-vulnerable';

export interface TakeoverFingerprint {
  service: string;
  /** Matched as a CNAME suffix, case-insensitively. */
  suffixes: readonly string[];
  status: TakeoverStatus;
  note: string;
}

export const TAKEOVER_FINGERPRINTS: readonly TakeoverFingerprint[] = [
  {
    service: 'AWS S3',
    suffixes: ['s3.amazonaws.com', 's3-website', '.s3.'],
    status: 'confirmed',
    note: 'A released bucket name can be re-created by anyone in the same region.',
  },
  {
    service: 'AWS Elastic Beanstalk',
    suffixes: ['elasticbeanstalk.com'],
    status: 'edge-case',
    note: 'Claimable only where the environment name is still free in that region.',
  },
  {
    service: 'GitHub Pages',
    suffixes: ['github.io', 'githubusercontent.com'],
    status: 'confirmed',
    note: 'An unclaimed Pages custom domain can be bound by another repository.',
  },
  {
    service: 'Bitbucket',
    suffixes: ['bitbucket.io'],
    status: 'confirmed',
    note: 'Unclaimed Bitbucket Pages hostnames can be bound by another account.',
  },
  {
    service: 'Heroku',
    suffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'],
    status: 'confirmed',
    note: 'A deleted Heroku app frees the hostname for immediate re-registration.',
  },
  {
    service: 'Azure',
    suffixes: [
      'azurewebsites.net',
      'cloudapp.net',
      'cloudapp.azure.com',
      'trafficmanager.net',
      'blob.core.windows.net',
      'azureedge.net',
      'azurefd.net',
      'azure-api.net',
    ],
    status: 'confirmed',
    note: 'Azure resource names are globally unique and reusable once released.',
  },
  {
    service: 'Google Cloud Storage',
    suffixes: ['storage.googleapis.com', 'appspot.com'],
    status: 'edge-case',
    note: 'Bucket names are reusable, but domain-named buckets need verification.',
  },
  {
    service: 'Shopify',
    suffixes: ['myshopify.com', 'shops.myshopify.com'],
    status: 'edge-case',
    note: 'Historically claimable; Shopify now blocks most re-binding.',
  },
  {
    service: 'Zendesk',
    suffixes: ['zendesk.com'],
    status: 'confirmed',
    note: 'A cancelled Zendesk subdomain can be registered by a new trial account.',
  },
  {
    service: 'Freshdesk',
    suffixes: ['freshdesk.com'],
    status: 'edge-case',
    note: 'Depends on whether the helpdesk name was fully released.',
  },
  {
    service: 'Help Scout',
    suffixes: ['helpscoutdocs.com'],
    status: 'confirmed',
    note: 'Docs sites release their custom domain on cancellation.',
  },
  {
    service: 'Helpjuice',
    suffixes: ['helpjuice.com'],
    status: 'confirmed',
    note: 'Knowledge-base custom domains are re-bindable.',
  },
  {
    service: 'UserVoice',
    suffixes: ['uservoice.com'],
    status: 'confirmed',
    note: 'Abandoned feedback portals are claimable.',
  },
  {
    service: 'Intercom',
    suffixes: ['custom.intercom.help', 'intercom.help'],
    status: 'confirmed',
    note: 'Help Center custom domains can be re-attached to another workspace.',
  },
  {
    service: 'Tumblr',
    suffixes: ['domains.tumblr.com', 'tumblr.com'],
    status: 'confirmed',
    note: 'A free blog can claim an unused custom domain.',
  },
  {
    service: 'WordPress.com',
    suffixes: ['wordpress.com'],
    status: 'edge-case',
    note: 'Requires the domain to be unmapped on the WordPress.com side.',
  },
  {
    service: 'Ghost',
    suffixes: ['ghost.io'],
    status: 'confirmed',
    note: 'A deleted Ghost(Pro) publication frees the custom domain.',
  },
  {
    service: 'Webflow',
    suffixes: ['proxy-ssl.webflow.com', 'webflow.io'],
    status: 'confirmed',
    note: 'Unclaimed Webflow custom domains can be added to another project.',
  },
  {
    service: 'Pantheon',
    suffixes: ['pantheonsite.io'],
    status: 'confirmed',
    note: 'Released Pantheon site names are re-registrable.',
  },
  {
    service: 'Unbounce',
    suffixes: ['unbouncepages.com'],
    status: 'confirmed',
    note: 'Landing-page domains are claimable after the page is deleted.',
  },
  {
    service: 'Readme.io',
    suffixes: ['readme.io'],
    status: 'confirmed',
    note: 'Docs subdomains are claimable once released.',
  },
  {
    service: 'Read the Docs',
    suffixes: ['readthedocs.io'],
    status: 'confirmed',
    note: 'Project slugs are reusable after deletion.',
  },
  {
    service: 'Surge.sh',
    suffixes: ['surge.sh'],
    status: 'confirmed',
    note: 'Any Surge account can publish to an unclaimed domain.',
  },
  {
    service: 'Netlify',
    suffixes: ['netlify.app', 'netlify.com'],
    status: 'edge-case',
    note: 'Netlify verifies most custom domains, but stale site names still occur.',
  },
  {
    service: 'Vercel',
    suffixes: ['vercel.app', 'vercel-dns.com', 'now.sh'],
    status: 'not-vulnerable',
    note: 'Vercel requires domain verification before binding.',
  },
  {
    service: 'Cloudflare Pages',
    suffixes: ['pages.dev'],
    status: 'edge-case',
    note: 'Requires the project name to be free and the domain unverified.',
  },
  {
    service: 'Fastly',
    suffixes: ['fastly.net', 'fastlylb.net'],
    status: 'edge-case',
    note: 'Depends on the service configuration; usually a misroute, not a takeover.',
  },
  {
    service: 'AWS CloudFront',
    suffixes: ['cloudfront.net'],
    status: 'not-vulnerable',
    note: 'CloudFront validates alternate domain names against a certificate.',
  },
  {
    service: 'Akamai',
    suffixes: ['edgekey.net', 'edgesuite.net', 'akamaiedge.net'],
    status: 'not-vulnerable',
    note: 'Akamai edge hostnames are not self-service claimable.',
  },
  {
    service: 'Campaign Monitor',
    suffixes: ['createsend.com'],
    status: 'confirmed',
    note: 'An unclaimed sending domain can be attached to another account.',
  },
  {
    service: 'Desk.com',
    suffixes: ['desk.com'],
    status: 'confirmed',
    note: 'Legacy support portals are claimable.',
  },
  {
    service: 'Statuspage',
    suffixes: ['statuspage.io'],
    status: 'edge-case',
    note: 'Atlassian has tightened claiming; still worth confirming.',
  },
  {
    service: 'Tilda',
    suffixes: ['tilda.ws'],
    status: 'confirmed',
    note: 'Free projects can bind released custom domains.',
  },
  {
    service: 'Strikingly',
    suffixes: ['s.strikinglydns.com', 'strikingly.com'],
    status: 'confirmed',
    note: 'Released sites free their custom domain.',
  },
  {
    service: 'Big Cartel',
    suffixes: ['bigcartel.com'],
    status: 'confirmed',
    note: 'Closed shops release their custom domain.',
  },
  {
    service: 'LaunchRock',
    suffixes: ['launchrock.com'],
    status: 'confirmed',
    note: 'Abandoned launch pages are claimable.',
  },
  {
    service: 'GetResponse',
    suffixes: ['gr8.com'],
    status: 'confirmed',
    note: 'Landing pages release their domain on deletion.',
  },
  {
    service: 'Wix',
    suffixes: ['wixdns.net', 'wix.com'],
    status: 'edge-case',
    note: 'Wix requires verification for most custom domains.',
  },
  {
    service: 'Squarespace',
    suffixes: ['squarespace.com'],
    status: 'edge-case',
    note: 'Depends on whether the domain is still attached to a site.',
  },
  {
    service: 'HubSpot',
    suffixes: ['hubspot.net', 'hs-sites.com'],
    status: 'edge-case',
    note: 'Content hosting domains can linger after a portal is closed.',
  },
  {
    service: 'Fly.io',
    suffixes: ['fly.dev'],
    status: 'edge-case',
    note: 'App names are reusable once an app is destroyed.',
  },
  {
    service: 'Render',
    suffixes: ['onrender.com'],
    status: 'edge-case',
    note: 'Service names are reusable after deletion.',
  },
  {
    service: 'Firebase Hosting',
    suffixes: ['firebaseapp.com', 'web.app', 'firebaseio.com'],
    status: 'edge-case',
    note: 'Project IDs are not reusable, but unverified custom domains linger.',
  },
  {
    service: 'AfterShip',
    suffixes: ['aftership.com'],
    status: 'confirmed',
    note: 'Tracking pages release their custom domain.',
  },
  {
    service: 'Aha!',
    suffixes: ['ideas.aha.io'],
    status: 'confirmed',
    note: 'Ideas portals are claimable once released.',
  },
  {
    service: 'Pingdom',
    suffixes: ['stats.pingdom.com'],
    status: 'confirmed',
    note: 'Public status pages are claimable.',
  },
  {
    service: 'Ngrok',
    suffixes: ['ngrok.io', 'ngrok-free.app'],
    status: 'edge-case',
    note: 'A CNAME to an ephemeral tunnel is almost always stale infrastructure.',
  },
];

/** Matches a CNAME target against the fingerprint catalogue. */
export function fingerprintCname(cname: string): TakeoverFingerprint | null {
  const target = cname.toLowerCase().replace(/\.+$/, '');

  for (const fingerprint of TAKEOVER_FINGERPRINTS) {
    for (const suffix of fingerprint.suffixes) {
      if (target === suffix || target.endsWith(`.${suffix}`) || target.includes(suffix)) {
        return fingerprint;
      }
    }
  }

  return null;
}

/**
 * Turns a resolution outcome into a severity and an operator-facing note.
 *
 * A dangling CNAME at a `confirmed` provider is the classic takeover and is
 * reported `high`; an `edge-case` provider is `medium` because exploitability
 * depends on that provider's current claiming rules; a dangling CNAME at an
 * unrecognised target is still `medium` — unknown provider, same broken link.
 */
export function classifyResolution(input: {
  host: string;
  addresses: string[];
  cname: string | null;
  resolves: boolean;
}): Pick<HostResolution, 'status' | 'service' | 'takeover' | 'severity' | 'note'> {
  const fingerprint = input.cname ? fingerprintCname(input.cname) : null;
  const service = fingerprint?.service ?? null;

  if (input.cname && !input.resolves) {
    if (fingerprint && fingerprint.status !== 'not-vulnerable') {
      const severity: Severity = fingerprint.status === 'confirmed' ? 'high' : 'medium';
      return {
        status: 'dangling',
        service,
        takeover: true,
        severity,
        note: `Dangling CNAME to ${service}. ${fingerprint.note}`,
      };
    }

    return {
      status: 'dangling',
      service,
      takeover: false,
      severity: 'medium',
      note: 'CNAME target does not resolve — the delegation is broken and may be claimable.',
    };
  }

  if (!input.resolves) {
    return {
      status: 'nxdomain',
      service,
      takeover: false,
      severity: 'info',
      note: 'Host does not currently resolve.',
    };
  }

  if (service) {
    return {
      status: 'live',
      service,
      takeover: false,
      severity: 'info',
      note: `Hosted on ${service}${fingerprint?.status === 'confirmed' ? ' — re-check if the service is ever decommissioned.' : '.'}`,
    };
  }

  return {
    status: 'live',
    service: null,
    takeover: false,
    severity: 'info',
    note: input.cname ? `Aliased to ${input.cname}.` : 'Resolves directly.',
  };
}
