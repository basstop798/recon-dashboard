# BulletRecon

A one-click passive reconnaissance dashboard for bug bounty and authorised
security work. Enter a domain, press one button, and ten OSINT modules run in
parallel and stream their results into a single triaged view.

**Nothing here attacks anything.** There is no port scanning, no directory
brute-forcing and no parameter fuzzing. The tool collects what public indexes
already hold, resolves DNS, reads the target's own published files — and then
hands you wordlists for the tooling you run under your own authorisation.

## What one scan does

| Module | What it collects |
| --- | --- |
| **Subdomain Aggregation** | crt.sh, Cert Spotter, HackerTarget, AlienVault OTX, Anubis and urlscan.io, merged with per-host source attribution |
| **Host Resolution & Takeover** | Resolves every discovered host, fingerprints CNAMEs against ~45 providers and flags dangling delegations |
| **DNS Records** | A, AAAA, MX, TXT, NS, CNAME, SOA and CAA |
| **Email Security** | SPF, DMARC, CAA, MX and common DKIM selectors, with the spoofing posture spelled out |
| **Domain & Network Intel** | RDAP registration data plus origin-AS ownership via Team Cymru's DNS service |
| **Technology & Headers** | Header/cookie/markup fingerprinting, a security-header audit with an A–F grade, and cookie flags |
| **JS Endpoints & Secrets** | Endpoint mining (LinkFinder-style), credential patterns (SecretFinder-style), source maps and in-scope hosts named by bundles |
| **Archived URLs** | Wayback CDX, Common Crawl, OTX and urlscan.io |
| **URL Intelligence** | gf-style pattern buckets, a parameter wordlist classified by bug class, sensitive files, cloud assets and third-party hosts |
| **Recon Extras** | robots.txt, sitemaps, security.txt, the Shodan favicon hash, and standard `/.well-known/` files |

On top of those, the dashboard derives a **findings feed** (severity-ranked,
with the evidence attached), generates **70 search dorks** across Google, Bing,
DuckDuckGo, GitHub, GitLab, grep.app and SearchCode, and builds **40+ OSINT
pivot links** — including favicon-hash pivots into Shodan/FOFA/ZoomEye and ASN
pivots once the scan knows the hosting network.

## Exports

Everything leaves in the shape the next tool expects: **JSON** (full bundle),
**Markdown** (write-up ready), **text**, **CSV** (findings only) and four
newline-delimited wordlists — `hosts.txt`, `urls.txt`, `params.txt`,
`endpoints.txt`.

## The passivity contract

Enforced in `app/api/passive-recon/route.ts`, which is the only place that
touches the network:

- **Third-party indexes** are asked for data they already hold.
- **DNS** covers the apex plus a capped sweep of discovered hosts. These are
  ordinary recursive lookups — the same ones a browser makes before opening any
  connection — so nothing reaches the target's web servers.
- **The target** receives one homepage `GET`, up to 12 same-origin
  `<script src>` files it advertises, and a fixed, short list of standardised
  public files (robots.txt, sitemap, security.txt, favicon, `/.well-known/*`,
  ads.txt, humans.txt). That is a browser's first visit — a published set, never
  a wordlist.

Two gates run before any of it: `sanitizeDomain` rejects anything that is not a
public registrable hostname, and `assertPublicHost` refuses targets that resolve
to loopback, RFC1918 or cloud-metadata addresses.

Secrets found in JavaScript are **redacted** before they reach the UI or any
export, because reports get pasted into tickets and screenshots.

## Running it

```bash
npm install
npm run dev     # http://localhost:3000
```

### Configuration

| Variable | Purpose |
| --- | --- |
| `PASSIVE_RECON_DNS_SERVERS` | Comma-separated resolver IPs (e.g. `1.1.1.1,8.8.8.8`). Optional, and deliberately not defaulted to a public resolver: that would send every target you scan to a third party. Set it when the host's own resolver is a broken stub. |

No API keys are required. Sources that need one are offered as pivot links
instead, so lookups run in your browser under your account rather than through
a server-side key you did not choose.

## Scope and legality

Passive collection is not permission. Confirm the target is in scope for a
programme you are authorised to test before acting on anything this tool
surfaces — the Pivots tab links straight to the HackerOne, Bugcrowd,
disclose.io and `security.txt` lookups for exactly that.
