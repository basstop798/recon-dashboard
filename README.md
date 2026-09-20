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

Every variable is optional; [`.env.example`](.env.example) is a copyable
template. Set both auth variables for anything reachable from the internet.

| Variable | Default | Purpose |
| --- | --- | --- |
| `BULLETRECON_AUTH_USER` | — | Username for HTTP Basic auth. Auth is off unless this **and** the password are set. |
| `BULLETRECON_AUTH_PASSWORD` | — | Password for HTTP Basic auth, covering every route including the API. Use ASCII. |
| `BULLETRECON_DNS_SERVERS` | system resolver | Comma-separated resolver IPs (e.g. `1.1.1.1,8.8.8.8`). Deliberately not defaulted to a public resolver: that would send every target you scan to a third party. Set it when the host's own resolver is a broken stub. |
| `BULLETRECON_RATE_PER_CLIENT` | `5` | Scans per client per window. |
| `BULLETRECON_RATE_PER_INSTANCE` | `60` | Scans per window across all clients. |
| `BULLETRECON_RATE_WINDOW_MS` | `600000` | Window length (10 minutes). |
| `BULLETRECON_MAX_CONCURRENT` | `3` | Simultaneous in-flight scans. |
| `BULLETRECON_TRUST_PROXY` | `true` | Set to `false` when the app is exposed directly to the internet, so forged `X-Forwarded-For` headers cannot mint fresh rate-limit buckets. Every client then shares one bucket. |
| `BULLETRECON_ALLOWED_ORIGINS` | — | Extra origins permitted to call the API, comma-separated. Only needed if you serve the UI from a different host than the API. |

The former `PASSIVE_RECON_*` names still work as a fallback, so a deployment
configured before the rename keeps running.

No API keys are required. Sources that need one are offered as pivot links
instead, so lookups run in your browser under your account rather than through
a server-side key you did not choose.

## Hosting it publicly

Read this part before you expose it. A hosted passive-recon tool is an
attractive proxy: whoever clicks "scan" is anonymous, but the requests that
reach the OSINT indexes and the target come from **your** server's IP.

### What protects the deployment

Four gates run before any network work happens, in this order:

1. **Origin check** — refuses cross-site browser requests. This is not CORS and
   does not stop `curl`; it stops another site driving scans from its visitors'
   browsers on your quota.
2. **Per-client window** — 5 scans / 10 minutes by default. The weakest gate,
   because client identity comes from a forwarding header.
3. **Per-instance window** — 60 scans / 10 minutes in total. Header spoofing
   does not get around this one; it is what keeps your IP in good standing with
   crt.sh and the other upstreams.
4. **Concurrency cap** — 3 in-flight scans. This is what protects CPU, sockets
   and platform execution limits.

Scans are metered *after* input validation, so a typo never costs a slot.

### Known limits of those gates

- **State is per-process and in memory.** On a single VM or container the limits
  hold exactly. On serverless (Vercel, Lambda) each warm instance keeps its own
  counters, so the real ceiling is the configured limit × live instances. If you
  need exact global limits, put your platform's edge rate limiting in front, or
  swap the store in `lib/passive-recon/rate-limit.ts` for Redis.
- **Per-client identity is only as good as your proxy.** Behind a load balancer
  that overwrites `X-Forwarded-For` it is reliable. Exposed directly, it is
  forgeable — set `BULLETRECON_TRUST_PROXY=false` there.

### Authentication

`proxy.ts` puts HTTP Basic auth in front of every route, the API included. It
is opt-in: with `BULLETRECON_AUTH_USER` and `BULLETRECON_AUTH_PASSWORD` unset,
nothing prompts and local development is unchanged. Set both in your host's
environment and an anonymous caller cannot reach the scan endpoint at all.

Credentials are compared by SHA-256 digest so the comparison time does not leak
how much of a guess was right, and a half-configured deployment (one variable
set, the other missing) fails closed rather than open. Keep the password ASCII:
browsers send UTF-8, but some Windows command-line clients re-encode non-ASCII
characters and then cannot authenticate at all.

### Target-side safety

Every outbound fetch re-runs the public-address check on **each redirect hop**,
rather than handing redirects to the runtime. Without that, a target whose
homepage answers `302 http://169.254.169.254/` walks the scan into cloud
metadata — the pre-scan guard only ever validated the domain that was typed in,
and the response body flows into the tech and JavaScript modules. Non-HTTP
redirect schemes and chains longer than five hops are refused outright.

The favicon is inlined by the server as a `data:` URI, so displaying it never
makes the operator's own browser connect to the host under research.

### Logging and privacy

Each scan writes one JSON line to stdout (`scan_started`, `scan_finished`,
`scan_rejected`) with the client IP — or IPv6 /64 — the target domain, duration
and module outcomes. You need this to respond if your IP is reported for abuse.
It is also personal data in most jurisdictions: mention it in your privacy
notice and set a retention period on your log collector.

The whole deployment is `Disallow: /` in robots.txt and `noindex` in page
headers, because the pages hold somebody else's attack surface.

### Deploying to Vercel

1. Push the repo and import it at [vercel.com/new](https://vercel.com/new). No
   build configuration is needed — the defaults build this app as-is.
2. Under **Settings → Environment Variables**, add at minimum
   `BULLETRECON_AUTH_USER` and `BULLETRECON_AUTH_PASSWORD`. Everything in
   [`.env.example`](.env.example) is optional beyond those two.
3. Deploy, open the URL, and expect the browser's login prompt before the
   dashboard appears.

Platform notes:

- **`maxDuration` is 60** in `app/api/passive-recon/route.ts`, which is the cap
  on Vercel's Hobby plan. A value above a plan's limit fails the deployment
  rather than being clamped. Self-hosting has no cap — raise it to 120 there if
  a slow index gets cut off. A full scan of a small domain takes ~20s.
- **Rate limits multiply per warm instance** on serverless, as described above.
- **Leave `BULLETRECON_TRUST_PROXY` unset**; Vercel sets `x-forwarded-for`.
- **Expect some upstream failures from cloud IPs.** crt.sh and similar indexes
  frequently block datacenter ranges. The per-source chips in the Subdomains and
  Archive tabs show exactly which ones refused.

### Verifying a live deployment

After deploying, confirm the gates actually work — replace `YOUR_HOST`, and add
`-u user:password` to each command if you enabled authentication:

```bash
# 0. Without credentials, everything is 401 (only if auth is configured).
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_HOST/passive-recon

# 1. A real scan streams NDJSON events.
curl -sN -X POST https://YOUR_HOST/api/passive-recon \
  -H 'Content-Type: application/json' \
  -d '{"domain":"a-domain-you-own.com"}' | head -20

# 2. The rate limiter engages (expect 429 with Retry-After on later attempts).
for i in $(seq 1 7); do
  curl -s -o /dev/null -w "%{http_code} " -X POST https://YOUR_HOST/api/passive-recon \
    -H 'Content-Type: application/json' -d '{"domain":"example.com"}'
done; echo

# 3. Cross-site requests are refused (expect 403).
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://YOUR_HOST/api/passive-recon \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"domain":"example.com"}'

# 4. SSRF targets are refused (expect 400).
curl -s -X POST https://YOUR_HOST/api/passive-recon \
  -H 'Content-Type: application/json' -d '{"domain":"localhost"}'
```

Run the first one against a domain **you own** as the first real scan: the
multi-source merge logic has only ever been exercised against upstreams that
returned errors, never live payloads.

## Scope and legality

Passive collection is not permission. Confirm the target is in scope for a
programme you are authorised to test before acting on anything this tool
surfaces — the Pivots tab links straight to the HackerOne, Bugcrowd,
disclose.io and `security.txt` lookups for exactly that.
