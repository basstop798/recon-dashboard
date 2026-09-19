/**
 * Shared contract between the passive-recon route handler and the dashboard UI.
 *
 * The route streams newline-delimited JSON (NDJSON); every line is one `ScanEvent`.
 * Keeping the event union here means the client can exhaustively narrow on
 * `event.type` / `event.module` instead of casting `any`.
 */

export const MODULE_IDS = [
  'subdomains',
  'takeover',
  'dns',
  'mail',
  'whois',
  'tech',
  'js-endpoints',
  'archived',
  'url-intel',
  'meta',
] as const;

export type ModuleId = (typeof MODULE_IDS)[number];

export const MODULE_LABELS: Record<ModuleId, string> = {
  subdomains: 'Subdomain Aggregation',
  takeover: 'Host Resolution & Takeover',
  dns: 'DNS Records',
  mail: 'Email Security',
  whois: 'Domain & Network Intel',
  tech: 'Technology & Headers',
  'js-endpoints': 'JS Endpoints & Secrets',
  archived: 'Archived URLs',
  'url-intel': 'URL Intelligence',
  meta: 'Recon Extras',
};

export const MODULE_DESCRIPTIONS: Record<ModuleId, string> = {
  subdomains: 'crt.sh, CertSpotter, HackerTarget, OTX, Anubis, urlscan',
  takeover: 'CNAME fingerprinting for dangling / claimable hosts',
  dns: 'A / AAAA / MX / TXT / NS / CNAME / SOA / CAA / SRV',
  mail: 'SPF, DMARC, MX and CAA posture (spoofing surface)',
  whois: 'RDAP registration data plus ASN / netblock ownership',
  tech: 'Fingerprint, security-header audit, cookie flags',
  'js-endpoints': 'Endpoint mining, secret patterns, source maps',
  archived: 'Wayback CDX, Common Crawl, OTX, urlscan',
  'url-intel': 'Parameters, vuln-pattern buckets, cloud assets',
  meta: 'robots, sitemap, security.txt, favicon, well-known',
};

/** Coarse grouping used by the dashboard to lay the module cards out. */
export const MODULE_GROUPS: ReadonlyArray<{
  label: string;
  modules: readonly ModuleId[];
}> = [
  { label: 'Attack surface', modules: ['subdomains', 'takeover', 'url-intel'] },
  { label: 'Infrastructure', modules: ['dns', 'mail', 'whois'] },
  { label: 'Application', modules: ['tech', 'js-endpoints', 'archived', 'meta'] },
];

/* -------------------------------------------------------------------------- */
/* Findings                                                                   */
/* -------------------------------------------------------------------------- */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export type Severity = (typeof SEVERITIES)[number];

/** Descending urgency, so findings sort with the scary ones first. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * A triage-ready observation derived from module payloads.
 *
 * Findings are *derived*, never streamed: `buildFindings` runs over a finished
 * (or partial) report so the dashboard, the Markdown export and the JSON export
 * can never disagree about what the scan actually said.
 */
export interface Finding {
  /** Stable within one report — used as a React key and for de-duplication. */
  id: string;
  module: ModuleId;
  severity: Severity;
  title: string;
  detail: string;
  /** Verbatim supporting data (a header, a record, a URL). */
  evidence?: string;
}

/* -------------------------------------------------------------------------- */
/* Per-module payloads                                                        */
/* -------------------------------------------------------------------------- */

/** Per-upstream outcome, so the UI can show which OSINT source degraded. */
export interface SourceStat {
  source: string;
  ok: boolean;
  count: number;
  error?: string;
}

export interface SubdomainRecord {
  host: string;
  /** Which upstream(s) reported this host — corroboration signal. */
  sources: string[];
}

export type Confidence = 'high' | 'medium' | 'low';

export interface Technology {
  name: string;
  category: string;
  /** The header/cookie/markup that produced the match, for auditability. */
  evidence: string;
  confidence: Confidence;
}

export interface HeaderRecord {
  name: string;
  value: string;
}

export interface SubdomainsPayload {
  subdomains: SubdomainRecord[];
  sources: SourceStat[];
  truncated: boolean;
}

/** One resolved host from the takeover sweep. */
export interface HostResolution {
  host: string;
  addresses: string[];
  cname: string | null;
  /** Fingerprinted provider behind the CNAME, when recognised. */
  service: string | null;
  status: 'live' | 'dangling' | 'nxdomain' | 'error';
  /** True when the CNAME points at a known service that no longer claims it. */
  takeover: boolean;
  severity: Severity;
  note: string;
}

export interface TakeoverPayload {
  /** Hosts known to the subdomain module. */
  total: number;
  /** Hosts actually resolved (the sweep is capped). */
  checked: number;
  live: number;
  hosts: HostResolution[];
}

/** RFC 7505 null-MX marker: the domain states that it accepts no mail. */
export const NULL_MX = '.';

export interface DnsRecord {
  type: string;
  value: string;
  /** MX only — lower wins. */
  priority?: number;
}

export interface DnsPayload {
  records: DnsRecord[];
  /** One entry per record type queried. */
  sources: SourceStat[];
}

export interface SpfInfo {
  found: boolean;
  raw: string | null;
  /** `include:` targets — each one widens who may send as this domain. */
  includes: string[];
  mechanisms: string[];
  /** The terminating `all` qualifier: `-all`, `~all`, `?all`, `+all`. */
  all: string | null;
  /** RFC 7208 caps DNS-querying mechanisms at 10. */
  lookups: number;
}

export interface DmarcInfo {
  found: boolean;
  raw: string | null;
  policy: string | null;
  subdomainPolicy: string | null;
  percent: number | null;
  rua: string[];
  ruf: string[];
}

export interface MailPayload {
  spf: SpfInfo;
  dmarc: DmarcInfo;
  /** Sorted by preference. */
  mx: DnsRecord[];
  caa: string[];
  /** Selectors probed for a DKIM key, and what the zone published for them. */
  dkim: Array<{ selector: string; found: boolean; revoked: boolean }>;
}

export interface DomainWhois {
  found: boolean;
  registrar: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  expiresAt: string | null;
  statuses: string[];
  nameservers: string[];
  abuseContacts: string[];
  dnssec: boolean | null;
}

export interface NetworkRecord {
  ip: string;
  org: string | null;
  asn: string | null;
  asnName: string | null;
  prefix: string | null;
  country: string | null;
}

export interface WhoisPayload {
  domain: DomainWhois;
  networks: NetworkRecord[];
  sources: SourceStat[];
}

/** Cookie *attributes* only — values are never captured. See route.ts. */
export interface CookieRecord {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

export interface SecurityHeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  /** Severity attached to the header being *absent*. */
  severity: Severity;
  advice: string;
}

export interface PageIdentity {
  title: string | null;
  description: string | null;
  generator: string | null;
  ogImage: string | null;
  lang: string | null;
}

export interface TechPayload {
  finalUrl: string;
  status: number;
  redirected: boolean;
  technologies: Technology[];
  headers: HeaderRecord[];
  cookies: CookieRecord[];
  security: SecurityHeaderCheck[];
  /** A..F over the security-header checks. */
  grade: string;
  identity: PageIdentity;
}

export interface SecretMatch {
  rule: string;
  severity: Severity;
  /** Redacted — enough to recognise, never enough to use. */
  match: string;
  source: string;
}

export interface JsEndpointsPayload {
  scripts: string[];
  endpoints: string[];
  scanned: number;
  inlineScripts: number;
  truncated: boolean;
  secrets: SecretMatch[];
  /** `//# sourceMappingURL=` references — original source is often readable. */
  sourceMaps: string[];
  /** In-scope hosts mentioned by the bundles. */
  hosts: string[];
}

export interface ArchivedPayload {
  urls: string[];
  sources: SourceStat[];
  truncated: boolean;
}

export interface ParamRecord {
  name: string;
  count: number;
  /** Vulnerability classes the parameter name is associated with. */
  classes: string[];
  example: string;
}

export interface PatternBucket {
  id: string;
  label: string;
  description: string;
  severity: Severity;
  urls: string[];
  total: number;
}

export interface CloudAsset {
  provider: string;
  asset: string;
  url: string;
}

export interface HostCount {
  host: string;
  count: number;
}

export interface UrlIntelPayload {
  /** How many URLs went into the analysis (archive + sitemap + JS). */
  analyzed: number;
  parameters: ParamRecord[];
  buckets: PatternBucket[];
  juicyFiles: string[];
  cloudAssets: CloudAsset[];
  thirdPartyHosts: HostCount[];
  inScopeHosts: HostCount[];
  extensions: HostCount[];
}

export interface RobotsPayload {
  found: boolean;
  url: string;
  disallowed: string[];
  sitemaps: string[];
}

export interface SitemapPayload {
  found: boolean;
  /** Sitemap documents that actually resolved. */
  documents: string[];
  urls: string[];
  truncated: boolean;
}

export interface SecurityTxtField {
  name: string;
  value: string;
}

export interface SecurityTxtPayload {
  found: boolean;
  url: string | null;
  /** Ordered, duplicates preserved — multiple `Contact:` lines are normal. */
  fields: SecurityTxtField[];
}

export interface FaviconPayload {
  found: boolean;
  url: string | null;
  /** Shodan-compatible `http.favicon.hash` value (signed int32). */
  hash: number | null;
  bytes: number | null;
}

export interface WellKnownFile {
  path: string;
  url: string;
  found: boolean;
  status: number | null;
  contentType: string | null;
  bytes: number | null;
  /** First few hundred characters, for triage without leaving the dashboard. */
  preview: string | null;
}

export interface MetaPayload {
  robots: RobotsPayload;
  sitemap: SitemapPayload;
  securityTxt: SecurityTxtPayload;
  favicon: FaviconPayload;
  wellKnown: WellKnownFile[];
}

/** Maps each module to the shape it resolves with. */
export interface ModulePayloads {
  subdomains: SubdomainsPayload;
  takeover: TakeoverPayload;
  dns: DnsPayload;
  mail: MailPayload;
  whois: WhoisPayload;
  tech: TechPayload;
  'js-endpoints': JsEndpointsPayload;
  archived: ArchivedPayload;
  'url-intel': UrlIntelPayload;
  meta: MetaPayload;
}

/* -------------------------------------------------------------------------- */
/* Stream events                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Distributed over `ModuleId` so that narrowing on `module` also narrows `data`.
 * `if (e.module === 'tech')` gives you `TechPayload` with no cast.
 */
export type ModuleDoneEvent = {
  [K in ModuleId]: {
    type: 'module_done';
    module: K;
    durationMs: number;
    data: ModulePayloads[K];
  };
}[ModuleId];

export type ScanEvent =
  | { type: 'scan_start'; domain: string; startedAt: string; modules: ModuleId[] }
  | { type: 'module_start'; module: ModuleId }
  | ModuleDoneEvent
  | { type: 'module_error'; module: ModuleId; durationMs: number; error: string }
  | { type: 'scan_complete'; finishedAt: string; durationMs: number }
  | { type: 'scan_error'; error: string };

export type ModuleStatus = 'pending' | 'running' | 'done' | 'error';

export interface ModuleState<K extends ModuleId = ModuleId> {
  status: ModuleStatus;
  durationMs: number | null;
  error: string | null;
  data: ModulePayloads[K] | null;
}

/** Aggregated client-side state, and the core of the exported JSON report. */
export interface ScanReport {
  domain: string;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  modules: { [K in ModuleId]: ModuleState<K> };
}

/* -------------------------------------------------------------------------- */
/* Operator-driven pivots (no network access of their own)                    */
/* -------------------------------------------------------------------------- */

export interface Dork {
  label: string;
  query: string;
  url: string;
}

export interface DorkGroup {
  engine: string;
  description: string;
  dorks: Dork[];
}

export interface PivotLink {
  label: string;
  url: string;
  note: string;
}

export interface PivotGroup {
  category: string;
  links: PivotLink[];
}
