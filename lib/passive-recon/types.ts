/**
 * Shared contract between the passive-recon route handler and the dashboard UI.
 *
 * The route streams newline-delimited JSON (NDJSON); every line is one `ScanEvent`.
 * Keeping the event union here means the client can exhaustively narrow on
 * `event.type` / `event.module` instead of casting `any`.
 */

export const MODULE_IDS = [
  'subdomains',
  'archived',
  'tech',
  'js-endpoints',
] as const;

export type ModuleId = (typeof MODULE_IDS)[number];

export const MODULE_LABELS: Record<ModuleId, string> = {
  subdomains: 'Subdomain Aggregation',
  archived: 'Archived URLs',
  tech: 'Technology Fingerprint',
  'js-endpoints': 'Static JS Endpoints',
};

export const MODULE_DESCRIPTIONS: Record<ModuleId, string> = {
  subdomains: 'HackerTarget + crt.sh certificate transparency',
  archived: 'Wayback Machine CDX + Common Crawl index',
  tech: 'Single HTTP GET, response-header fingerprinting',
  'js-endpoints': 'Static parse of same-origin script references',
};

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
  /** The header/cookie that produced the match, for auditability. */
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
}

export interface ArchivedPayload {
  urls: string[];
  sources: SourceStat[];
  truncated: boolean;
}

export interface TechPayload {
  finalUrl: string;
  status: number;
  technologies: Technology[];
  headers: HeaderRecord[];
  /** Cookie *names* only — values are never captured. See route.ts. */
  cookieNames: string[];
}

export interface JsEndpointsPayload {
  scripts: string[];
  endpoints: string[];
  scanned: number;
  truncated: boolean;
}

/** Maps each module to the shape it resolves with. */
export interface ModulePayloads {
  subdomains: SubdomainsPayload;
  archived: ArchivedPayload;
  tech: TechPayload;
  'js-endpoints': JsEndpointsPayload;
}

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

/** Aggregated client-side state, also the shape of the exported JSON report. */
export interface ScanReport {
  domain: string;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  modules: { [K in ModuleId]: ModuleState<K> };
  dorks: DorkGroup[];
}

export type DorkEngine = 'Google' | 'Bing' | 'GitHub';

export interface Dork {
  label: string;
  query: string;
  url: string;
}

export interface DorkGroup {
  engine: DorkEngine;
  dorks: Dork[];
}
