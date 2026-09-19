/**
 * URL intelligence — the triage layer over everything that produced a URL.
 *
 * Hunters run `gau | gf xss | qsreplace` and `ParamSpider` to turn a wall of
 * archived URLs into a short list worth touching. This module does the same
 * work in-process and without sending anything anywhere: it only reads URLs the
 * archive, sitemap and JS modules already collected.
 *
 * Everything here is a *lead*. A parameter named `redirect` is not an open
 * redirect; it is the URL you test first. The dashboard labels them that way.
 */

import type {
  CloudAsset,
  HostCount,
  ParamRecord,
  PatternBucket,
  Severity,
  UrlIntelPayload,
} from './types';

const LIMITS = {
  urls: 25_000,
  parameters: 400,
  bucketUrls: 250,
  juicyFiles: 300,
  cloudAssets: 200,
  hosts: 300,
  extensions: 40,
} as const;

/* -------------------------------------------------------------------------- */
/* Parameter classification                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Parameter names associated with each vulnerability class.
 *
 * Adapted from the `gf` pattern set that grew out of real bug bounty reports —
 * these are the names that historically sat in front of the bug, not a guess at
 * what a developer might call something.
 */
const PARAM_CLASSES: ReadonlyArray<{ id: string; names: readonly string[] }> = [
  {
    id: 'open-redirect',
    names: [
      'url', 'redirect', 'redirect_uri', 'redirect_url', 'redir', 'return',
      'return_url', 'returnurl', 'returnto', 'next', 'goto', 'dest',
      'destination', 'continue', 'forward', 'out', 'target', 'rurl', 'link',
      'checkout_url', 'callback_url', 'ref_url', 'login_url', 'logout_url',
    ],
  },
  {
    id: 'ssrf',
    names: [
      'url', 'uri', 'src', 'source', 'dest', 'domain', 'host', 'site', 'feed',
      'proxy', 'fetch', 'load', 'remote', 'endpoint', 'callback', 'webhook',
      'image_url', 'imageurl', 'filename_url', 'port', 'open', 'target',
    ],
  },
  {
    id: 'lfi',
    names: [
      'file', 'filename', 'path', 'folder', 'dir', 'document', 'doc', 'root',
      'pg', 'style', 'template', 'include', 'require', 'page', 'download',
      'read', 'retrieve', 'show', 'view', 'cat', 'detail', 'pdf', 'log',
    ],
  },
  {
    id: 'sqli',
    names: [
      'id', 'select', 'where', 'order', 'sort', 'query', 'search', 'filter',
      'column', 'field', 'table', 'from', 'row', 'report', 'update', 'delete',
      'category', 'keyword', 'number', 'user_id', 'product', 'item', 'news_id',
    ],
  },
  {
    id: 'xss',
    names: [
      'q', 's', 'search', 'query', 'keyword', 'keywords', 'term', 'message',
      'name', 'title', 'comment', 'text', 'content', 'lang', 'redirect_to',
      'callback', 'jsonp', 'email', 'value', 'data', 'html', 'body', 'error',
    ],
  },
  {
    id: 'rce-ssti',
    names: [
      'cmd', 'exec', 'command', 'execute', 'ping', 'run', 'code', 'func',
      'function', 'process', 'step', 'do', 'action', 'op', 'option', 'module',
      'payload', 'template', 'preview', 'eval', 'shell', 'system',
    ],
  },
  {
    id: 'idor',
    names: [
      'id', 'uid', 'user', 'user_id', 'userid', 'account', 'account_id',
      'customer_id', 'order', 'order_id', 'invoice', 'doc_id', 'profile',
      'member', 'group_id', 'team_id', 'org_id', 'key', 'number', 'no', 'email',
    ],
  },
  {
    id: 'debug',
    names: [
      'debug', 'test', 'trace', 'verbose', 'dev', 'admin', 'env', 'config',
      'source', 'mode', 'status', 'phpinfo', 'stage', 'sandbox',
    ],
  },
  {
    id: 'upload',
    names: ['file', 'upload', 'attachment', 'photo', 'image', 'avatar', 'media'],
  },
  {
    id: 'secret-in-url',
    names: [
      'token', 'access_token', 'id_token', 'refresh_token', 'api_key', 'apikey',
      'key', 'secret', 'client_secret', 'password', 'passwd', 'pwd', 'auth',
      'authorization', 'session', 'sessionid', 'sid', 'jwt', 'signature', 'sig',
      'code', 'otp', 'hash',
    ],
  },
];

const CLASS_LABELS: Record<string, string> = {
  'open-redirect': 'Open redirect',
  ssrf: 'SSRF',
  lfi: 'LFI / path traversal',
  sqli: 'SQL injection',
  xss: 'XSS',
  'rce-ssti': 'RCE / SSTI',
  idor: 'IDOR',
  debug: 'Debug / config',
  upload: 'File upload',
  'secret-in-url': 'Secret in URL',
};

export function classLabel(id: string): string {
  return CLASS_LABELS[id] ?? id;
}

const CLASS_INDEX: ReadonlyMap<string, string[]> = (() => {
  const index = new Map<string, string[]>();
  for (const { id, names } of PARAM_CLASSES) {
    for (const name of names) {
      const entry = index.get(name);
      if (entry) entry.push(id);
      else index.set(name, [id]);
    }
  }
  return index;
})();

/** Classes a parameter name belongs to, matched case-insensitively. */
export function classifyParam(name: string): string[] {
  const lower = name.toLowerCase();
  const exact = CLASS_INDEX.get(lower);
  if (exact) return exact;

  // Fall back to a token match so `?loginRedirectUrl=` is still recognised.
  const classes = new Set<string>();
  for (const [candidate, ids] of CLASS_INDEX) {
    if (candidate.length < 4) continue;
    if (lower.includes(candidate)) for (const id of ids) classes.add(id);
  }
  return [...classes];
}

/* -------------------------------------------------------------------------- */
/* URL buckets                                                                */
/* -------------------------------------------------------------------------- */

interface BucketSpec {
  id: string;
  label: string;
  description: string;
  severity: Severity;
  test: (url: URL, full: string) => boolean;
}

/** Paths and filenames that are interesting on sight. */
const JUICY_PATH_RE =
  /(?:^|\/)(?:\.env(?:\.[a-z]+)?|\.git(?:\/config|\/HEAD)?|\.svn|\.hg|\.DS_Store|\.htpasswd|\.htaccess|\.npmrc|\.dockerenv|dockerfile|docker-compose\.ya?ml|web\.config|wp-config\.php(?:\.bak)?|config\.(?:json|ya?ml|php|xml)|settings\.py|credentials|id_rsa|id_dsa|\.pem|\.ppk|\.key|\.p12|\.pfx|\.kdbx|backup|dump|database|db_backup|phpinfo\.php|server-status|actuator(?:\/\w+)?|debug\/pprof|swagger(?:-ui)?(?:\.(?:json|ya?ml|html))?|openapi\.(?:json|ya?ml)|graphiql|\.well-known\/openid-configuration)(?:$|[/?#.])/i;

const JUICY_EXT_RE =
  /\.(?:sql|sqlite3?|db|bak|old|orig|save|swp|backup|tar|tar\.gz|tgz|zip|rar|7z|gz|log|ini|conf|cfg|yml|yaml|env|pem|key|crt|p12|pfx|dump|csv|xls|xlsx)(?:$|[?#])/i;

const SECRET_PARAM_RE =
  /[?&](?:access_token|id_token|refresh_token|api_?key|apikey|client_secret|secret|password|passwd|pwd|auth|authorization|token|jwt|session(?:id)?|sig|signature)=[^&\s]{6,}/i;

const API_PATH_RE =
  /(?:^|\/)(?:api|graphql|gql|rest|rpc|jsonrpc|v[1-9]\d?|oauth2?|soap|wsdl)(?:$|[/?#])/i;

const AUTH_PATH_RE =
  /(?:^|\/)(?:login|signin|sign-in|logout|register|signup|sign-up|auth|sso|saml|oidc|oauth|password|reset|forgot|verify|2fa|mfa|token)(?:$|[/?#])/i;

const ADMIN_PATH_RE =
  /(?:^|\/)(?:admin|administrator|wp-admin|dashboard|console|manage|management|panel|cpanel|backend|internal|staff|moderator|sysadmin|phpmyadmin|adminer)(?:$|[/?#])/i;

const UPLOAD_PATH_RE =
  /(?:^|\/)(?:upload|uploads|files?|attachments?|media|assets\/user|documents?|import|export)(?:$|[/?#])/i;

const BUCKETS: readonly BucketSpec[] = [
  {
    id: 'secrets',
    label: 'Credentials in URL',
    description:
      'Archived URLs carrying a token, key or password in the query string. Anything archived here is public and may still be valid.',
    severity: 'high',
    test: (_url, full) => SECRET_PARAM_RE.test(full),
  },
  {
    id: 'juicy',
    label: 'Sensitive files',
    description:
      'Config, backup, key and VCS paths the crawler recorded. Confirm which still resolve before reporting.',
    severity: 'high',
    test: (url) => JUICY_PATH_RE.test(url.pathname) || JUICY_EXT_RE.test(url.pathname),
  },
  {
    id: 'admin',
    label: 'Admin & internal',
    description: 'Administrative and internal-looking routes worth an access-control test.',
    severity: 'medium',
    test: (url) => ADMIN_PATH_RE.test(url.pathname),
  },
  {
    id: 'api',
    label: 'API surface',
    description: 'REST, GraphQL and versioned endpoints — the densest source of logic bugs.',
    severity: 'info',
    test: (url) => API_PATH_RE.test(url.pathname),
  },
  {
    id: 'auth',
    label: 'Authentication flows',
    description: 'Login, SSO, registration and password-reset routes.',
    severity: 'info',
    test: (url) => AUTH_PATH_RE.test(url.pathname),
  },
  {
    id: 'upload',
    label: 'Upload & file handling',
    description: 'Routes that move files around; check type/size validation and storage ACLs.',
    severity: 'medium',
    test: (url) => UPLOAD_PATH_RE.test(url.pathname),
  },
  {
    id: 'redirect',
    label: 'Redirect candidates',
    description: 'URLs whose query string carries a redirect-shaped parameter.',
    severity: 'medium',
    test: (url) =>
      [...url.searchParams.keys()].some((key) =>
        classifyParam(key).includes('open-redirect'),
      ),
  },
  {
    id: 'ssrf',
    label: 'SSRF candidates',
    description: 'Parameters that historically take a URL or host the server then fetches.',
    severity: 'medium',
    test: (url) =>
      [...url.searchParams.keys()].some((key) => classifyParam(key).includes('ssrf')),
  },
  {
    id: 'debug',
    label: 'Debug & diagnostics',
    description: 'Debug switches, traces and status endpoints that often over-share.',
    severity: 'medium',
    test: (url) =>
      /(?:^|\/)(?:debug|trace|test|status|health|metrics|phpinfo|info|env|config)(?:$|[/?#])/i.test(
        url.pathname,
      ) ||
      [...url.searchParams.keys()].some((key) => classifyParam(key).includes('debug')),
  },
];

/* -------------------------------------------------------------------------- */
/* Cloud asset extraction                                                     */
/* -------------------------------------------------------------------------- */

interface CloudRule {
  provider: string;
  /** Returns the asset identifier (bucket/app name) or null. */
  match: (url: URL) => string | null;
}

const CLOUD_RULES: readonly CloudRule[] = [
  {
    provider: 'AWS S3',
    match: (url) => {
      const virtualHosted = url.hostname.match(
        /^([a-z0-9][a-z0-9.-]{1,61})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i,
      );
      if (virtualHosted) return virtualHosted[1];

      if (/^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i.test(url.hostname)) {
        const bucket = url.pathname.split('/').filter(Boolean)[0];
        return bucket ?? null;
      }
      return null;
    },
  },
  {
    provider: 'Google Cloud Storage',
    match: (url) => {
      if (/^storage\.(?:googleapis|cloud\.google)\.com$/i.test(url.hostname)) {
        return url.pathname.split('/').filter(Boolean)[0] ?? null;
      }
      const host = url.hostname.match(/^([a-z0-9._-]+)\.storage\.googleapis\.com$/i);
      return host?.[1] ?? null;
    },
  },
  {
    provider: 'Azure Blob',
    match: (url) =>
      url.hostname.match(/^([a-z0-9-]+)\.blob\.core\.windows\.net$/i)?.[1] ?? null,
  },
  {
    provider: 'Azure Web App',
    match: (url) =>
      url.hostname.match(/^([a-z0-9-]+)\.azurewebsites\.net$/i)?.[1] ?? null,
  },
  {
    provider: 'DigitalOcean Spaces',
    match: (url) =>
      url.hostname.match(/^([a-z0-9.-]+)\.[a-z0-9-]+\.digitaloceanspaces\.com$/i)?.[1] ??
      null,
  },
  {
    provider: 'Firebase',
    match: (url) =>
      url.hostname.match(/^([a-z0-9-]+)\.(?:firebaseio\.com|firebaseapp\.com|web\.app)$/i)?.[1] ??
      null,
  },
  {
    provider: 'Heroku',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.herokuapp\.com$/i)?.[1] ?? null,
  },
  {
    provider: 'Netlify',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.netlify\.(?:app|com)$/i)?.[1] ?? null,
  },
  {
    provider: 'Vercel',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.vercel\.app$/i)?.[1] ?? null,
  },
  {
    provider: 'Cloudflare Pages / R2',
    match: (url) =>
      url.hostname.match(/^([a-z0-9-]+)\.(?:pages\.dev|r2\.cloudflarestorage\.com)$/i)?.[1] ??
      null,
  },
  {
    provider: 'GitHub Pages',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.github\.io$/i)?.[1] ?? null,
  },
  {
    provider: 'Shopify',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.myshopify\.com$/i)?.[1] ?? null,
  },
  {
    provider: 'Zendesk',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.zendesk\.com$/i)?.[1] ?? null,
  },
  {
    provider: 'Atlassian',
    match: (url) => url.hostname.match(/^([a-z0-9-]+)\.atlassian\.net$/i)?.[1] ?? null,
  },
];

/* -------------------------------------------------------------------------- */
/* Analysis                                                                   */
/* -------------------------------------------------------------------------- */

function inScope(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

function topCounts(counter: Map<string, number>, limit: number): HostCount[] {
  return [...counter.entries()]
    .map(([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host))
    .slice(0, limit);
}

function bump(counter: Map<string, number>, key: string): void {
  counter.set(key, (counter.get(key) ?? 0) + 1);
}

/**
 * Folds every known URL into parameters, buckets, hosts and cloud assets.
 *
 * @param rawUrls Every URL the scan saw — archive, sitemap, robots and JS.
 * @param domain  The sanitised in-scope apex.
 */
export function analyzeUrls(rawUrls: readonly string[], domain: string): UrlIntelPayload {
  const buckets = BUCKETS.map((spec) => ({ spec, urls: [] as string[], total: 0 }));

  const params = new Map<string, { count: number; example: string }>();
  const thirdParty = new Map<string, number>();
  const inScopeHosts = new Map<string, number>();
  const extensions = new Map<string, number>();
  const cloud = new Map<string, CloudAsset>();
  const juicy = new Set<string>();

  let analyzed = 0;

  for (const raw of rawUrls.slice(0, LIMITS.urls)) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      continue;
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
    analyzed += 1;

    bump(inScope(url.hostname, domain) ? inScopeHosts : thirdParty, url.hostname);

    const extension = url.pathname.match(/\.([A-Za-z0-9]{1,8})$/)?.[1]?.toLowerCase();
    if (extension) bump(extensions, extension);

    for (const [name, value] of url.searchParams) {
      if (!name || name.length > 60) continue;
      const entry = params.get(name);
      if (entry) {
        entry.count += 1;
      } else {
        // Keep one concrete example so the operator can see the real shape.
        params.set(name, { count: 1, example: value ? `${name}=${value.slice(0, 60)}` : name });
      }
    }

    for (const rule of CLOUD_RULES) {
      const asset = rule.match(url);
      if (!asset) continue;
      const key = `${rule.provider}:${asset}`;
      if (!cloud.has(key)) {
        cloud.set(key, { provider: rule.provider, asset, url: raw });
      }
    }

    if (JUICY_PATH_RE.test(url.pathname) || JUICY_EXT_RE.test(url.pathname)) {
      if (juicy.size < LIMITS.juicyFiles) juicy.add(raw);
    }

    for (const bucket of buckets) {
      if (!bucket.spec.test(url, raw)) continue;
      bucket.total += 1;
      if (bucket.urls.length < LIMITS.bucketUrls) bucket.urls.push(raw);
    }
  }

  const parameters: ParamRecord[] = [...params.entries()]
    .map(([name, { count, example }]) => ({
      name,
      count,
      classes: classifyParam(name),
      example,
    }))
    // Classified parameters first — those are the ones worth fuzzing.
    .sort(
      (a, b) =>
        Number(b.classes.length > 0) - Number(a.classes.length > 0) ||
        b.count - a.count ||
        a.name.localeCompare(b.name),
    )
    .slice(0, LIMITS.parameters);

  const patternBuckets: PatternBucket[] = buckets
    .filter((bucket) => bucket.total > 0)
    .map(({ spec, urls, total }) => ({
      id: spec.id,
      label: spec.label,
      description: spec.description,
      severity: spec.severity,
      urls,
      total,
    }));

  return {
    analyzed,
    parameters,
    buckets: patternBuckets,
    juicyFiles: [...juicy].sort(),
    cloudAssets: [...cloud.values()]
      .sort((a, b) => a.provider.localeCompare(b.provider) || a.asset.localeCompare(b.asset))
      .slice(0, LIMITS.cloudAssets),
    thirdPartyHosts: topCounts(thirdParty, LIMITS.hosts),
    inScopeHosts: topCounts(inScopeHosts, LIMITS.hosts),
    extensions: topCounts(extensions, LIMITS.extensions),
  };
}
