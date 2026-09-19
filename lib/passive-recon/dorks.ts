/**
 * Search-engine dork generation.
 *
 * Pure and isomorphic: the dashboard renders these instantly without waiting on
 * the scan, and the same function feeds the exported report. Nothing here
 * touches the network — every dork is a link the operator chooses to open, so
 * the query runs from their browser, under their account, at their pace.
 */

import type { Dork, DorkGroup } from './types';

type Builder = (label: string, query: string) => Dork;

function engine(toUrl: (query: string) => string): Builder {
  return (label, query) => ({ label, query, url: toUrl(query) });
}

const google = engine((q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`);
const bing = engine((q) => `https://www.bing.com/search?q=${encodeURIComponent(q)}`);
const duck = engine((q) => `https://duckduckgo.com/?q=${encodeURIComponent(q)}`);
const github = engine(
  (q) => `https://github.com/search?type=code&q=${encodeURIComponent(q)}`,
);
const gitlab = engine(
  (q) => `https://gitlab.com/search?scope=blobs&search=${encodeURIComponent(q)}`,
);
const grepApp = engine((q) => `https://grep.app/search?q=${encodeURIComponent(q)}`);
const searchCode = engine(
  (q) => `https://searchcode.com/?q=${encodeURIComponent(q)}`,
);

/**
 * Builds the full dork matrix for a target.
 *
 * @param domain An already-sanitised domain (see `sanitizeDomain`).
 */
export function buildDorks(domain: string): DorkGroup[] {
  return [
    {
      engine: 'Google — content discovery',
      description: 'Map what the index already knows about the estate.',
      dorks: [
        google('All indexed pages', `site:${domain}`),
        google('Subdomains (excl. www)', `site:*.${domain} -site:www.${domain}`),
        google('Deep subdomains', `site:*.*.${domain}`),
        google('Non-production hosts', `site:*.${domain} (inurl:dev | inurl:test | inurl:staging | inurl:uat | inurl:qa)`),
        google('Admin panels', `site:${domain} (inurl:admin | inurl:dashboard | inurl:panel | inurl:console)`),
        google('Login pages', `site:${domain} (inurl:login | inurl:signin | inurl:auth | inurl:sso)`),
        google('API surfaces', `site:${domain} (inurl:api | inurl:graphql | inurl:swagger | inurl:openapi)`),
        google('Upload endpoints', `site:${domain} (inurl:upload | inurl:file | inurl:attachment)`),
        google('Redirect parameters', `site:${domain} (inurl:redirect= | inurl:url= | inurl:next= | inurl:return=)`),
        google('ID parameters (IDOR)', `site:${domain} (inurl:id= | inurl:user= | inurl:account= | inurl:order=)`),
        google('Directory listings', `site:${domain} intitle:"index of"`),
        google('Self-hosted dev tooling', `site:${domain} (inurl:gitlab | inurl:gitea | inurl:jenkins | inurl:jira | inurl:sonar)`),
        google('Error messages', `site:${domain} ("sql syntax near" | "stack trace" | "fatal error" | "undefined index")`),
        google('Open redirects in cache', `site:${domain} inurl:"=http"`),
        google('Status & monitoring', `site:${domain} (inurl:status | inurl:health | inurl:metrics | inurl:actuator)`),
      ],
    },
    {
      engine: 'Google — files & secrets',
      description: 'Documents and configuration the crawler picked up.',
      dorks: [
        google('PDF documents', `site:${domain} ext:pdf`),
        google('Office documents', `site:${domain} (ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx)`),
        google('Config & env files', `site:${domain} (ext:env | ext:yml | ext:yaml | ext:ini | ext:conf | ext:config)`),
        google('Backups & databases', `site:${domain} (ext:sql | ext:db | ext:bak | ext:old | ext:log | ext:zip)`),
        google('Source & script files', `site:${domain} (ext:php | ext:asp | ext:aspx | ext:jsp | ext:cgi | ext:pl)`),
        google('Text & data dumps', `site:${domain} (ext:txt | ext:csv | ext:json | ext:xml)`),
        google('Confidential wording', `site:${domain} ("internal use only" | "confidential" | "not for distribution")`),
        google('Credential wording', `site:${domain} ("password" | "passwd" | "api key" | "secret key") ext:txt`),
        google('Employee data', `site:${domain} ("employee id" | "staff directory" | "phone list") ext:xlsx`),
      ],
    },
    {
      engine: 'Google — third-party exposure',
      description: 'Where the target leaks through somebody else’s platform.',
      dorks: [
        google('Exposed S3 buckets', `site:s3.amazonaws.com "${domain}"`),
        google('Azure blob storage', `site:blob.core.windows.net "${domain}"`),
        google('Google Cloud Storage', `site:storage.googleapis.com "${domain}"`),
        google('DigitalOcean Spaces', `site:digitaloceanspaces.com "${domain}"`),
        google('Paste sites', `(site:pastebin.com | site:ghostbin.com | site:paste.ee) "${domain}"`),
        google('Public Trello boards', `site:trello.com "${domain}"`),
        google('Public Jira / Confluence', `(site:atlassian.net | site:jira.com) "${domain}"`),
        google('Postman collections', `site:postman.com "${domain}"`),
        google('Public docs & sheets', `(site:docs.google.com | site:drive.google.com) "${domain}"`),
        google('Code sandboxes', `(site:codepen.io | site:jsfiddle.net | site:replit.com | site:codesandbox.io) "${domain}"`),
        google('Stack Overflow mentions', `site:stackoverflow.com "${domain}"`),
        google('Employees on LinkedIn', `site:linkedin.com/in "${domain}"`),
        google('Bug bounty scope mentions', `("${domain}") (site:hackerone.com | site:bugcrowd.com | site:intigriti.com)`),
      ],
    },
    {
      engine: 'Bing & DuckDuckGo',
      description: 'A second index — coverage differs from Google more than people expect.',
      dorks: [
        bing('All indexed pages', `site:${domain}`),
        bing('IP neighbours', `ip:${domain}`),
        bing('Admin in URL', `site:${domain} instreamset:url:admin`),
        bing('API in URL', `site:${domain} instreamset:url:api`),
        bing('Login in URL', `site:${domain} instreamset:url:login`),
        bing('PDF documents', `site:${domain} filetype:pdf`),
        bing('Directory listings', `site:${domain} intitle:"index of"`),
        duck('All indexed pages', `site:${domain}`),
        duck('Config files', `site:${domain} ext:env | ext:yml | ext:conf`),
      ],
    },
    {
      engine: 'GitHub code search',
      description: 'The single highest-yield source for leaked credentials.',
      dorks: [
        github('Any mention', `"${domain}"`),
        github('Passwords', `"${domain}" password`),
        github('API keys', `"${domain}" api_key`),
        github('Generic secrets', `"${domain}" secret`),
        github('AWS credentials', `"${domain}" AWS_SECRET_ACCESS_KEY`),
        github('Bearer tokens', `"${domain}" authorization bearer`),
        github('Env files', `"${domain}" path:.env`),
        github('Private keys', `"${domain}" "BEGIN RSA PRIVATE KEY"`),
        github('Database URLs', `"${domain}" DATABASE_URL`),
        github('JDBC / connection strings', `"${domain}" jdbc OR mongodb+srv`),
        github('Internal hostnames', `"internal.${domain}"`),
        github('Staging hostnames', `"staging.${domain}" OR "dev.${domain}"`),
        github('CI configuration', `"${domain}" path:.github/workflows`),
        github('Kubernetes manifests', `"${domain}" path:*.yaml kind:Secret`),
        github('Terraform state', `"${domain}" path:*.tfstate`),
        github('Docker compose', `"${domain}" path:docker-compose.yml`),
        github('JWT signing keys', `"${domain}" jwt_secret OR JWT_SECRET`),
        github('SMTP credentials', `"${domain}" smtp password`),
      ],
    },
    {
      engine: 'Other code indexes',
      description: 'GitHub is not the only place code ends up in public.',
      dorks: [
        gitlab('Any mention', `${domain}`),
        gitlab('Secrets', `${domain} password`),
        grepApp('Any mention', `${domain}`),
        grepApp('API keys', `${domain} api_key`),
        searchCode('Any mention', `${domain}`),
        searchCode('Config references', `${domain} config`),
      ],
    },
  ];
}
