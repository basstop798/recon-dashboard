/**
 * Search-engine dork generation.
 *
 * Pure and isomorphic: the dashboard renders these instantly without waiting on
 * the scan, and the same function feeds the exported report. Nothing here
 * touches the network — every dork is a link the operator chooses to open.
 */

import type { Dork, DorkGroup } from './types';

function google(label: string, query: string): Dork {
  return {
    label,
    query,
    url: `https://www.google.com/search?q=${encodeURIComponent(query)}`,
  };
}

function bing(label: string, query: string): Dork {
  return {
    label,
    query,
    url: `https://www.bing.com/search?q=${encodeURIComponent(query)}`,
  };
}

function github(label: string, query: string): Dork {
  return {
    label,
    query,
    url: `https://github.com/search?type=code&q=${encodeURIComponent(query)}`,
  };
}

/**
 * Builds the full dork matrix for a target.
 *
 * @param domain An already-sanitised domain (see `sanitizeDomain`).
 */
export function buildDorks(domain: string): DorkGroup[] {
  return [
    {
      engine: 'Google',
      dorks: [
        google('All indexed pages', `site:${domain}`),
        google('Subdomains (excl. www)', `site:*.${domain} -site:www.${domain}`),
        google('PDF documents', `site:${domain} ext:pdf`),
        google(
          'Office documents',
          `site:${domain} (ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx)`,
        ),
        google(
          'Config & env files',
          `site:${domain} (ext:env | ext:yml | ext:yaml | ext:ini | ext:conf | ext:config)`,
        ),
        google(
          'Backups & databases',
          `site:${domain} (ext:sql | ext:db | ext:bak | ext:old | ext:log | ext:zip)`,
        ),
        google('Directory listings', `site:${domain} intitle:"index of"`),
        google('Admin panels', `site:${domain} (inurl:admin | inurl:dashboard | inurl:panel)`),
        google('Login pages', `site:${domain} (inurl:login | inurl:signin | inurl:auth)`),
        google('API surfaces', `site:${domain} (inurl:api | inurl:graphql | inurl:swagger)`),
        google('Self-hosted git', `site:${domain} (inurl:gitlab | inurl:gitea | inurl:jenkins)`),
        google('Confidential wording', `site:${domain} ("internal use only" | "confidential")`),
        google('Exposed S3 buckets', `site:s3.amazonaws.com "${domain}"`),
        google('Paste sites', `site:pastebin.com "${domain}"`),
        google('Public Trello boards', `site:trello.com "${domain}"`),
      ],
    },
    {
      engine: 'Bing',
      dorks: [
        bing('All indexed pages', `site:${domain}`),
        bing('PDF documents', `site:${domain} filetype:pdf`),
        bing('Admin in URL', `site:${domain} instreamset:url:admin`),
        bing('API in URL', `site:${domain} instreamset:url:api`),
        bing('Login in URL', `site:${domain} instreamset:url:login`),
        bing('Title mentions', `site:${domain} intitle:"index of"`),
      ],
    },
    {
      engine: 'GitHub',
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
        github('Internal hostnames', `"internal.${domain}"`),
      ],
    },
  ];
}
