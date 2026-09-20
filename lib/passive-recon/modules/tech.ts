/**
 * Module 3 — technology detection (Wappalyzer-style, passive).
 *
 * Every signal here comes from data the target already sent unprompted for
 * the one homepage request the scan makes: response headers, Set-Cookie
 * names, and the HTML body. Nothing here issues an extra request.
 */

import { auditSecurityHeaders, parsePageIdentity, readCookies } from '../headers-audit';
import type { Confidence, HeaderRecord, TechPayload, Technology } from '../types';
import type { HomepageResult } from './homepage';

interface HeaderRule {
  header: string;
  pattern: RegExp;
  /** `$1` is replaced with the first capture group (usually a version). */
  name: string;
  category: string;
  confidence: Confidence;
}

const HEADER_RULES: readonly HeaderRule[] = [
  { header: 'server', pattern: /nginx(?:\/([\d.]+))?/i, name: 'Nginx $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /apache(?:\/([\d.]+))?/i, name: 'Apache $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /microsoft-iis(?:\/([\d.]+))?/i, name: 'IIS $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /litespeed/i, name: 'LiteSpeed', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /envoy/i, name: 'Envoy', category: 'Proxy', confidence: 'high' },
  { header: 'server', pattern: /caddy/i, name: 'Caddy', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /cloudflare/i, name: 'Cloudflare', category: 'CDN / WAF', confidence: 'high' },
  { header: 'server', pattern: /gws/i, name: 'Google Web Server', category: 'Web Server', confidence: 'medium' },
  { header: 'server', pattern: /awselb/i, name: 'AWS ELB', category: 'Load Balancer', confidence: 'high' },
  { header: 'server', pattern: /vercel/i, name: 'Vercel', category: 'Hosting', confidence: 'high' },
  { header: 'server', pattern: /openresty(?:\/([\d.]+))?/i, name: 'OpenResty $1', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /tengine/i, name: 'Tengine', category: 'Web Server', confidence: 'high' },
  { header: 'server', pattern: /gunicorn(?:\/([\d.]+))?/i, name: 'Gunicorn $1', category: 'Application Server', confidence: 'high' },
  { header: 'server', pattern: /uvicorn/i, name: 'Uvicorn', category: 'Application Server', confidence: 'high' },
  { header: 'server', pattern: /kestrel/i, name: 'Kestrel (.NET)', category: 'Application Server', confidence: 'high' },
  { header: 'server', pattern: /jetty(?:\(([\d.]+)\))?/i, name: 'Jetty $1', category: 'Application Server', confidence: 'high' },
  { header: 'server', pattern: /tomcat(?:\/([\d.]+))?/i, name: 'Tomcat $1', category: 'Application Server', confidence: 'high' },
  { header: 'server', pattern: /cowboy/i, name: 'Cowboy (Erlang)', category: 'Application Server', confidence: 'medium' },

  { header: 'x-powered-by', pattern: /php(?:\/([\d.]+))?/i, name: 'PHP $1', category: 'Language', confidence: 'high' },
  { header: 'x-powered-by', pattern: /asp\.net/i, name: 'ASP.NET', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /express/i, name: 'Express', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /next\.js/i, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /servlet/i, name: 'Java Servlet', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /nuxt/i, name: 'Nuxt', category: 'Framework', confidence: 'high' },
  { header: 'x-powered-by', pattern: /shopify/i, name: 'Shopify', category: 'E-commerce', confidence: 'high' },

  { header: 'x-aspnet-version', pattern: /([\d.]+)/, name: 'ASP.NET $1', category: 'Framework', confidence: 'high' },
  { header: 'x-generator', pattern: /drupal\s*([\d.]+)?/i, name: 'Drupal $1', category: 'CMS', confidence: 'high' },
  { header: 'x-drupal-cache', pattern: /.+/, name: 'Drupal', category: 'CMS', confidence: 'high' },
  { header: 'x-shopify-stage', pattern: /.+/, name: 'Shopify', category: 'E-commerce', confidence: 'high' },
  { header: 'x-wix-request-id', pattern: /.+/, name: 'Wix', category: 'CMS', confidence: 'high' },
  { header: 'x-ghost-cache-status', pattern: /.+/, name: 'Ghost', category: 'CMS', confidence: 'high' },
  { header: 'x-magento-cache-debug', pattern: /.+/, name: 'Magento', category: 'E-commerce', confidence: 'high' },
  { header: 'x-hubspot-correlation-id', pattern: /.+/, name: 'HubSpot', category: 'Marketing', confidence: 'high' },

  { header: 'cf-ray', pattern: /.+/, name: 'Cloudflare', category: 'CDN / WAF', confidence: 'high' },
  { header: 'cf-cache-status', pattern: /.+/, name: 'Cloudflare', category: 'CDN / WAF', confidence: 'high' },
  { header: 'x-amz-cf-id', pattern: /.+/, name: 'AWS CloudFront', category: 'CDN', confidence: 'high' },
  { header: 'x-amz-request-id', pattern: /.+/, name: 'AWS S3', category: 'Storage', confidence: 'medium' },
  { header: 'x-vercel-id', pattern: /.+/, name: 'Vercel', category: 'Hosting', confidence: 'high' },
  { header: 'x-nextjs-cache', pattern: /.+/, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { header: 'x-nf-request-id', pattern: /.+/, name: 'Netlify', category: 'Hosting', confidence: 'high' },
  { header: 'x-fastly-request-id', pattern: /.+/, name: 'Fastly', category: 'CDN', confidence: 'high' },
  { header: 'x-served-by', pattern: /cache-/i, name: 'Fastly', category: 'CDN', confidence: 'medium' },
  { header: 'x-akamai-transformed', pattern: /.+/, name: 'Akamai', category: 'CDN', confidence: 'high' },
  { header: 'x-github-request-id', pattern: /.+/, name: 'GitHub Pages', category: 'Hosting', confidence: 'high' },
  { header: 'x-sucuri-id', pattern: /.+/, name: 'Sucuri WAF', category: 'CDN / WAF', confidence: 'high' },
  { header: 'x-varnish', pattern: /.+/, name: 'Varnish', category: 'Cache', confidence: 'high' },
  { header: 'via', pattern: /varnish/i, name: 'Varnish', category: 'Cache', confidence: 'medium' },
  { header: 'x-runtime', pattern: /.+/, name: 'Ruby on Rails', category: 'Framework', confidence: 'low' },
  { header: 'x-envoy-upstream-service-time', pattern: /.+/, name: 'Envoy', category: 'Proxy', confidence: 'high' },
  { header: 'x-kong-upstream-latency', pattern: /.+/, name: 'Kong Gateway', category: 'API Gateway', confidence: 'high' },
  { header: 'x-amzn-requestid', pattern: /.+/, name: 'AWS API Gateway', category: 'API Gateway', confidence: 'high' },
  { header: 'x-ms-request-id', pattern: /.+/, name: 'Azure', category: 'Hosting', confidence: 'medium' },
  { header: 'x-cache', pattern: /(?:hit|miss)/i, name: 'CDN cache layer', category: 'Cache', confidence: 'low' },
  { header: 'x-litespeed-cache', pattern: /.+/, name: 'LiteSpeed Cache', category: 'Cache', confidence: 'high' },

  { header: 'strict-transport-security', pattern: /.+/, name: 'HSTS', category: 'Security', confidence: 'high' },
  { header: 'content-security-policy', pattern: /.+/, name: 'CSP', category: 'Security', confidence: 'high' },
  { header: 'x-frame-options', pattern: /.+/, name: 'X-Frame-Options', category: 'Security', confidence: 'high' },
];

/** Session-cookie names are among the most reliable stack fingerprints. */
const COOKIE_RULES: ReadonlyArray<{ pattern: RegExp; name: string; category: string }> = [
  { pattern: /^phpsessid$/i, name: 'PHP', category: 'Language' },
  { pattern: /^jsessionid$/i, name: 'Java / Servlet', category: 'Framework' },
  { pattern: /^asp\.net_sessionid$|^\.aspxauth$/i, name: 'ASP.NET', category: 'Framework' },
  { pattern: /^laravel_session$|^xsrf-token$/i, name: 'Laravel', category: 'Framework' },
  { pattern: /^_rails_session$|^_session_id$/i, name: 'Ruby on Rails', category: 'Framework' },
  { pattern: /^csrftoken$|^django_language$/i, name: 'Django', category: 'Framework' },
  { pattern: /^connect\.sid$/i, name: 'Express', category: 'Framework' },
  { pattern: /^ci_session$/i, name: 'CodeIgniter', category: 'Framework' },
  { pattern: /^wordpress_|^wp-settings/i, name: 'WordPress', category: 'CMS' },
  { pattern: /^__cf_bm$|^cf_clearance$/i, name: 'Cloudflare Bot Management', category: 'CDN / WAF' },
  { pattern: /^incap_ses|^visid_incap/i, name: 'Imperva Incapsula', category: 'CDN / WAF' },
  { pattern: /^ak_bmsc$|^bm_sv$/i, name: 'Akamai Bot Manager', category: 'CDN / WAF' },
  { pattern: /^awsalb|^awsalbcors$/i, name: 'AWS ALB', category: 'Load Balancer' },
  { pattern: /^_shopify_/i, name: 'Shopify', category: 'E-commerce' },
];

/**
 * Front-end frameworks leave no header trace, so they are detected from markup
 * the server already returned — still passive, just a different signal source.
 */
const HTML_RULES: ReadonlyArray<{
  pattern: RegExp;
  name: string;
  category: string;
  confidence: Confidence;
}> = [
  { pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i, name: '$1', category: 'Generator', confidence: 'high' },
  { pattern: /\/_next\/static\//, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { pattern: /__NEXT_DATA__/, name: 'Next.js', category: 'Framework', confidence: 'high' },
  { pattern: /__NUXT__/, name: 'Nuxt', category: 'Framework', confidence: 'high' },
  { pattern: /ng-version=["']([^"']+)["']/i, name: 'Angular $1', category: 'Framework', confidence: 'high' },
  { pattern: /data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js/i, name: 'React', category: 'Framework', confidence: 'medium' },
  { pattern: /__sveltekit|svelte-/i, name: 'Svelte / SvelteKit', category: 'Framework', confidence: 'medium' },
  { pattern: /___gatsby/, name: 'Gatsby', category: 'Framework', confidence: 'high' },
  { pattern: /\/wp-content\/|\/wp-includes\//i, name: 'WordPress', category: 'CMS', confidence: 'high' },
  { pattern: /cdn\.shopify\.com/i, name: 'Shopify', category: 'E-commerce', confidence: 'high' },
  { pattern: /jquery(?:[-.]([\d.]+))?(?:\.min)?\.js/i, name: 'jQuery $1', category: 'Library', confidence: 'medium' },
  { pattern: /bootstrap(?:[-.]([\d.]+))?(?:\.min)?\.css/i, name: 'Bootstrap $1', category: 'UI Framework', confidence: 'medium' },
  { pattern: /googletagmanager\.com\/gtm\.js/i, name: 'Google Tag Manager', category: 'Analytics', confidence: 'high' },
  { pattern: /google-analytics\.com\/analytics\.js|gtag\/js\?id=/i, name: 'Google Analytics', category: 'Analytics', confidence: 'high' },
  { pattern: /connect\.facebook\.net\/[^"']+\/fbevents\.js/i, name: 'Meta Pixel', category: 'Analytics', confidence: 'high' },
  { pattern: /cdn\.segment\.com\/analytics\.js/i, name: 'Segment', category: 'Analytics', confidence: 'high' },
  { pattern: /js\.stripe\.com/i, name: 'Stripe', category: 'Payments', confidence: 'high' },
  { pattern: /js\.hs-scripts\.com|hs-analytics\.net/i, name: 'HubSpot', category: 'Marketing', confidence: 'high' },
  { pattern: /static\.zdassets\.com|zendesk\.com\/embeddable/i, name: 'Zendesk', category: 'Support', confidence: 'high' },
  { pattern: /widget\.intercom\.io|intercomcdn\.com/i, name: 'Intercom', category: 'Support', confidence: 'high' },
  { pattern: /browser\.sentry-cdn\.com|@sentry\//i, name: 'Sentry', category: 'Monitoring', confidence: 'high' },
  { pattern: /cdn\.optimizely\.com/i, name: 'Optimizely', category: 'A/B Testing', confidence: 'high' },
  { pattern: /recaptcha\/api\.js|hcaptcha\.com\/1\/api\.js/i, name: 'CAPTCHA', category: 'Security', confidence: 'high' },
  { pattern: /auth0\.com\/js|cdn\.auth0\.com/i, name: 'Auth0', category: 'Identity', confidence: 'high' },
  { pattern: /firebaseapp\.com|firebasejs/i, name: 'Firebase', category: 'Backend', confidence: 'high' },
  { pattern: /cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com/i, name: 'Public CDN assets', category: 'CDN', confidence: 'low' },
];

function applyTemplate(template: string, match: RegExpMatchArray): string {
  return template.replace('$1', match[1] ?? '').trim();
}

export async function fingerprintTech(homepage: Promise<HomepageResult>): Promise<TechPayload> {
  const result = await homepage;
  if (!result.ok) throw new Error(result.error);

  const { response, html, finalUrl, redirected } = result;
  const found = new Map<string, Technology>();

  const add = (tech: Technology) => {
    // First match wins so a high-confidence hit is not overwritten by a weaker
    // rule for the same product.
    if (tech.name && !found.has(tech.name)) found.set(tech.name, tech);
  };

  for (const rule of HEADER_RULES) {
    const value = response.headers.get(rule.header);
    if (!value) continue;

    const match = value.match(rule.pattern);
    if (!match) continue;

    add({
      name: applyTemplate(rule.name, match),
      category: rule.category,
      evidence: `${rule.header}: ${value.slice(0, 120)}`,
      confidence: rule.confidence,
    });
  }

  const cookies = readCookies(response.headers);
  for (const cookie of cookies) {
    for (const rule of COOKIE_RULES) {
      if (!rule.pattern.test(cookie.name)) continue;
      add({
        name: rule.name,
        category: rule.category,
        evidence: `Set-Cookie: ${cookie.name}`,
        confidence: 'high',
      });
    }
  }

  for (const rule of HTML_RULES) {
    const match = html.match(rule.pattern);
    if (!match) continue;
    add({
      name: applyTemplate(rule.name, match),
      category: rule.category,
      evidence: `HTML body: ${match[0].slice(0, 100)}`,
      confidence: rule.confidence,
    });
  }

  // Set-Cookie is excluded on purpose; its names and flags are reported
  // separately and its values are never persisted into a shareable report.
  const headers: HeaderRecord[] = [...response.headers.entries()]
    .filter(([name]) => name.toLowerCase() !== 'set-cookie')
    .map(([name, value]) => ({ name, value: value.slice(0, 300) }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const audit = auditSecurityHeaders(response.headers);

  return {
    finalUrl,
    status: response.status,
    redirected,
    technologies: [...found.values()].sort(
      (a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name),
    ),
    headers,
    cookies,
    security: audit.checks,
    grade: audit.grade,
    identity: parsePageIdentity(html),
  };
}
