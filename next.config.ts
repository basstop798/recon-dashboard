import type { NextConfig } from "next";

/**
 * Security headers for a publicly hosted deployment.
 *
 * The dashboard renders somebody else's attack surface, so the headers are
 * tuned to keep that data from leaking sideways: nothing embeds this page,
 * nothing learns where an operator came from, and the browser is not allowed
 * to reach any origin the app does not need.
 *
 * The CSP is deliberately tight. It works because the server hands the client
 * everything it needs: the favicon arrives as a `data:` URI computed during the
 * scan, so the operator's own browser never has to contact the target — which
 * would otherwise expose the analyst's IP to the host they are researching.
 * `'unsafe-inline'` for styles is Next's hydration requirement, not a choice.
 */
const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  // Next injects inline bootstrap scripts; `strict-dynamic` would need a nonce
  // per request, which a statically prerendered page cannot carry.
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  // Same-origin only: every upstream lookup happens server-side, by design.
  "connect-src 'self'",
].join('; ');

const nextConfig: NextConfig = {
  // Lets the app be copied into a slim container image as-is. Harmless on
  // Vercel, which ignores it.
  output: 'standalone',

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: CSP },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          // Never announce the researched target, or even this tool, to a site
          // an operator opens from a pivot or dork link.
          { key: 'Referrer-Policy', value: 'no-referrer' },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
