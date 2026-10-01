import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['**/*.test.ts'],
    exclude: ['node_modules/**', '.next/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      // The security-critical gates (input validation, SSRF guard, abuse
      // controls, auth) plus the two modules that decide what the operator
      // is told: takeover.ts (the high-severity subdomain-takeover verdict)
      // and findings.ts (the triage feed every surface reads). Those two are
      // covered because a wrong answer there is more expensive than a
      // missing one. The remaining OSINT parsers/formatters in lib/ still
      // have no tests — see README's "Testing" section.
      include: [
        'lib/passive-recon/sanitize.ts',
        'lib/passive-recon/net-guard.ts',
        'lib/passive-recon/rate-limit.ts',
        'lib/passive-recon/takeover.ts',
        'lib/passive-recon/findings.ts',
        'proxy.ts',
      ],
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
});
