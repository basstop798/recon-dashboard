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
      // controls, auth) plus the three modules that decide what the operator
      // is told: takeover.ts (the subdomain-takeover verdict), findings.ts
      // (the triage feed every surface reads) and headers-audit.ts (the A–F
      // grade and per-header advice). Those are covered because a wrong
      // answer costs more than a missing one. The remaining OSINT
      // parsers/formatters in lib/ still have no tests — see README's
      // "Testing" section.
      include: [
        'lib/passive-recon/sanitize.ts',
        'lib/passive-recon/net-guard.ts',
        'lib/passive-recon/rate-limit.ts',
        'lib/passive-recon/takeover.ts',
        'lib/passive-recon/findings.ts',
        'lib/passive-recon/headers-audit.ts',
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
