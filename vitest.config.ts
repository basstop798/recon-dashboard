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
      // controls, auth) plus takeover.ts — the first *answer*-producing
      // module to be covered. It decides the high-severity "subdomain
      // takeover" verdict an operator would file with a bug-bounty
      // programme, so a false positive there is expensive. The remaining
      // OSINT parsers/formatters in lib/ still have no tests — see README's
      // "Testing" section.
      include: [
        'lib/passive-recon/sanitize.ts',
        'lib/passive-recon/net-guard.ts',
        'lib/passive-recon/rate-limit.ts',
        'lib/passive-recon/takeover.ts',
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
