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
      // Scoped to the security-critical gates this hardening pass covers
      // (input validation, SSRF guard, abuse controls, auth). The OSINT
      // parsers/formatters in the rest of lib/ have no tests yet — see
      // README's "Testing" section for the plan to extend coverage there.
      include: [
        'lib/passive-recon/sanitize.ts',
        'lib/passive-recon/net-guard.ts',
        'lib/passive-recon/rate-limit.ts',
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
