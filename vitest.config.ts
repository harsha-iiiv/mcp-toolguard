import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 30_000,
    // e2e tests spawn dist/cli/main.js; tests/e2e/global-setup.ts builds first.
    globalSetup: ['tests/e2e/global-setup.ts'],
  },
});
