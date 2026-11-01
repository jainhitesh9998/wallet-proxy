import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // *.live.test.ts need network access / a running trust service: `npm run test:live`
    exclude: ['**/node_modules/**', '**/dist/**', ...(process.env.LIVE ? [] : ['**/*.live.test.ts'])],
    testTimeout: 30_000,
  },
});
