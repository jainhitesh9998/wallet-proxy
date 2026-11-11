import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const trustClient = (file: string) => fileURLToPath(new URL(`../trust-client/src/${file}`, import.meta.url));

export default defineConfig({
  // Tests run against the trust client's sources, not a build of it that may be out of date.
  resolve: {
    alias: [
      { find: /^@vctrust\/trust-client\/primitives$/, replacement: trustClient('primitives.ts') },
      { find: /^@vctrust\/trust-client$/, replacement: trustClient('index.ts') },
    ],
  },
  test: {
    // *.live.test.ts need network access / a running trust service: `npm run test:live`
    exclude: ['**/node_modules/**', '**/dist/**', ...(process.env.LIVE ? [] : ['**/*.live.test.ts'])],
    testTimeout: 30_000,
  },
});
