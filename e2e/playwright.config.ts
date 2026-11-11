import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';
import { SUSPENDED_ISSUER_PORT } from './tests/support';

/**
 * E2E tests of the exported web wallet (apps/wallet, react-native-web).
 *
 *   tests/wallet.spec.ts       the local reference ecosystem and trust service (scripts/dev-up.sh); no internet needed
 *   tests/animo.live.spec.ts   the public Animo playground; runs with LIVE=1
 *
 * Playwright starts two servers of its own and stops them afterwards: the exported web build (skip the export with
 * WALLET_SKIP_BUILD=1), and a second reference issuer on :8793 that one test lists in the trust service as suspended.
 * The trust service (:8090) and the reference issuer and verifier (:8791, :8792) must already run: global-setup.ts
 * checks that and says how to start them.
 */
const WALLET_PORT = Number(process.env.WALLET_PORT ?? 8099);
const serve = `node serve-static.mjs ../apps/wallet/dist ${WALLET_PORT}`;
const build = 'cd ../apps/wallet && CI=1 npm run export:web && cd ../../e2e';

export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.ts',
  timeout: 240_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://127.0.0.1:${WALLET_PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 900, height: 1000 },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 900, height: 1000 } } }],
  webServer: [
    {
      command: process.env.WALLET_SKIP_BUILD ? serve : `${build} && ${serve}`,
      url: `http://127.0.0.1:${WALLET_PORT}/`,
      reuseExistingServer: false,
      timeout: 300_000,
      stdout: 'ignore',
    },
    {
      // A reference issuer of its own (own keys, own data directory), for the test of an issuer the trust service refuses.
      command: 'node ../test-ecosystem/src/serve.mjs',
      env: { ISSUER_PORT: String(SUSPENDED_ISSUER_PORT), VERIFIER_PORT: String(SUSPENDED_ISSUER_PORT + 1), DATA_DIR: join(tmpdir(), 'vctrust-e2e-suspended-issuer') },
      url: `http://localhost:${SUSPENDED_ISSUER_PORT}/.well-known/openid-credential-issuer`,
      reuseExistingServer: false,
      timeout: 60_000,
      stdout: 'ignore',
    },
  ],
});
