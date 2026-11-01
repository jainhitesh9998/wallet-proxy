import { defineConfig, devices } from '@playwright/test';

/**
 * E2E tests of the exported web wallet (apps/wallet, react-native-web) against the local trust server and the
 * public Animo playground. The first web server exports the web build (skip with WALLET_SKIP_BUILD=1) and serves it
 * statically; the trust server is reused when already running on :8090, otherwise started from .runtime.
 */
const WALLET_PORT = Number(process.env.WALLET_PORT ?? 8099);
const serve = `node serve-static.mjs ../apps/wallet/dist ${WALLET_PORT}`;
const build = 'cd ../apps/wallet && CI=1 npm run export:web && cd ../../e2e';

export default defineConfig({
  testDir: './tests',
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
      // Dev-only CORS relay for MOSIP hosts (used by the opt-in MOSIP test; harmless otherwise).
      command: 'node ../apps/wallet/dev-cors-proxy.mjs',
      url: 'http://127.0.0.1:8787/health',
      reuseExistingServer: true,
      stdout: 'ignore',
    },
    {
      // Reused when already running (the usual case); otherwise started from .runtime like the README says.
      command: 'bash -c "source ~/.local/tools/env.sh && cd ../.runtime && exec java -jar ../trust-server/trust-server/target/trust-server.jar"',
      url: 'http://localhost:8090/actuator/health',
      reuseExistingServer: true,
      timeout: 180_000,
      stdout: 'ignore',
    },
  ],
});
