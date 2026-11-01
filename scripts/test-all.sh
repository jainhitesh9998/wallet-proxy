#!/bin/sh
# Unit/integration tests (offline), then live end-to-end tests (network: Animo playground, MOSIP collab, trust server).
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
echo "== Java (core, adapters, server)"; (cd trust-server && mvn -q test) && echo ok
echo "== trust-client"; (cd packages/trust-client && npx vitest run)
echo "== wallet-core (offline)"; (cd packages/wallet-core && npx vitest run)
[ "$1" = "--offline" ] && exit 0
scripts/start-trust-server.sh
echo "== live end-to-end (wallet-core against live issuers/verifier + trust server)"
(cd packages/wallet-core && LIVE=1 npx vitest run test/animo.live.test.ts test/animo-present.live.test.ts test/animo-sdjwt.live.test.ts test/animo-authcode.live.test.ts test/animo-deferred.live.test.ts \
  test/mosip.live.test.ts test/fallback.live.test.ts test/samples.live.test.ts)
if [ -f e2e/playwright.config.ts ]; then echo "== wallet UI (Playwright)"; (cd e2e && npx playwright test); fi
