#!/bin/sh
# Runs every suite. With --offline: only what needs no network and no running service.
# Without it: also starts the local environment (scripts/dev-up.sh) and runs the live suites, which need the internet
# (Animo playground, walt.id demo issuer).
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
echo "== trust service (Java: unit, integration, evaluation vectors)"; (cd trust-server && mvn -q test) && echo ok
echo "== client library"; npm test -w @vctrust/trust-client
echo "== reference ecosystem"; npm test -w @vctrust/reference-ecosystem
echo "== wallet core (offline: verification rules, the wallet against the reference ecosystem, real-world credentials)"; npm test -w @vctrust/wallet-core
[ "$1" = "--offline" ] && exit 0
scripts/dev-up.sh
echo "== service and device decide alike (live)"
(cd packages/trust-client && LIVE=1 npx vitest run test/parity.live.test.ts)
echo "== the wallet through the trust service: reference ecosystem, Animo playground, walt.id demo issuer (live)"
(cd packages/wallet-core && LIVE=1 npx vitest run test/proxy.live.test.ts test/animo.live.test.ts test/animo-sdjwt.live.test.ts test/animo-present.live.test.ts \
  test/animo-authcode.live.test.ts test/animo-deferred.live.test.ts test/animo-batch.live.test.ts test/waltid.live.test.ts)
if [ -f e2e/playwright.config.ts ]; then echo "== wallet UI (Playwright)"; (cd e2e && npx playwright test); fi
