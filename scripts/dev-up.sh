#!/bin/sh
# Brings up everything a developer runs locally: the trust service (:8090), the reference issuer (:8791) and verifier
# (:8792), and lists the two in the service. Stop it all with scripts/dev-down.sh.
#
# The trust service is started with access to loopback over plain http, which it refuses by default: the reference
# issuer lives on http://localhost. Never run a production service with these two flags.
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
mkdir -p .runtime
[ -f trust-server/trust-server/target/trust-server.jar ] || scripts/build.sh
scripts/start-trust-server.sh --trust.http.allow-private-networks=true --trust.http.http-allowed-hosts=localhost
if ! curl -sf localhost:8791/.well-known/openid-credential-issuer >/dev/null 2>&1; then
  DATA_DIR="$PWD/.runtime/reference-ecosystem" nohup node test-ecosystem/src/serve.mjs > .runtime/reference-ecosystem.log 2>&1 &
  echo $! > .runtime/reference-ecosystem.pid
  for i in $(seq 1 30); do
    sleep 1
    curl -sf localhost:8791/.well-known/openid-credential-issuer >/dev/null 2>&1 && break
  done
fi
curl -sf localhost:8791/.well-known/openid-credential-issuer >/dev/null || { echo "the reference ecosystem did not start: see .runtime/reference-ecosystem.log"; exit 1; }
echo "reference issuer http://localhost:8791, verifier http://localhost:8792"
node scripts/register-reference.mjs
