#!/bin/sh
# Builds the Java trust server (with tests) and the TypeScript packages.
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
(cd trust-server && mvn -q install)
npm install
npm run build -w @vctrust/trust-client -w @vctrust/wallet-core
echo "build ok: trust-server/trust-server/target/trust-server.jar"
