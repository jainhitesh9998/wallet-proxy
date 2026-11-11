#!/bin/sh
# Stops what scripts/dev-up.sh started.
cd "$(dirname "$0")/.."
[ -f .runtime/reference-ecosystem.pid ] && kill "$(cat .runtime/reference-ecosystem.pid)" 2>/dev/null && rm .runtime/reference-ecosystem.pid && echo "reference ecosystem stopped"
scripts/stop-trust-server.sh
