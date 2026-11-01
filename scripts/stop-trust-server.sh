#!/bin/sh
cd "$(dirname "$0")/.."
[ -f .runtime/trust-server.pid ] && kill "$(cat .runtime/trust-server.pid)" 2>/dev/null && rm .runtime/trust-server.pid && echo stopped
