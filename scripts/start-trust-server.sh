#!/bin/sh
# Starts the trust server on :8090 (data and logs in .runtime/) with the demo configuration (the "demo" profile:
# clients with published API keys, for development only) and waits until all sources are loaded.
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
mkdir -p .runtime
if curl -sf localhost:8090/actuator/health >/dev/null 2>&1; then echo "trust server already running"; exit 0; fi
(cd .runtime && { nohup java -jar ../trust-server/trust-server/target/trust-server.jar --spring.profiles.active=demo "$@" > trust-server.log 2>&1 & echo $! > trust-server.pid; })
status() { curl -s localhost:8090/actuator/health | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null; }
for i in $(seq 1 60); do
  sleep 1
  if [ "$(status)" = "UP" ]; then break; fi
done
# UP means every required source has loaded; what each source did is in .runtime/trust-server.log and GET /admin/v1/sources.
echo "trust server $(status)"
[ "$(status)" = "UP" ]
