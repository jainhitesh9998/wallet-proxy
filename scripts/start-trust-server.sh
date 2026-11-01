#!/bin/sh
# Starts the trust server on :8090 (data and logs in .runtime/) and waits until all sources are loaded.
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
mkdir -p .runtime
if curl -sf localhost:8090/actuator/health >/dev/null 2>&1; then echo "trust server already running"; exit 0; fi
(cd .runtime && { nohup java -jar ../trust-server/trust-server/target/trust-server.jar "$@" > trust-server.log 2>&1 & echo $! > trust-server.pid; })
for i in $(seq 1 60); do
  sleep 1
  if curl -s localhost:8090/actuator/health | grep -q '"trust":{"details":{[^}]*},"status":"UP"\|"status":"UP"}$'; then break; fi
done
curl -s localhost:8090/actuator/health | python3 -c "import sys,json; d=json.load(sys.stdin); t=d['components']['trust']; print('trust server', d['status'], json.dumps(t['details']['sources']))"
