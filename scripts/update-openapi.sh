#!/bin/sh
# Regenerates docs/openapi.json from the built service: starts the jar on a spare port with no configuration,
# reads /v3/api-docs, and writes it in the form the file is kept in (sorted keys, the default server URL).
#   scripts/update-openapi.sh [port]      (after scripts/build.sh, or mvn package in trust-server/)
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
PORT=${1:-8097}
JAR="$PWD/trust-server/trust-server/target/trust-server.jar"
[ -f "$JAR" ] || { echo "build the service first: $JAR is missing" >&2; exit 1; }
WORK=$(mktemp -d)
trap 'kill "$PID" 2>/dev/null; rm -rf "$WORK"' EXIT
(cd "$WORK" && exec java -jar "$JAR" --server.port="$PORT" > service.log 2>&1) &
PID=$!
for i in $(seq 1 60); do
  if curl -sf "localhost:$PORT/v3/api-docs" -o "$WORK/api.json"; then break; fi
  sleep 1
done
[ -s "$WORK/api.json" ] || { echo "the service did not answer on port $PORT; its log:" >&2; tail -20 "$WORK/service.log" >&2; exit 1; }
python3 - "$WORK/api.json" docs/openapi.json <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["servers"] = [{"description": "Generated server url", "url": "http://localhost:8090"}]
open(sys.argv[2], "w").write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
PY
echo "docs/openapi.json written ($(python3 -c 'import json; print(len(json.load(open("docs/openapi.json"))["paths"]))') paths)"
