#!/bin/sh
# For a failed build on GitHub Actions: writes what failed as error annotations (shown on the run's page and on the
# commit), so that it can be read without opening the log.
#   scripts/ci-report-failures.sh [directory with Surefire reports, default trust-server] [log of the build]
# Each failed test class becomes one annotation; the log's error lines (or its end) become another.
set -u
dir=${1:-trust-server}
log=${2:-}
# Annotation text is one line: %, CR and LF are escaped as the workflow command syntax asks.
annotate() { # title; text on stdin
  text=$(cut -c1-400 | sed -e 's/%/%25/g' | awk '{ gsub(/\r/, "%0D"); printf "%s%%0A", $0 }')
  echo "::error title=$1::${text}"
}
found=0
for report in $(find "$dir" -path '*/surefire-reports/*.txt' 2>/dev/null | sort); do
  grep -qE 'FAILURE!|ERROR!' "$report" || continue
  sed -n '4,60p' "$report" | annotate "$(basename "$report" .txt)"
  found=$((found + 1))
  [ "$found" -ge 8 ] && break
done
if [ -n "$log" ] && [ -f "$log" ]; then
  if grep -q '^\[ERROR\]' "$log"; then
    grep '^\[ERROR\]' "$log" | head -n 40 | annotate "Build errors"
  else
    tail -n 40 "$log" | annotate "End of the build log"
  fi
elif [ "$found" -eq 0 ]; then
  echo "::error title=Build failed::No failed test report was found under $dir: the build stopped before or outside the tests (see the log)."
fi
