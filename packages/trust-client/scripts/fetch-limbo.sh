#!/bin/sh
# Downloads the C2SP x509-limbo test suite (https://github.com/C2SP/x509-limbo, Apache-2.0) at a pinned commit into
# a git-ignored cache directory and prints the path of limbo.json (about 42 MB). Used by the opt-in conformance test:
#
#   LIMBO_JSON="$(sh scripts/fetch-limbo.sh)" npx vitest run test/x509-limbo.conformance.test.ts --reporter=default
#
# The file is test data only: it is never executed, and nothing of it is checked in.
set -eu

# Pinned so that results are reproducible; bump deliberately and re-run the harness (the skip table is keyed by id).
LIMBO_COMMIT="${LIMBO_COMMIT:-519f4bcf6a31d20e1b7011a0586e233dbbd3e732}"

here="$(cd "$(dirname "$0")" && pwd)"
cache="${LIMBO_CACHE_DIR:-$here/../.cache}"
dir="$cache/x509-limbo/$LIMBO_COMMIT"
file="$dir/limbo.json"

mkdir -p "$dir"
# The cache directory ignores itself, so no root .gitignore entry is needed.
[ -f "$cache/.gitignore" ] || printf '*\n' > "$cache/.gitignore"

if [ ! -s "$file" ]; then
  url="https://raw.githubusercontent.com/C2SP/x509-limbo/$LIMBO_COMMIT/limbo.json"
  echo "Downloading $url" >&2
  curl --fail --silent --show-error --location --retry 3 --output "$file.part" "$url"
  # A truncated download must not be mistaken for the suite.
  tail -c 64 "$file.part" | grep -q '}' || { echo "Download of limbo.json looks truncated" >&2; rm -f "$file.part"; exit 1; }
  mv "$file.part" "$file"
fi

(cd "$dir" && printf '%s/limbo.json\n' "$(pwd)")
