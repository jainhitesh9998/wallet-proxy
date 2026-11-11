#!/bin/sh
# Builds the documentation site into site/ (or the directory given):
#   guides and READMEs   MkDocs Material over pages assembled by scripts/site-pages.mjs
#   api/rest             the OpenAPI description (docs/openapi.json), rendered by Redoc
#   api/typescript       TypeDoc for @vctrust/trust-client and @vctrust/wallet-core
#   api/java             Javadoc for the trust service modules
# Needs: node_modules (npm ci), mkdocs-material (pip install mkdocs-material), Maven.
set -e
cd "$(dirname "$0")/.." && . scripts/env.sh
OUT=${1:-site}
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
rm -rf build/site-src "$OUT"
node scripts/site-pages.mjs build/site-src
${MKDOCS:-mkdocs} build --quiet -f mkdocs.yml -d "$OUT"
mkdir -p "$OUT/api/rest"
cp docs/openapi.json "$OUT/api/rest/openapi.json"
cp docs/site/rest-api.html "$OUT/api/rest/index.html"
npx typedoc --options typedoc.json --logLevel Error --out "$OUT/api/typescript"
(cd trust-server && mvn -q -DskipTests -Ddoclint=none -Dmaven.javadoc.failOnError=false javadoc:aggregate)
JAVADOC=trust-server/target/reports/apidocs
[ -d "$JAVADOC" ] || JAVADOC=trust-server/target/site/apidocs
cp -R "$JAVADOC" "$OUT/api/java"
echo "site built in $OUT"
