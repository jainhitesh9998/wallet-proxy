#!/usr/bin/env node
/**
 * Assembles the pages of the documentation site from the Markdown that lives next to the code, so nothing is written
 * twice: the READMEs and the guides in docs/. Links between those files become links between pages; a link to anything
 * else in the repository becomes a link to it on GitHub.
 *
 *   node scripts/site-pages.mjs <output directory>
 */
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, normalize, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(process.argv[2] ?? 'build/site-src');
const REPOSITORY = (process.env.REPOSITORY_URL ?? 'https://github.com/jainhitesh9998/wallet-proxy').replace(/\/$/, '');
const BRANCH = process.env.REPOSITORY_BRANCH ?? 'main';

/** source file → page of the site */
const PAGES = {
  'README.md': 'index.md',
  'docs/architecture.md': 'architecture.md',
  'docs/configuration.md': 'configuration.md',
  'docs/trust-methods.md': 'trust-methods.md',
  'trust-server/README.md': 'service.md',
  'packages/trust-client/README.md': 'library.md',
  'packages/wallet-core/README.md': 'wallet-core.md',
  'apps/wallet/README.md': 'wallet-app.md',
  'test-ecosystem/README.md': 'reference-ecosystem.md',
  'conformance/README.md': 'conformance.md',
  'conformance/real-world/README.md': 'real-world-credentials.md',
  'CONTRIBUTING.md': 'contributing.md',
  'SECURITY.md': 'security.md',
};
/** repository files that the site serves in another form */
const RENDERED = { 'docs/openapi.json': 'api/rest/index.html', LICENSE: `${REPOSITORY}/blob/${BRANCH}/LICENSE` };

function rewrite(target, source) {
  if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target)) return target;
  const [path, anchor = ''] = target.split(/(?=#)/);
  const file = normalize(join(dirname(source), path)).replace(/\/$/, '');
  if (PAGES[file]) return PAGES[file] + anchor;
  if (RENDERED[file]) return RENDERED[file];
  const absolute = join(root, file);
  if (!existsSync(absolute)) {
    console.warn(`${source}: link to ${target} points at nothing`);
    return target;
  }
  return `${REPOSITORY}/${statSync(absolute).isDirectory() ? 'tree' : 'blob'}/${BRANCH}/${file}${anchor}`;
}

mkdirSync(out, { recursive: true });
for (const [source, page] of Object.entries(PAGES)) {
  let text = readFileSync(join(root, source), 'utf8');
  // Fenced code is left alone; everywhere else, [text](target) and bare ](target) are rewritten.
  text = text.split(/(^```[\s\S]*?^```)/m).map((part, i) => (i % 2 ? part
    : part.replace(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewrite(target, source)})`))).join('');
  writeFileSync(join(out, page), `${text.trimEnd()}\n\n---\n\n<small>Source: [${source}](${REPOSITORY}/blob/${BRANCH}/${source})</small>\n`);
}
console.log(`${Object.keys(PAGES).length} pages in ${relative(root, out) || out}`);
