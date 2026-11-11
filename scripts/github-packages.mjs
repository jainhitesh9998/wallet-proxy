#!/usr/bin/env node
/**
 * Prepares the npm packages for GitHub Packages, whose npm registry only takes packages scoped to the owner of the
 * repository. Run in a CI checkout after the packages are built; it changes package.json and README files in place
 * and is not meant to be committed:
 *
 *   @vctrust/trust-client  ->  @<owner>/trust-client
 *   @vctrust/wallet-core   ->  @<owner>/wallet-core, depending on the library through an npm alias
 *                              ("@vctrust/trust-client": "npm:@<owner>/trust-client@<version>"), so that its
 *                              compiled imports of @vctrust/trust-client keep resolving at the consumer
 *
 *   node scripts/github-packages.mjs <owner>
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const owner = (process.argv[2] ?? process.env.GITHUB_REPOSITORY_OWNER ?? '').toLowerCase();
if (!/^[a-z0-9][a-z0-9-]*$/.test(owner)) {
  console.error('usage: node scripts/github-packages.mjs <repository owner>');
  process.exit(1);
}
const REGISTRY = 'https://npm.pkg.github.com';
const SCOPE = '@vctrust/';

const read = (dir) => JSON.parse(readFileSync(join(root, dir, 'package.json'), 'utf8'));
const write = (dir, pkg) => writeFileSync(join(root, dir, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);

const library = read('packages/trust-client');
const published = (name) => `@${owner}/${name.slice(SCOPE.length)}`;

for (const dir of ['packages/trust-client', 'packages/wallet-core']) {
  const pkg = read(dir);
  const original = pkg.name;
  const name = published(original);
  // The wallet core keeps importing the library under its own name; npm installs the renamed package under that name.
  if (pkg.dependencies?.[library.name]) pkg.dependencies[library.name] = `npm:${published(library.name)}@${library.version}`;
  // Workspace-only development dependencies do not exist in the registry.
  for (const dep of Object.keys(pkg.devDependencies ?? {})) if (dep.startsWith(SCOPE)) delete pkg.devDependencies[dep];
  pkg.name = name;
  pkg.publishConfig = { registry: REGISTRY };
  // Published from files already built: nothing runs on install or pack.
  delete pkg.scripts;
  write(dir, pkg);
  const readme = join(root, dir, 'README.md');
  const note = `> Published to GitHub Packages as \`${name}\`. Where this document says \`${original}\`, that is this package`
    + `${dir.endsWith('wallet-core') ? `; it installs the library under the name \`${library.name}\`, which is the name to import the trust client by` : ''}.\n\n`;
  writeFileSync(readme, note + readFileSync(readme, 'utf8'));
  console.log(`${dir}: ${name}@${pkg.version}`);
}
