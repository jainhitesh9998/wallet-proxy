// Metro config for the npm-workspaces monorepo. Expo detects the workspace root automatically (watchFolders and
// node_modules lookup in the root); on top of that we make the @vctrust/* workspace packages bundle from their
// TypeScript sources on every platform (their `react-native` export condition is not applied on web).
const path = require('path');
const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);
const root = path.resolve(__dirname, '../..');
const WORKSPACE_SOURCES = {
  '@vctrust/trust-client': path.join(root, 'packages/trust-client/src/index.ts'),
  '@vctrust/wallet-core': path.join(root, 'packages/wallet-core/src/index.ts'),
};
const packagesDir = path.join(root, 'packages') + path.sep;

const upstream = config.resolver.resolveRequest;
config.resolver.resolveRequest = (context, moduleName, platform) => {
  const resolve = upstream ?? context.resolveRequest;
  if (WORKSPACE_SOURCES[moduleName]) return { type: 'sourceFile', filePath: WORKSPACE_SOURCES[moduleName] };
  // The packages use NodeNext-style `./x.js` specifiers for `./x.ts` files.
  if (context.originModulePath.startsWith(packagesDir) && moduleName.startsWith('.') && moduleName.endsWith('.js')) {
    try {
      return resolve(context, moduleName.slice(0, -3) + '.ts', platform);
    } catch {
      /* fall through: a real .js file */
    }
  }
  return resolve(context, moduleName, platform);
};

module.exports = config;
