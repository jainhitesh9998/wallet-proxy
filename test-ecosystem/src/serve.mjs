/**
 * Runs the reference issuer and verifier on loopback. As a program: `node src/serve.mjs`, with ISSUER_PORT (8791),
 * VERIFIER_PORT (8792) and DATA_DIR (test-ecosystem/.data) from the environment. As a module: `startEcosystem`.
 */
import { realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { serve } from './http.mjs';
import { createIssuer } from './issuer.mjs';
import { generatePki, loadOrCreatePki } from './pki.mjs';
import { createVerifier } from './verifier.mjs';

/**
 * @param {{ issuerPort?: number, verifierPort?: number, dataDir?: string }} [opts] port 0 picks a free port; with
 *   `dataDir` the PKI and the issuer's keys and status lists persist there, without it everything is new and in memory
 * @returns {Promise<{ issuer: Awaited<ReturnType<typeof createIssuer>>, verifier: Awaited<ReturnType<typeof createVerifier>>,
 *   issuerUrl: string, verifierUrl: string, pki: import('./pki.mjs').Pki, stop(): Promise<void> }>}
 */
export async function startEcosystem({ issuerPort = 8791, verifierPort = 8792, dataDir } = {}) {
  // The ports are bound first: the certificates and the DID name the issuer's URL, which a free port decides.
  const handlers = {};
  const starting = { status: 503, body: { error: 'temporarily_unavailable' } };
  const servers = [];
  const stop = () => Promise.all(servers.map((server) => server.close())).then(() => {});
  try {
    servers.push(await serve((request, body) => handlers.issuer?.(request, body) ?? starting, issuerPort));
    servers.push(await serve((request, body) => handlers.verifier?.(request, body) ?? starting, verifierPort));
    const [issuerUrl, verifierUrl] = servers.map((server) => `http://localhost:${server.port}`);
    const names = { issuerUrl, verifierHost: 'localhost' };
    const pki = dataDir ? await loadOrCreatePki(dataDir, names) : await generatePki(names);
    const issuer = await createIssuer({ baseUrl: issuerUrl, pki, dataDir });
    const verifier = await createVerifier({ baseUrl: verifierUrl, pki });
    handlers.issuer = issuer.handle;
    handlers.verifier = verifier.handle;
    return { issuer, verifier, issuerUrl, verifierUrl, pki, stop };
  } catch (e) {
    await stop();
    throw e;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const { issuer, issuerUrl, verifier, verifierUrl, stop } = await startEcosystem({
    issuerPort: Number(process.env.ISSUER_PORT ?? 8791), verifierPort: Number(process.env.VERIFIER_PORT ?? 8792),
    dataDir: process.env.DATA_DIR ?? fileURLToPath(new URL('../.data', import.meta.url)),
  });
  console.log([
    `Reference issuer    ${issuerUrl}`,
    `  metadata          ${issuerUrl}/.well-known/openid-credential-issuer`,
    `  issuer DID        ${issuer.did}`,
    `  trust anchors     ${issuerUrl}/pki/iaca.pem (mdoc), ${issuerUrl}/pki/issuer-ca.pem (SD-JWT VC), CRL ${issuerUrl}/pki/iaca.crl`,
    `  configurations    ${issuer.configurationIds.join(', ')}`,
    `  create an offer   curl -s ${issuerUrl}/api/offers -H 'Content-Type: application/json' -d '{"configurationIds":["${issuer.configurationIds[0]}"]}'`,
    `Reference verifier  ${verifierUrl}`,
    `  client_id         ${verifier.clientId}`,
    `  trust anchor      ${verifierUrl}/pki/verifier-ca.pem`,
    `  create a request  curl -s ${verifierUrl}/api/requests -H 'Content-Type: application/json' -d '{"credentials":[{"format":"dc+sd-jwt","vct":"urn:reference:identity:1","claims":[["given_name"]]}]}'`,
  ].join('\n'));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => stop().then(() => process.exit(0)));
}
