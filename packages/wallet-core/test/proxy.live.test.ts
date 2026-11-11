/**
 * Live: the whole arrangement. The reference issuer and verifier run as their own process; the running trust service
 * (started with loopback access, see scripts/dev-up.sh) lists them, registered through its admin API; the wallet knows
 * only the trust service. It then learns everything about the issuer and the verifier through the library:
 *
 *  - trust decisions from the signed snapshot, on the device;
 *  - issuer metadata through the proxy;
 *  - the issuer's DID document and JSON-LD context from the snapshot (the service resolved and fetched them);
 *  - the IACA's CRL from the snapshot, status lists through the proxy.
 *
 * And when the service stops answering, the same wallet goes on with the snapshot it holds and the standard
 * mechanisms: discovery at the issuer, status lists from their hosts.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TrustClient } from '@vctrust/trust-client';
import { MemoryCredentialStore, SoftwareKeyStore, Wallet, type IssuedCredential } from '../src/index.js';
import { CONFIGURATIONS, LOOPBACK, start, type Ecosystem } from './ecosystem.js';
import { liveTrust, managed, TRUST_URL } from './live-trust.js';

let eco: Ecosystem;
let trust: TrustClient;
let wallet: Wallet;
/** While true, the trust service is unreachable for this wallet. */
let serviceDown = false;
const serviceFetch = (async (input: string | URL | Request, init?: RequestInit) => {
  if (serviceDown && String(input instanceof Request ? input.url : input).startsWith(TRUST_URL)) throw new TypeError('fetch failed: the trust service is down');
  return fetch(input, init);
}) as typeof fetch;
const log = (s: string) => process.stderr.write(`${s}\n`);
const pem = async (url: string) => (await fetch(url)).text();
const ids = { entities: ['live-reference-issuer', 'live-reference-verifier'], anchors: ['live-reference-iaca', 'live-reference-issuer-ca', 'live-reference-verifier-ca'] };

beforeAll(async () => {
  eco = await start();
  trust = await liveTrust({ http: { fetch: serviceFetch, insecureHosts: LOOPBACK, retries: 0, timeoutMs: 10_000 }, snapshot: { retryMs: 0 } });
  // What the snapshot holds before this ecosystem is listed (other parties may be registered in the running service).
  const before = await trust.sync();
  const contextUrl = `${eco.issuerUrl}/contexts/reference/v1`;
  // What an operator would put in the registry: who the parties are, which certificates are theirs, which contexts they use.
  await managed('PUT', 'entities', ids.entities[0]!, { framework: 'reference', roles: ['CREDENTIAL_ISSUER'], name: 'Reference issuer',
    identifiers: [{ type: 'URL', value: eco.issuerUrl }, eco.issuer.did], contexts: [contextUrl],
    authorizations: [{ format: 'mso_mdoc', type: 'org.iso.18013.5.1.mDL' }, { format: 'dc+sd-jwt', type: 'urn:reference:identity:1' }, { format: 'ldp_vc', type: 'UniversityDegreeCredential' }] });
  await managed('PUT', 'entities', ids.entities[1]!, { framework: 'reference', roles: ['VERIFIER'], name: 'Reference verifier',
    identifiers: [{ type: 'CLIENT_ID', value: eco.verifier.clientId }] });
  await managed('PUT', 'anchors', ids.anchors[0]!, { framework: 'reference', domain: 'mdoc-iaca', entity: ids.entities[0], certificate: await pem(`${eco.issuerUrl}/pki/iaca.pem`),
    constraints: { docTypes: ['org.iso.18013.5.1.mDL'], crlUrls: [`${eco.issuerUrl}/pki/iaca.crl`] } });
  await managed('PUT', 'anchors', ids.anchors[1]!, { framework: 'reference', domain: 'credential-issuer', entity: ids.entities[0], certificate: await pem(`${eco.issuerUrl}/pki/issuer-ca.pem`) });
  await managed('PUT', 'anchors', ids.anchors[2]!, { framework: 'reference', domain: 'verifier-access', certificate: await pem(`${eco.verifierUrl}/pki/verifier-ca.pem`) });
  // The service resolves the DID, fetches the context and the CRL after the registration; wait for a snapshot that has them.
  for (let i = 0; i < 60; i++) {
    const s = await trust.sync();
    if (s.didDocuments > before.didDocuments && s.contexts > before.contexts && s.crls > before.crls) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.example/callback',
    clientId: 'reference-wallet', insecureHosts: LOOPBACK });
}, 120_000);

afterAll(async () => {
  for (const id of ids.anchors) await managed('DELETE', 'anchors', id);
  for (const id of ids.entities) await managed('DELETE', 'entities', id);
  await eco?.stop();
});

async function issue(configurationId: string): Promise<IssuedCredential> {
  const offer = await eco.issuer.createOffer({ configurationIds: [configurationId] });
  const session = await wallet.receive(offer.credentialOfferUri);
  const issued = await session.acceptPreAuthorized();
  await wallet.store(issued);
  log(`\n== ${configurationId}: metadata via ${session.metadata.source}, issuer ${session.issuerTrust.decision} (${session.issuerTrust.source})`);
  for (const x of issued[0]!.report!.checks) log(`  [${x.status}] ${x.label}: ${x.detail ?? ''}`.slice(0, 230));
  return issued[0]!;
}
const detail = (c: IssuedCredential, id: string) => c.report!.checks.find((x) => x.id === id)?.detail ?? '';

describe('the wallet knows the ecosystem only through the trust service', () => {
  it('holds a snapshot with the parties, their anchors, the issuer\'s DID document, its JSON-LD context and the IACA\'s CRL', async () => {
    const status = await trust.status();
    expect(status).toMatchObject({ service: 'online', degraded: false });
    expect(status.snapshot).toMatchObject({ stale: false });
    expect(status.snapshot!.didDocuments).toBeGreaterThanOrEqual(1);
    expect(status.snapshot!.contexts).toBeGreaterThanOrEqual(1);
    const context = await trust.context(`${eco.issuerUrl}/contexts/reference/v1`);
    expect(context).toMatchObject({ source: 'snapshot', vouched: true });
    expect((await trust.resolveDid(eco.issuer.did)).didResolutionMetadata.source).toBe('snapshot');
  });

  it('gets issuer metadata through the proxy and decides the issuer\'s trust on the device', async () => {
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.mdl] });
    const session = await wallet.receive(offer.credentialOfferUri);
    expect(session.metadata.source).toBe('proxy');
    expect(session.issuerTrust).toMatchObject({ decision: 'TRUSTED', source: 'snapshot', entity: { id: 'live-reference-issuer' }, framework: { id: 'reference' } });
  });

  it('issues a W3C credential and verifies it without contacting the issuer\'s DID or context hosts', async () => {
    const c = await issue(CONFIGURATIONS.ecdsa);
    expect(c.report).toMatchObject({ valid: true, trusted: true, trust: { source: 'snapshot' } });
    expect(detail(c, 'ldp.signature')).toMatch(/\(snapshot\) over RDFC-1\.0/);
    expect(c.report!.checks.find((x) => x.id === 'ldp.contexts')).toMatchObject({ status: 'pass' });
    expect(detail(c, 'ldp.status')).toMatch(/via the trust service relay/);
  });

  it('issues an mDL whose Document Signer is checked against the IACA\'s CRL from the snapshot', async () => {
    const c = await issue(CONFIGURATIONS.mdl);
    expect(c.report).toMatchObject({ valid: true, trusted: true });
    expect(c.report!.trust!.evidence!.x509!.revocation![0]).toMatchObject({ status: 'GOOD', method: 'crl', source: 'snapshot' });
  });

  it('issues an SD-JWT VC whose status list comes through the proxy', async () => {
    const c = await issue(CONFIGURATIONS.identity);
    expect(c.report).toMatchObject({ valid: true, trusted: true });
    expect(detail(c, 'sdjwt.status')).toMatch(/via the trust service relay/);
  });

  it('presents to the verifier the service lists', async () => {
    const request = await eco.verifier.createRequest({ credentials: [{ format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL', claims: [['org.iso.18013.5.1', 'family_name']] }] });
    const session = await wallet.startPresentation(request.authorizationRequestUri);
    expect(session.verifier).toMatchObject({ name: 'Reference verifier', trust: { decision: 'TRUSTED', source: 'snapshot' } });
    await session.respond();
    expect((await eco.verifier.requestState(request.id)).status).toBe('verified');
  });

  it('refuses a credential type the registry does not authorize the issuer for, when the client profile is strict', async () => {
    // The demo wallet's profile is lenient; the decision for the same question under the registry's authorizations:
    const d = await trust.evaluateIssuer({ credentialIssuer: eco.issuerUrl, format: 'dc+sd-jwt', type: 'urn:eudi:pid:1' });
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.reasons.map((r) => r.code)).toContain('entity.not_authorized');
  });
});

describe('when the trust service stops answering', () => {
  beforeAll(() => { serviceDown = true; });
  afterAll(() => { serviceDown = false; });

  it('goes on with the snapshot it holds and the standard mechanisms', async () => {
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.identity] });
    // A wallet that has never seen this issuer's metadata: a fresh client over the same stored snapshot would do the same.
    const session = await wallet.receive(offer.credentialOfferUri);
    expect(['cache', 'fallback']).toContain(session.metadata.source);
    expect(session.issuerTrust).toMatchObject({ decision: 'TRUSTED', source: 'snapshot' });
    const [c] = await session.acceptPreAuthorized();
    expect(c!.report).toMatchObject({ valid: true, trusted: true, trust: { source: 'snapshot' } });
    log(`\n== service down: status ${detail(c!, 'sdjwt.status')}`);
    // The status list of a new credential may be cached from before; either way it never came from the unreachable relay just now.
    expect((await trust.status()).snapshot).not.toBeNull();
  });

  it('reaches an issuer it has no cached metadata for by standard discovery', async () => {
    const fresh = await liveTrust({ http: { fetch: serviceFetch, insecureHosts: LOOPBACK, retries: 0, timeoutMs: 5_000 }, pinned: {} });
    const d = await fresh.getIssuerMetadata(eco.issuerUrl);
    expect(d.source).toBe('fallback');
    // Without a snapshot and with nothing pinned, nobody is trusted: the fallback fetches, it does not vouch.
    expect(d.trust).toMatchObject({ decision: 'UNKNOWN', source: 'pinned' });
    expect((await fresh.status()).degraded).toBe(true);
  });
});
