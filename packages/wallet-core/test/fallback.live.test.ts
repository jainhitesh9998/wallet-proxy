/**
 * Trust service outage: the wallet keeps working on standard mechanisms (direct OpenID4VCI discovery, local DID
 * resolution, local X.509 validation) and decides trust from the signed offline snapshot — or reports UNKNOWN.
 */
import { describe, expect, it } from 'vitest';
import { createTrustClient, MemoryCacheStore } from '@vctrust/trust-client';
import { MemoryCredentialStore, Oid4vciClient, SoftwareKeyStore, Wallet, type IssuerClientRegistration } from '../src/index.js';
// @ts-expect-error untyped helper script
import { loginAndGetCode } from '../../../tools/mosip-issuance/issue.mjs';

const TRUST = process.env.TRUST_URL ?? 'http://localhost:8090';
const PLAYGROUND = 'https://playground.animo.id';
const log = (s: string) => process.stderr.write(`${s}\n`);

/** fetch that black-holes the trust service while `down` is set. */
function outageFetch() {
  const state = { down: false, blocked: 0 };
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (state.down && String(input).startsWith(TRUST)) { state.blocked++; throw new TypeError('fetch failed: ECONNREFUSED (simulated outage)'); }
    return fetch(input, init);
  }) as typeof fetch;
  return { f, state };
}

async function animoOffer(id: string) {
  const r = await fetch(`${PLAYGROUND}/api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: [id], authorization: 'none', deferBy: 'none', requireDpop: true, requireWalletAttestation: false, requireKeyAttestation: false }) });
  return ((await r.json()) as { credentialOffer: string }).credentialOffer;
}

function trustClient(f: typeof fetch) {
  return createTrustClient({ baseUrl: TRUST, apiKey: 'demo-wallet-key', clientId: 'demo-wallet', fetch: f, cache: new MemoryCacheStore(),
    retries: 0, timeoutMs: 1500, circuitBreaker: { failureThreshold: 2, resetAfterMs: 1000 }, serviceKeys: { trustOnFirstUse: true } });
}

describe('trust service outage', () => {
  it('mDL issuance + presentation continue from the signed snapshot', async () => {
    const { f, state } = outageFetch();
    const trust = trustClient(f);
    const snap = await trust.syncSnapshot();
    log(`snapshot v${snap.version}: ${snap.entities.length} entities, ${snap.anchors.length} anchors`);
    state.down = true;
    const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), fetch: f, redirectUri: 'https://wallet.vctrust.dev/cb' });
    const session = await wallet.receive(await animoOffer('mdl-mdoc-utopia'));
    log(`metadata source=${session.metadata.source} issuer trust=${session.issuerTrust.decision}/${session.issuerTrust.source}`);
    expect(session.metadata.source).toBe('fallback');
    expect(session.issuerTrust.source).toBe('snapshot');
    expect(session.issuerTrust.decision).toBe('TRUSTED');
    const [cred] = await wallet.store(await session.acceptPreAuthorized());
    log(`credential valid=${cred!.report?.valid} trust=${cred!.report?.trust?.decision}/${cred!.report?.trust?.source}: ${cred!.report?.trust?.summary}`);
    expect(cred!.report!.valid).toBe(true);
    expect(cred!.report!.trust?.decision).toBe('TRUSTED');
    expect(cred!.report!.trust?.source).toBe('snapshot');

    const req = await (await fetch(`${PLAYGROUND}/api/requests/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request: { credentials: [{ id: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name'] }], combination: 'all' },
        requestScheme: 'openid4vp://', responseMode: 'direct_post.jwt', requestSignerType: 'x5c', transactionAuthorizationType: 'none' }) })).json() as
      { authorizationRequestUri: string };
    const p = await wallet.startPresentation(req.authorizationRequestUri);
    log(`verifier trust=${p.verifier.trust.decision}/${p.verifier.trust.source}: ${p.verifier.trust.summary}`);
    expect(p.verifier.trust.source).toBe('snapshot');
    expect(p.verifier.trust.decision).toBe('TRUSTED');
    expect((await p.respond()).status).toBe(200);
    expect(state.blocked).toBeGreaterThan(0);
    expect(trust.status).toBe('offline');

    // recovery after the circuit cool-down
    state.down = false;
    await new Promise((r) => setTimeout(r, 1100));
    const back = await trust.evaluateIssuer({ credentialIssuer: `${PLAYGROUND}/oid4vci/b39e71cf-9cf1-4723-a9cd-66f42a510b36` });
    expect(back.source).toBe('trust-service');
    expect(trust.status).toBe('online');
  }, 120_000);

  it('without any snapshot the credential is still verified, but trust is UNKNOWN', async () => {
    const { f, state } = outageFetch();
    state.down = true;
    const trust = trustClient(f);
    const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), fetch: f, redirectUri: 'https://wallet.vctrust.dev/cb' });
    const session = await wallet.receive(await animoOffer('mdl-mdoc-utopia'));
    const [cred] = await session.acceptPreAuthorized();
    log(`no-snapshot: valid=${cred!.report?.valid} trusted=${cred!.report?.trusted} trust=${cred!.report?.trust?.decision}/${cred!.report?.trust?.source}`);
    expect(cred!.report!.valid).toBe(true);
    expect(cred!.report!.trusted).toBe(false);
    expect(cred!.report!.trust?.decision).toBe('UNKNOWN');
    expect(cred!.report!.trust?.source).toBe('fallback');
  }, 120_000);

  it('JSON-LD (MOSIP) issuance resolves did:web locally and trusts from the snapshot', async () => {
    const { f, state } = outageFetch();
    const trust = trustClient(f);
    await trust.syncSnapshot();
    state.down = true;
    const REDIRECT = 'io.mosip.residentapp.inji://oauthredirect';
    const registrations: Record<string, IssuerClientRegistration> = { 'https://injicertify-farmer.collab.mosip.net': { clientId: 'mpartner-default-mimoto-land-oidc',
      redirectUri: REDIRECT, tokenEndpoint: 'https://api.collab.mosip.net/v1/mimoto/get-token/Farmer', extraAuthorizeParams: { ui_locales: 'en' } } };
    const client = new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), fetch: f, redirectUri: REDIRECT, registrations });
    const session = await client.startWalletInitiated('https://injicertify-farmer.collab.mosip.net', ['FarmerCredential_VCDM2.0']);
    expect(session.metadata.source).toBe('fallback');
    const { authorizationUrl } = await session.beginAuthorization();
    const { redirectUrl } = await loginAndGetCode(authorizationUrl, REDIRECT, { log: () => undefined });
    const [cred] = await session.completeAuthorization(redirectUrl);
    for (const c of cred!.report!.checks) log(`  [${c.status}] ${c.label}: ${c.detail ?? ''}`.slice(0, 180));
    expect(cred!.report!.valid).toBe(true);
    expect(cred!.report!.checks.find((c) => c.id === 'ldp.vm')?.detail).toContain('fallback');
    expect(cred!.report!.trust?.decision).toBe('TRUSTED');
    expect(cred!.report!.trust?.source).toBe('snapshot');
  }, 180_000);
});
