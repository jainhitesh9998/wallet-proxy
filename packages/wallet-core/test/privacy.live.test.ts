/**
 * Device-side decisions keep the user's activity private: in 'local' mode the trust service only ever sees snapshot
 * (and JWKS) requests — never which issuers the user receives credentials from, which verifiers they present to,
 * or any certificate or credential data. Every request the trust client makes is recorded and checked.
 */
import { describe, expect, it } from 'vitest';
import { liveTrust, TRUST_URL } from './live-trust.js';
import { MemoryCredentialStore, Oid4vciClient, SoftwareKeyStore, Wallet, type IssuerClientRegistration } from '../src/index.js';
// @ts-expect-error untyped helper script
import { loginAndGetCode } from '../../../tools/mosip-issuance/issue.mjs';

const PLAYGROUND = 'https://playground.animo.id';
const ALLOWED = new Set(['GET /api/v1/snapshot', 'GET /.well-known/jwks.json']);
const log = (s: string) => process.stderr.write(`${s}\n`);

function recordingFetch() {
  const toService: string[] = [];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith(TRUST_URL)) toService.push(`${init?.method ?? 'GET'} ${new URL(url).pathname}`);
    return fetch(input, init);
  }) as typeof fetch;
  return { f, toService };
}

describe('local decisions: the trust service learns nothing about the user', () => {
  it('mDL issuance and presentation (Animo)', async () => {
    const { f, toService } = recordingFetch();
    const trust = await liveTrust({ fetch: f });
    const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.vctrust.dev/cb' });
    const offer = await (await fetch(`${PLAYGROUND}/api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'none', deferBy: 'none', requireDpop: true,
        requireWalletAttestation: false, requireKeyAttestation: false }) })).json() as { credentialOffer: string };
    const session = await wallet.receive(offer.credentialOffer);
    expect(session.metadata.source).toBe('direct');
    expect(session.issuerTrust.source).toBe('snapshot');
    const [cred] = await wallet.store(await session.acceptPreAuthorized());
    log(`mDL valid=${cred!.report?.valid} trust=${cred!.report?.trust?.decision}/${cred!.report?.trust?.source}: ${cred!.report?.trust?.summary}`);
    expect(cred!.report!.valid).toBe(true);
    expect(cred!.report!.trust).toMatchObject({ decision: 'TRUSTED', source: 'snapshot' });
    // The Document Signer is checked against Animo's IACA CRL, which the service compiled into the snapshot.
    expect(cred!.report!.trust?.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'GOOD', source: 'snapshot', crlUrl: 'https://playground.animo.id/crl' });

    const req = await (await fetch(`${PLAYGROUND}/api/requests/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request: { credentials: [{ id: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name'] }], combination: 'all' },
        requestScheme: 'openid4vp://', responseMode: 'direct_post.jwt', requestSignerType: 'x5c', transactionAuthorizationType: 'none' }) })).json() as
      { authorizationRequestUri: string; verificationSessionId: string };
    const p = await wallet.startPresentation(req.authorizationRequestUri);
    log(`verifier trust=${p.verifier.trust.decision}/${p.verifier.trust.source}: ${p.verifier.trust.summary}`);
    expect(p.verifier.trust).toMatchObject({ decision: 'TRUSTED', source: 'snapshot' });
    expect((await p.respond()).status).toBe(200);

    log(`requests to the trust service: ${JSON.stringify(toService)}`);
    expect(toService.length).toBeGreaterThan(0);
    expect(toService.filter((r) => !ALLOWED.has(r))).toEqual([]);
  }, 120_000);

  it('JSON-LD issuance (MOSIP): the issuer DID document comes from the snapshot', async () => {
    const { f, toService } = recordingFetch();
    const trust = await liveTrust({ fetch: f });
    const REDIRECT = 'io.mosip.residentapp.inji://oauthredirect';
    const registrations: Record<string, IssuerClientRegistration> = { 'https://injicertify-farmer.collab.mosip.net': { clientId: 'mpartner-default-mimoto-land-oidc',
      redirectUri: REDIRECT, tokenEndpoint: 'https://api.collab.mosip.net/v1/mimoto/get-token/Farmer', extraAuthorizeParams: { ui_locales: 'en' } } };
    const client = new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: REDIRECT, registrations });
    const session = await client.startWalletInitiated('https://injicertify-farmer.collab.mosip.net', ['FarmerCredential_VCDM2.0']);
    const { authorizationUrl } = await session.beginAuthorization();
    const { redirectUrl } = await loginAndGetCode(authorizationUrl, REDIRECT, { log: () => undefined });
    const [cred] = await session.completeAuthorization(redirectUrl);
    const vm = cred!.report!.checks.find((c) => c.id === 'ldp.vm');
    log(`farmer valid=${cred!.report?.valid} ${vm?.detail} trust=${cred!.report?.trust?.decision}/${cred!.report?.trust?.source}`);
    expect(cred!.report!.valid).toBe(true);
    expect(vm?.detail).toContain('snapshot');
    expect(cred!.report!.trust).toMatchObject({ decision: 'TRUSTED', source: 'snapshot' });

    log(`requests to the trust service: ${JSON.stringify(toService)}`);
    expect(toService.filter((r) => !ALLOWED.has(r))).toEqual([]);
  }, 180_000);
});
