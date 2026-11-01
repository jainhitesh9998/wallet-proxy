/** Live OpenID4VP 1.0 (HAIP: x509_hash, request_uri, direct_post.jwt, DCQL) presentation of an mDL to the Animo verifier. */
import { expect, it } from 'vitest';
import { createTrustClient } from '@vctrust/trust-client';
import { MemoryCredentialStore, SoftwareKeyStore, Wallet } from '../src/index.js';

const PLAYGROUND = 'https://playground.animo.id';
const log = (s: string) => process.stderr.write(`${s}\n`);

it('issues an mDL then presents it to the HAIP verifier', async () => {
  const trust = createTrustClient({ baseUrl: process.env.TRUST_URL ?? 'http://localhost:8090', apiKey: 'demo-wallet-key', clientId: 'demo-wallet' });
  const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.vctrust.dev/cb' });
  const offer = await (await fetch(`${PLAYGROUND}/api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'none', deferBy: 'none', requireDpop: true,
      requireWalletAttestation: false, requireKeyAttestation: false }) })).json() as { credentialOffer: string };
  const session = await wallet.receive(offer.credentialOffer);
  await wallet.store(await session.acceptPreAuthorized());

  const req = await (await fetch(`${PLAYGROUND}/api/requests/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request: { credentials: [{ id: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name', 'birth_date'] }], combination: 'all' },
      requestScheme: 'openid4vp://', responseMode: 'direct_post.jwt', requestSignerType: 'x5c', transactionAuthorizationType: 'none' }) })).json() as
    { authorizationRequestUri: string; verificationSessionId: string };
  const p = await wallet.startPresentation(req.authorizationRequestUri);
  log(`verifier ${p.verifier.clientId} name=${p.verifier.name} trust=${p.verifier.trust.decision}: ${p.verifier.trust.summary}`);
  for (const c of p.verifier.checks) log(`  [${c.ok ? 'ok' : '!!'}] ${c.label}: ${c.detail ?? ''}`);
  log(`dcql satisfied=${p.dcql.satisfied} selected=${p.dcql.selected}`);
  expect(p.dcql.satisfied).toBe(true);
  const res = await p.respond();
  log(`response: HTTP ${res.status} ${JSON.stringify(res.body).slice(0, 300)}`);
  expect(res.status).toBe(200);
  let status = '';
  for (let i = 0; i < 10 && status !== 'ResponseVerified' && status !== 'Error'; i++) {
    const s = await (await fetch(`${PLAYGROUND}/api/requests/${req.verificationSessionId}`)).json() as Record<string, unknown>;
    status = String(s.responseStatus);
    if (status === 'ResponseVerified' || status === 'Error') log(`verifier result: ${JSON.stringify(s).slice(0, 900)}`);
    else await new Promise((r) => setTimeout(r, 1000));
  }
  expect(status).toBe('ResponseVerified');
}, 90_000);
