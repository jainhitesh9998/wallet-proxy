/** Deferred issuance (OID4VCI 1.0 §9): 202 + transaction_id, then polling the deferred credential endpoint. */
import { expect, it } from 'vitest';
import { createTrustClient } from '@vctrust/trust-client';
import { Oid4vciClient, SoftwareKeyStore } from '../src/index.js';

it('waits for a deferred mDL', async () => {
  const o = await (await fetch('https://playground.animo.id/api/offers/create', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'none', deferBy: '1m', requireDpop: true,
      requireWalletAttestation: false, requireKeyAttestation: false }) })).json() as { credentialOffer: string };
  const trust = createTrustClient({ baseUrl: process.env.TRUST_URL ?? 'http://localhost:8090', apiKey: 'demo-wallet-key' });
  const client = new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: 'https://wallet.vctrust.dev/cb', deferredWaitSeconds: 150 });
  const session = await client.startFromOffer(o.credentialOffer);
  const t0 = Date.now();
  const [cred] = await session.acceptPreAuthorized();
  process.stderr.write(`deferred after ${Math.round((Date.now() - t0) / 1000)}s pending=${!!cred!.pending} valid=${cred!.report?.valid} trusted=${cred!.report?.trusted}\n`);
  expect(cred!.pending).toBeUndefined();
  expect(cred!.report!.trusted).toBe(true);
}, 200_000);
