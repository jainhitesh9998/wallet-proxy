/** Deferred issuance (OID4VCI 1.0 §9): 202 + transaction_id, then polling the deferred credential endpoint. */
import { expect, it } from 'vitest';
import { liveTrust } from './live-trust.js';
import { MemoryCredentialStore, Oid4vciClient, SoftwareKeyStore, Wallet } from '../src/index.js';

it('waits for a deferred mDL', async () => {
  const o = await (await fetch('https://playground.animo.id/api/offers/create', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'none', deferBy: '1m', requireDpop: true,
      requireWalletAttestation: false, requireKeyAttestation: false }) })).json() as { credentialOffer: string };
  const trust = await liveTrust();
  const client = new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: 'https://wallet.vctrust.dev/cb', deferredWaitSeconds: 150 });
  const session = await client.startFromOffer(o.credentialOffer);
  const t0 = Date.now();
  const [cred] = await session.acceptPreAuthorized();
  process.stderr.write(`deferred after ${Math.round((Date.now() - t0) / 1000)}s pending=${!!cred!.pending} valid=${cred!.report?.valid} trusted=${cred!.report?.trusted}\n`);
  expect(cred!.pending).toBeUndefined();
  expect(cred!.report!.trusted).toBe(true);
}, 200_000);

it('keeps a deferred mDL pending, then retrieves it later (OID4VCI §9)', async () => {
  const o = await (await fetch('https://playground.animo.id/api/offers/create', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'none', deferBy: '1m', requireDpop: true,
      requireWalletAttestation: false, requireKeyAttestation: false }) })).json() as { credentialOffer: string };
  const trust = await liveTrust();
  const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.vctrust.dev/cb', batchSize: 2 });
  (wallet.oid4vci.opts as { deferredWaitSeconds?: number }).deferredWaitSeconds = 0;
  const [pending] = await wallet.store(await (await wallet.receive(o.credentialOffer)).acceptPreAuthorized());
  expect(pending!.pending?.dpopKeyId).toBeDefined();
  let c = await wallet.retrieveDeferred(pending!.id);
  for (let i = 0; i < 20 && c.pending; i++) {
    await new Promise((r) => setTimeout(r, Math.max(5, c.pending!.interval) * 1000));
    c = await wallet.retrieveDeferred(pending!.id);
  }
  process.stderr.write(`retrieved: pending=${!!c.pending} instances=${1 + (c.instances?.length ?? 0)} trusted=${c.report?.trusted}\n`);
  expect(c.pending).toBeUndefined();
  expect(c.report!.trusted).toBe(true);
  expect((await wallet.list()).map((x) => x.id)).toEqual([pending!.id]);
}, 200_000);
