/** Live batch issuance (OID4VCI 1.0 §8.2, HAIP §4) from the Animo playground, then one fresh instance per presentation. */
import { describe, expect, it } from 'vitest';
import { liveTrust } from './live-trust.js';
import { holderBinding, instancesOf, MemoryCredentialStore, pickInstance, SoftwareKeyStore, Wallet } from '../src/index.js';
import { demoAttester } from './wallet-provider.js';

const PLAYGROUND = 'https://playground.animo.id';
const log = (s: string) => process.stderr.write(`${s}\n`);

async function offer(id: string, keyAttestation = false) {
  const r = await fetch(`${PLAYGROUND}/api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
    credentialSupportedIds: [id], authorization: 'none', deferBy: 'none', requireDpop: true, requireWalletAttestation: keyAttestation,
    requireKeyAttestation: keyAttestation }) });
  return ((await r.json()) as { credentialOffer: string }).credentialOffer;
}

const trust = await liveTrust();
const walletWith = (extra = {}) => new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(),
  redirectUri: 'https://wallet.vctrust.dev/cb', batchSize: 3, ...extra });

describe('Animo batch issuance', () => {
  for (const [config, keyAttestation] of [['mdl-mdoc-utopia', false], ['eudi-pid-sd-jwt-utopia', false], ['mdl-mdoc-utopia', true]] as const) {
    it(`issues three instances of ${config}${keyAttestation ? ' with one key attestation for all keys' : ''}`, async () => {
      const wallet = walletWith(keyAttestation ? { attester: demoAttester(undefined, true), keyAttestation: 'always', walletAttestation: 'always' } : {});
      const [cred] = await (await wallet.receive(await offer(config, keyAttestation))).acceptPreAuthorized();
      const all = instancesOf(cred!);
      log(`${config}: ${all.length} instance(s) ${all.map((x) => `${x.report?.valid}/${x.report?.trust?.decision}`).join(' ')}`);
      expect(all).toHaveLength(3);
      for (const x of all) {
        expect(x.report?.trusted).toBe(true);
        expect(holderBinding(cred!.format, x.credential).jwk?.x).toBe(x.holderJwk.x);
      }
      expect(new Set(all.map((x) => x.holderJwk.x)).size).toBe(3);
    }, 90_000);
  }

  it('presents a different mDL instance to each of two verifier sessions', async () => {
    const wallet = walletWith();
    const [stored] = await wallet.store(await (await wallet.receive(await offer('mdl-mdoc-utopia'))).acceptPreAuthorized());
    for (let n = 0; n < 2; n++) {
      const req = await (await fetch(`${PLAYGROUND}/api/requests/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request: { credentials: [{ id: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name'] }], combination: 'all' },
          requestScheme: 'openid4vp://', responseMode: 'direct_post.jwt', requestSignerType: 'x5c', transactionAuthorizationType: 'none' }) })).json() as
        { authorizationRequestUri: string; verificationSessionId: string };
      const p = await wallet.startPresentation(req.authorizationRequestUri);
      const res = await p.respond();
      expect(res.status).toBe(200);
      let status = '';
      for (let i = 0; i < 10 && status !== 'ResponseVerified' && status !== 'Error'; i++) {
        status = String(((await (await fetch(`${PLAYGROUND}/api/requests/${req.verificationSessionId}`)).json()) as Record<string, unknown>).responseStatus);
        if (status !== 'ResponseVerified' && status !== 'Error') await new Promise((r) => setTimeout(r, 1000));
      }
      log(`presentation ${n + 1}: ${status}`);
      expect(status).toBe('ResponseVerified');
    }
    const after = (await wallet.list()).find((c) => c.id === stored!.id)!;
    expect(instancesOf(after).map((x) => x.presentations ?? 0)).toEqual([1, 1, 0]);
    expect(pickInstance(after)).toMatchObject({ index: 2, fresh: true });
  }, 120_000);
});
