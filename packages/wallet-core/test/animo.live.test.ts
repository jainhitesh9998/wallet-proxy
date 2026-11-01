/** Live OpenID4VCI 1.0 / HAIP issuance against the Animo playground, verified end to end through the trust service. */
import { describe, expect, it } from 'vitest';
import { createTrustClient } from '@vctrust/trust-client';
import { Oid4vciClient, SoftwareKeyStore } from '../src/index.js';
import { demoAttester } from './wallet-provider.js';

const PLAYGROUND = 'https://playground.animo.id';
const TRUST = process.env.TRUST_URL ?? 'http://localhost:8090';

async function offer(id: string, opts: { authorization?: string; dpop?: boolean; walletAttestation?: boolean; keyAttestation?: boolean } = {}) {
  const r = await fetch(`${PLAYGROUND}/api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
    credentialSupportedIds: [id], authorization: opts.authorization ?? 'none', deferBy: 'none', requireDpop: opts.dpop ?? false,
    requireWalletAttestation: opts.walletAttestation ?? false, requireKeyAttestation: opts.keyAttestation ?? false }) });
  const j = (await r.json()) as { credentialOffer: string; issuanceSession: { userPin?: string; txCode?: string } };
  return j;
}

const log = (s: string) => process.stderr.write(`${s}\n`);

describe('Animo playground (mDL mdoc)', () => {
  const trust = createTrustClient({ baseUrl: TRUST, apiKey: 'demo-wallet-key', clientId: 'demo-wallet' });
  const wallet = (extra = {}) => new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: 'https://wallet.vctrust.dev/cb', ...extra });

  for (const [name, flags] of [
    ['plain pre-authorized', {}],
    ['DPoP', { dpop: true }],
    ['DPoP + wallet attestation + key attestation', { dpop: true, walletAttestation: true, keyAttestation: true }],
  ] as const) {
    it(`issues and verifies an mDL (${name})`, async () => {
      const o = await offer('mdl-mdoc-utopia', flags);
      const session = await wallet({ attester: demoAttester(undefined, flags.keyAttestation === true), keyAttestation: flags.keyAttestation ? 'always' : 'auto',
        walletAttestation: flags.walletAttestation ? 'always' : 'auto' }).startFromOffer(o.credentialOffer);
      expect(session.issuerTrust.decision).toBe('TRUSTED');
      const [cred] = await session.acceptPreAuthorized();
      log(`\n== ${name}: format=${cred!.format} valid=${cred!.report?.valid} trusted=${cred!.report?.trusted}`);
      for (const c of cred!.report!.checks) log(`  [${c.status}] ${c.label}: ${c.detail ?? ''}`.slice(0, 200));
      expect(cred!.report!.valid).toBe(true);
      expect(cred!.report!.trusted).toBe(true);
    }, 60_000);
  }

  it('refuses when the issuer requires stronger key protection than the wallet attests', async () => {
    const o = await offer('mdl-mdoc-utopia', { keyAttestation: true });
    const session = await wallet({ attester: demoAttester(undefined, false) }).startFromOffer(o.credentialOffer);
    await expect(session.acceptPreAuthorized()).rejects.toThrow(/insufficient|requires key storage/i);
  }, 60_000);

  it('handles a transaction code (PIN)', async () => {
    const o = await offer('mdl-mdoc-utopia', { authorization: 'pin' });
    const session = await wallet().startFromOffer(o.credentialOffer);
    log(`tx_code: ${JSON.stringify(session.txCode)} session keys: ${Object.keys(o.issuanceSession).join(',')}`);
    expect(session.txCode).toBeDefined();
    const pin = (o.issuanceSession as Record<string, unknown>).userPin ?? (o.issuanceSession as Record<string, unknown>).txCode;
    const [cred] = await session.acceptPreAuthorized(String(pin));
    expect(cred!.report!.trusted).toBe(true);
  }, 60_000);
});
