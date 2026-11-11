/**
 * Live: walt.id's public demo issuer (https://issuer2.demo.walt.id), OpenID4VCI 1.0 with the pre-authorized code grant.
 * It issues an ISO mDL, an EUDI PID as mdoc and an EUDI PID as SD-JWT VC; the PID provider certificate is issued by
 * the EUDI reference implementation's pre-production "PID Issuer CA 02".
 *
 * The issuer is registered with the running trust service for the duration of the test (framework 'local', through
 * the admin API), so the wallet learns everything about it the way it would in production: issuer metadata through
 * the proxy, trust from the signed snapshot, the CA's CRL through the proxy.
 */
import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TrustClient } from '@vctrust/trust-client';
import { MemoryCredentialStore, SoftwareKeyStore, Wallet } from '../src/index.js';
import { liveTrust, managed } from './live-trust.js';

const HOST = 'https://issuer2.demo.walt.id';
const ISSUER = `${HOST}/openid4vci`;
const pem = (name: string) => readFileSync(new URL(`./fixtures/live/${name}.pem`, import.meta.url), 'utf8');
const log = (s: string) => process.stderr.write(`${s}\n`);

async function offer(profileId: string): Promise<string> {
  const r = await fetch(`${HOST}/issuer2/credential-offers`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ profileId, authMethod: 'PRE_AUTHORIZED' }) });
  if (!r.ok) throw new Error(`walt.id offer for ${profileId}: HTTP ${r.status}`);
  return ((await r.json()) as { credentialOffer: string }).credentialOffer;
}

let trust: TrustClient;
let wallet: Wallet;

beforeAll(async () => {
  // The issuer is known by its URL and by its two signing certificates: the mDL Document Signer (its IACA is not
  // published) and the PID provider certificate. The PID CA below issues to many providers, so it vouches for the
  // certificate's validity, while the registry says whose certificate it is: a PID that names this issuer in iss
  // under any other certificate of that CA is refused.
  await managed('PUT', 'entities', 'live-waltid', { roles: ['CREDENTIAL_ISSUER'], name: 'walt.id demo issuer (sandbox)', identifiers: [{ type: 'URL', value: ISSUER }],
    certificates: [pem('waltid-mdl-document-signer'), pem('waltid-pid-provider')] });
  for (const domain of ['credential-issuer', 'mdoc-iaca']) {
    await managed('PUT', 'anchors', `live-eudi-pid-ca-${domain}`, { domain, certificate: pem('eudi-pid-issuer-ca-02') });
  }
  trust = await liveTrust();
  await trust.sync();
  wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.vctrust.dev/cb' });
}, 60_000);

afterAll(async () => {
  await managed('DELETE', 'entities', 'live-waltid');
  for (const domain of ['credential-issuer', 'mdoc-iaca']) await managed('DELETE', 'anchors', `live-eudi-pid-ca-${domain}`);
});

describe('walt.id demo issuer through the trust proxy', () => {
  for (const [profile, format, type] of [
    ['isoMdl', 'mso_mdoc', 'org.iso.18013.5.1.mDL'],
    ['eudiPidMdoc', 'mso_mdoc', 'eu.europa.ec.eudi.pid.1'],
    ['eudiPidSdJwt', 'dc+sd-jwt', 'urn:eudi:pid:1'],
  ] as const) {
    it(`issues and verifies ${profile} (${format})`, async () => {
      const session = await wallet.receive(await offer(profile));
      // Through the proxy the first time, then from the client's own cache.
      expect(session.metadata.source).toBe(profile === 'isoMdl' ? 'proxy' : 'cache');
      expect(session.issuerTrust).toMatchObject({ decision: 'TRUSTED', source: 'snapshot', entity: { id: 'live-waltid' } });
      const [c] = await session.acceptPreAuthorized();
      log(`\n== walt.id ${profile}: valid=${c!.report?.valid} trusted=${c!.report?.trusted}`);
      for (const x of c!.report!.checks) log(`  [${x.status}] ${x.label}: ${x.detail ?? ''}`.slice(0, 220));
      expect(c!.report).toMatchObject({ format, credentialType: type, valid: true, trusted: true });
      if (profile !== 'isoMdl') {
        // The PID provider certificate is checked against the CRL of the EUDI PID CA: carried in the snapshot (the
        // service fetches its anchors' CRLs), or fetched through the proxy.
        const [revocation] = c!.report!.trust!.evidence!.x509!.revocation!;
        log(`  revocation: ${JSON.stringify(revocation)}`.slice(0, 260));
        expect(revocation).toMatchObject({ status: 'GOOD' });
        expect(['snapshot', 'proxy', 'cache']).toContain(revocation!.source);
      }
    }, 90_000);
  }
});
