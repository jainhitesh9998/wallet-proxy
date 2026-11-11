/**
 * Credentials that public sandbox issuers actually issued (conformance/real-world), verified offline as of the day
 * they were obtained. The ones that follow the specifications verify and are trusted under their issuers' real
 * certificates; for the others the test states what the wallet refuses them for.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createTrustClient, MemoryCacheStore, type Jwk, type TrustClient, type TrustClientConfig } from '@vctrust/trust-client';
import { parseCertificate } from '@vctrust/trust-client/primitives';
import { verifyCredential, type VerificationReport } from '../src/index.js';
import { entity, fakeFetch, json } from './support.js';

const DIR = new URL('../../../conformance/real-world/', import.meta.url);
const LIVE = new URL('./fixtures/live/', import.meta.url);
const read = (name: string) => readFileSync(new URL(name, DIR), 'utf8');
const sample = (name: string) => JSON.parse(read(`${name}.json`)) as { format: string; type: string; obtained: string; holderJwk: Jwk; credential: unknown };
const pem = (name: string) => readFileSync(new URL(`${name}.pem`, LIVE), 'utf8');
const failures = (r: VerificationReport) => r.checks.filter((c) => c.status === 'fail').map((c) => `${c.id}: ${c.detail}`);

/** A trust client as of a given day, with nothing but what is passed in: no service, no network beyond {@code routes}. */
function trustAsOf(day: string, pinned: TrustClientConfig['pinned'] = {}, routes: Parameters<typeof fakeFetch>[0] = {}): TrustClient {
  return createTrustClient({ pinned, clock: () => new Date(day), lookups: { crl: 'none' }, storage: new MemoryCacheStore(), http: { fetch: fakeFetch(routes), retries: 0 } });
}

describe('walt.id demo issuer (2026-11-11): conforming credentials under real certificates', () => {
  // As registered in waltid.live.test.ts: the issuer's two signing certificates, and the EUDI pre-production PID CA.
  const trust = trustAsOf('2026-11-12T00:00:00Z', {
    anchors: ['credential-issuer', 'mdoc-iaca'].map((domain) => ({ domain, certificate: pem('eudi-pid-issuer-ca-02') })),
    entities: [entity('waltid', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://issuer2.demo.walt.id/openid4vci' }],
      { certificates: [pem('waltid-mdl-document-signer'), pem('waltid-pid-provider')].map((p) => ({ sha256: parseCertificate(p).sha256 })) as never })],
  });
  for (const name of ['waltid-mdl', 'waltid-pid-mdoc', 'waltid-pid-sdjwt']) {
    it(`${name} verifies and is trusted`, async () => {
      const s = sample(name);
      const expected = s.format === 'mso_mdoc' ? { doctype: s.type } : { vct: s.type };
      const r = await verifyCredential(s.format, s.credential, { trust, holderJwk: s.holderJwk, expected, now: new Date('2026-11-12T00:00:00Z') });
      expect(failures(r)).toEqual([]);
      expect(r).toMatchObject({ valid: true, trusted: true, credentialType: s.type, trust: { entity: { id: 'waltid' } } });
    });
  }

  it('the same credentials are worth nothing to a wallet that trusts nobody', async () => {
    const s = sample('waltid-pid-sdjwt');
    const r = await verifyCredential(s.format, s.credential, { trust: trustAsOf('2026-11-12T00:00:00Z'), holderJwk: s.holderJwk, now: new Date('2026-11-12T00:00:00Z') });
    expect(r).toMatchObject({ valid: true, trusted: false, trust: { decision: 'UNKNOWN' } });
  });
});

describe('credentials the wallet refuses, and why', () => {
  const now = new Date('2026-11-12T00:00:00Z');
  const nobody = trustAsOf(now.toISOString());

  it('Talao sandbox, W3C credential: its @context contains an inline context', async () => {
    const s = sample('talao-emailpass-ldp');
    const r = await verifyCredential('ldp_vc', s.credential, { trust: nobody, now });
    expect(failures(r)).toEqual(['ldp.model: @context contains an inline context; this wallet processes contexts given by URL only']);
    expect(r.checks.find((c) => c.id === 'ldp.signature')?.status).toBe('skip');
  });

  it('Talao sandbox, SD-JWT VC: signed with a key named by kid, without an X.509 chain', async () => {
    const s = sample('talao-pid-sdjwt');
    const r = await verifyCredential('dc+sd-jwt', s.credential, { trust: nobody, holderJwk: s.holderJwk, now });
    expect(failures(r)).toEqual([expect.stringMatching(/^sdjwt\.structure: No x5c header/)]);
  });

  it('University of the Aegean issuer, SD-JWT VC: typ vc+sd-jwt and no X.509 chain', async () => {
    const s = sample('aegean-pid-sdjwt');
    const r = await verifyCredential('dc+sd-jwt', s.credential, { trust: nobody, holderJwk: s.holderJwk, now });
    expect(failures(r)).toEqual(['sdjwt.typ: typ is vc+sd-jwt; dc+sd-jwt is required', expect.stringMatching(/^sdjwt\.structure: No x5c header/)]);
  });

  it('MOSIP Inji Certify (collab), W3C credential: signed with a key published under another DID than the issuer\'s, whose assertionMethod lists the DID instead of the key', async () => {
    const vc = (JSON.parse(read('mosip-land-statement-ldp.json')) as { credentials: Array<{ credential: Record<string, unknown> }> }).credentials[0]!.credential;
    const asOf = String(vc.validFrom);
    const trust = trustAsOf(asOf, {}, {
      'https://injicertify-landregistry.collab.mosip.net/.well-known/did.json': () => json(JSON.parse(read('mosip-land-issuer-did.json'))),
      'https://inji.github.io/inji-config/collab/landregistry/did.json': () => json(JSON.parse(read('mosip-land-key-did.json'))),
    });
    const r = await verifyCredential('ldp_vc', vc, { trust, now: new Date(asOf) });
    expect(failures(r)).toEqual([
      'ldp.signature: The verification method belongs to did:web:inji.github.io:inji-config:collab:landregistry, not to the issuer did:web:injicertify-landregistry.collab.mosip.net',
      expect.stringMatching(/^issuer\.trust: NOT_TRUSTED .* is not authorized for assertionMethod$/),
    ]);
  });

  it('MOSIP Inji Certify (collab), mDL: a {docType, issuerSigned} wrapper where OpenID4VCI issues the IssuerSigned itself', async () => {
    const credential = (JSON.parse(read('mosip-mock-mdl.json')) as { credentials: Array<{ credential: string }> }).credentials[0]!.credential;
    const r = await verifyCredential('mso_mdoc', credential, { trust: nobody, now });
    expect(failures(r)).toEqual(['mdoc.structure: The credential is not an IssuerSigned structure (OpenID4VCI 1.0 A.2.4)']);
  });
});
