/**
 * A CRL is its issuer's: the device matches a CRL to a certificate by the issuer's name and signature, whichever of the
 * issuer's certificates the chain validated to. The fixture of ReissuedCaCrlsTest.java (conformance/pki/generate-reissued.sh):
 * a CA with two certificates of the same name and key, one listed by framework `other` (its distribution point serves
 * the current CRL, which revokes the signer), the other by framework `partner` (crlUrls naming an earlier CRL that
 * revokes nothing). Each client's snapshot carries the CRLs of its frameworks, as the service signs it; the device
 * reaches what the service decides for that client, in either order of the anchors.
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { createTrustClient, MemoryCacheStore, type TrustQuery } from '../src/index.js';
import { jwkThumbprint } from '../src/primitives.js';
import { b64, down, es256Key, fakeFetch, fixture, json, pem, signJwt } from './helpers.js';

const BASE = 'https://trust.example';
const CURRENT = 'http://crl.registry.example/current.crl';
const LAST_WEEK = 'http://crl.registry.example/last-week.crl';
const serviceKey = es256Key();
const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };

const thumbprint = (name: string) => createHash('sha256').update(Buffer.from(b64(pem(name)), 'base64')).digest('base64url');
const official = { id: 'official-iaca', domain: 'mdoc-iaca', frameworkId: 'other', status: 'ACTIVE', constraints: {}, certificate: b64(pem('reissued-ca')) };
const partner = { id: 'partner-iaca', domain: 'mdoc-iaca', frameworkId: 'partner', status: 'ACTIVE', constraints: { crlUrls: [LAST_WEEK] },
  certificate: b64(pem('reissued-ca-2')) };
/** The snapshot claim `crls` as the service writes it: the anchor certificate the CRL was configured for, its location. */
const currentCrl = { issuer: thumbprint('reissued-ca'), url: CURRENT, crl: fixture('pki/reissued-ca.crl').toString('base64') };
const lastWeekCrl = { issuer: thumbprint('reissued-ca-2'), url: LAST_WEEK, crl: fixture('pki/reissued-ca-old.crl').toString('base64') };

const signer: TrustQuery = { role: 'issuer', subject: { x5c: [b64(pem('reissued-ds'))] },
  context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } };

async function decide(frameworks: string[], anchors: unknown[], crls: unknown[]) {
  const iat = Math.floor(Date.now() / 1000);
  const jwt = signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: 'svc-1' }, { iss: BASE, aud: 'wallet-1', iat, exp: iat + 3600, format: 4,
    policy: { frameworks, strictAuthorization: false, requireRevocationStatus: false, requireSignedIssuerMetadata: false },
    frameworks: frameworks.map((id) => ({ id, name: id })), entities: [], anchors, crls }, serviceKey.privateKey);
  const { fetch } = fakeFetch({
    [`${BASE}/api/v1/snapshot`]: () => new Response(jwt, { headers: { 'Content-Type': 'application/jwt' } }),
    [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
  }, down);
  const client = createTrustClient({ service: { url: BASE, clientId: 'wallet-1', keys: { thumbprints: [jwkThumbprint(serviceJwk)] } },
    storage: new MemoryCacheStore(), lookups: { crl: 'none' }, http: { fetch, retries: 0, timeoutMs: 500 } });
  const d = await client.evaluate(signer);
  expect(d.source).toBe('snapshot');
  return { decision: d.decision, revocation: d.evidence?.x509?.revocation?.map((r) => [r.status, r.crlUrl]) };
}

describe('a CRL of a CA with two certificates', () => {
  it('counts for a client that sees both frameworks, whichever certificate the chain validates to: REVOKED', async () => {
    for (const anchors of [[partner, official], [official, partner]]) {
      expect(await decide(['other', 'partner'], anchors, [currentCrl, lastWeekCrl])).toEqual({ decision: 'NOT_TRUSTED', revocation: [['REVOKED', CURRENT]] });
      expect(await decide(['other', 'partner'], anchors, [lastWeekCrl, currentCrl])).toEqual({ decision: 'NOT_TRUSTED', revocation: [['REVOKED', CURRENT]] });
    }
  });

  it("decides a client of one framework by that framework's CRL", async () => {
    expect(await decide(['other'], [official], [currentCrl])).toEqual({ decision: 'NOT_TRUSTED', revocation: [['REVOKED', CURRENT]] });
    expect(await decide(['partner'], [partner], [lastWeekCrl])).toEqual({ decision: 'TRUSTED', revocation: [['GOOD', LAST_WEEK]] });
  });
});
