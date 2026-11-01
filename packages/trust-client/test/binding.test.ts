/**
 * Entity matching is bound to the presented key: a claimed identifier (client_id, iss, issuer DID) never makes a
 * self-signed certificate or a foreign DID key TRUSTED. Mirrored by the Java TrustEvaluatorTest and the live parity test.
 */
import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { LocalEvaluator, type LocalTrustData } from '../src/evaluation/local.js';
import { parseCertificate } from '../src/x509/certificate.js';
import { resolveDidJwk } from '../src/did/resolver.js';

const PKI = new URL('./fixtures/pki/', import.meta.url);
const pem = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8');
const b64 = (n: string) => pem(n).replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const entity = (id: string, roles: string[], identifiers: Array<{ type: string; value: string }>, extra: Record<string, unknown> = {}) =>
  ({ id, frameworkId: 'fw', roles, status: 'ACTIVE', display: [{ locale: 'en', name: id }], identifiers, authorizations: [], ...extra }) as never;
const data = (entities: unknown[], anchorExtra: Record<string, unknown> = {}): LocalTrustData => ({
  entities: entities as never[], frameworks: [], source: 'snapshot', mode: 'local',
  anchors: [
    { certificate: parseCertificate(pem('rp-ca')), domain: 'verifier-access', frameworkId: 'fw', status: 'ACTIVE' },
    { certificate: parseCertificate(pem('rp-ca')), domain: 'credential-issuer', frameworkId: 'fw', status: 'ACTIVE' },
    { certificate: parseCertificate(pem('iaca')), domain: 'mdoc-iaca', frameworkId: 'fw', status: 'ACTIVE', ...anchorExtra },
  ] as never[],
  policy: { strictAuthorization: false, requireRevocationStatus: false, allowRelaxedProfiles: false },
});
const ev = new LocalEvaluator(async (d) => resolveDidJwk(d.split('#')[0]!));
const codes = (d: { reasons: Array<{ code: string }> }) => d.reasons.map((r) => r.code);
const bank = entity('bank-verifier', ['VERIFIER'], [{ type: 'DNS', value: 'verifier.example' }]);
const gov = entity('gov-issuer', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://verifier.example' }]);

describe('identifiers are bound to the presented key', () => {
  it('refuses an x509_san_dns verifier whose self-signed certificate claims a registered DNS name', async () => {
    const d = await ev.evaluate({ role: 'verifier', subject: { identifier: 'x509_san_dns:verifier.example', x5c: [b64('selfsigned-verifier')] },
      context: { protocol: 'oid4vp', responseUri: 'https://verifier.example/cb' } }, data([bank]));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(codes(d)).toContain('identifier.unbound');
    expect(d.entity).toBeNull();
  });

  it('trusts the same verifier when its certificate chains to the anchor', async () => {
    const d = await ev.evaluate({ role: 'verifier', subject: { identifier: 'x509_san_dns:verifier.example', x5c: [b64('rp')] },
      context: { protocol: 'oid4vp', responseUri: 'https://verifier.example/cb' } }, data([bank]));
    expect(d.decision).toBe('TRUSTED');
    expect(d.entity?.id).toBe('bank-verifier');
  });

  it('refuses an issuer whose iss names a registered issuer but whose x5c is self-signed', async () => {
    const d = await ev.evaluate({ role: 'issuer', subject: { identifier: 'https://verifier.example', x5c: [b64('selfsigned-issuer')] },
      context: { credentialFormat: 'dc+sd-jwt', credentialType: 'urn:eudi:pid:1' } }, data([gov]));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(codes(d)).toContain('identifier.unbound');
  });

  it('matches certificate subjects only in a validated chain, and pinned certificates only as the leaf', async () => {
    const leaf = parseCertificate(pem('selfsigned-verifier'));
    const bySubject = await ev.evaluate({ role: 'issuer', subject: { x5c: [b64('selfsigned-verifier')] }, context: { credentialFormat: 'dc+sd-jwt' } },
      data([entity('tl', ['CREDENTIAL_ISSUER'], [{ type: 'X509_SUBJECT', value: leaf.subject }])]));
    expect(bySubject.decision).toBe('UNKNOWN');
    const victim = parseCertificate(pem('rsa-leaf'));
    const appended = await ev.evaluate({ role: 'issuer', subject: { x5c: [b64('selfsigned-issuer'), b64('rsa-leaf')] }, context: { credentialFormat: 'dc+sd-jwt' } },
      data([entity('pinned', ['CREDENTIAL_ISSUER'], [], { certificates: [{ sha256: victim.sha256 }] })]));
    expect(appended.decision).not.toBe('TRUSTED');
    const pinned = await ev.evaluate({ role: 'issuer', subject: { x5c: [b64('selfsigned-issuer')] }, context: { credentialFormat: 'dc+sd-jwt' } },
      data([entity('pinned', ['CREDENTIAL_ISSUER'], [], { certificates: [{ sha256: parseCertificate(pem('selfsigned-issuer')).sha256 }] })]));
    expect(pinned.decision).toBe('TRUSTED');
  });

  it('refuses a DID identifier signed with a key of another DID, unless the entity lists both DIDs', async () => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const other = `did:jwk:${Buffer.from(JSON.stringify(jwk)).toString('base64url')}`;
    const land = (ids: string[]) => entity('land', ['CREDENTIAL_ISSUER'], ids.map((value) => ({ type: 'DID', value })));
    const q = { role: 'issuer' as const, subject: { identifier: 'did:web:land.example', kid: `${other}#0` }, context: { credentialFormat: 'ldp_vc' } };
    const foreign = await ev.evaluate(q, data([land(['did:web:land.example'])]));
    expect(foreign.decision).toBe('NOT_TRUSTED');
    expect(codes(foreign)).toContain('identifier.unbound');
    expect((await ev.evaluate(q, data([land(['did:web:land.example', other])]))).decision).toBe('TRUSTED');
  });

  it('looks the identifier up when no key is presented (issuer metadata, keys fetched from the identifier)', async () => {
    const d = await ev.evaluate({ role: 'issuer', subject: { identifier: 'https://verifier.example' } }, data([gov]));
    expect(d.decision).toBe('TRUSTED');
  });

  it('lets an anchor that is not tied to one entity vouch for identifiers in its own framework only', async () => {
    const q = { role: 'issuer' as const, subject: { identifier: 'https://issuer.example', x5c: [b64('ds')] },
      context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } };
    const member = entity('member', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://issuer.example' }]);
    expect((await ev.evaluate(q, data([member]))).entity?.id).toBe('member');
    const outsider = await ev.evaluate(q, data([{ ...(member as object), frameworkId: 'other' }]));
    expect(outsider.decision).toBe('NOT_TRUSTED');
    expect(codes(outsider)).toContain('identifier.unbound');
    const bound = await ev.evaluate(q, data([member, entity('iaca-owner', ['CREDENTIAL_ISSUER'], [])], { entityId: 'iaca-owner' }));
    expect(bound.decision).toBe('NOT_TRUSTED');
  });
});
