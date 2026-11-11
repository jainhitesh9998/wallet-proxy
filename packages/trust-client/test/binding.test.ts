/**
 * Entity matching is bound to the presented key: a claimed identifier (client_id, iss, issuer DID) never makes a
 * self-signed certificate or a foreign DID key TRUSTED. Mirrored by the Java TrustEvaluatorTest and the live parity test.
 */
import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { LocalEvaluator, httpsHost, identifierKey, type LocalTrustData } from '../src/evaluation/local.js';
import { parseCertificate } from '../src/x509/certificate.js';
import { resolveDidJwk } from '../src/did/resolver.js';

const PKI = new URL('../../../conformance/pki/', import.meta.url);
const pem = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8');
const b64 = (n: string) => pem(n).replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const entity = (id: string, roles: string[], identifiers: Array<{ type: string; value: string }>, extra: Record<string, unknown> = {}) =>
  ({ id, frameworkId: 'fw', roles, status: 'ACTIVE', display: [{ locale: 'en', name: id }], identifiers, authorizations: [], ...extra }) as never;
const data = (entities: unknown[], anchorExtra: Record<string, unknown> = {}): LocalTrustData => ({
  entities: entities as never[], frameworks: [], source: 'snapshot',
  anchors: [
    { certificate: parseCertificate(pem('rp-ca')), domain: 'verifier-access', frameworkId: 'fw', status: 'ACTIVE' },
    { certificate: parseCertificate(pem('rp-ca')), domain: 'credential-issuer', frameworkId: 'fw', status: 'ACTIVE' },
    { certificate: parseCertificate(pem('iaca')), domain: 'mdoc-iaca', frameworkId: 'fw', status: 'ACTIVE', ...anchorExtra },
  ] as never[],
  policy: { strictAuthorization: false, requireRevocationStatus: false },
});
const OTHER_DID = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9';
const EBSI_DID = 'did:ebsi:zParityIssuer4LkPq';
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

  it('a shared anchor does not lend its framework\'s identities: an entity is found only through what the key proves', async () => {
    const q = { role: 'issuer' as const, subject: { identifier: 'https://issuer.example', x5c: [b64('ds')] },
      context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } };
    const member = entity('member', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://issuer.example' }]);
    // Any certificate under the shared anchor could claim the member's identifier.
    const claimed = await ev.evaluate(q, data([member]));
    expect([claimed.decision, claimed.entity]).toEqual(['NOT_TRUSTED', null]);
    expect(codes(claimed)).toContain('identifier.unbound');
    // Without the claim the chain is what it is: issued under a trusted anchor, by no named party.
    const anonymous = await ev.evaluate({ ...q, subject: { x5c: [b64('ds')] } }, data([member]));
    expect([anonymous.decision, anonymous.entity]).toEqual(['TRUSTED', null]);
    // The anchor registered as the member's own makes the key the member's.
    const owned = await ev.evaluate(q, data([member], { entityId: 'member' }));
    expect([owned.decision, owned.entity?.id]).toEqual(['TRUSTED', 'member']);
    const bound = await ev.evaluate(q, data([member, entity('iaca-owner', ['CREDENTIAL_ISSUER'], [])], { entityId: 'iaca-owner' }));
    expect(bound.decision).toBe('NOT_TRUSTED');
  });

  it('a pinned certificate with no anchor behind it stands only while it is valid', async () => {
    const pinned = entity('pinned', ['CREDENTIAL_ISSUER'], [], { certificates: [{ sha256: parseCertificate(pem('selfsigned-issuer')).sha256 }] });
    const q = (time?: string) => ({ role: 'issuer' as const, subject: { x5c: [b64('selfsigned-issuer')] }, context: { credentialFormat: 'dc+sd-jwt', time } });
    expect((await ev.evaluate(q(), data([pinned]))).decision).toBe('TRUSTED');
    const later = await ev.evaluate(q('2099-01-01T00:00:00Z'), data([pinned]));
    expect(later.decision).toBe('NOT_TRUSTED');
    expect(codes(later)).toContain('x509.pinned_expired');
  });

  it('refuses a query that presents both a certificate chain and a DID key (the caller verified only one)', async () => {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const d = await ev.evaluate({ role: 'verifier', subject: { identifier: 'x509_san_dns:verifier.example', x5c: [b64('rp')],
      kid: `did:jwk:${Buffer.from(JSON.stringify(jwk)).toString('base64url')}#0` }, context: { protocol: 'oid4vp' } }, data([bank]));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(codes(d)).toContain('key.ambiguous');
  });

  it('never lets a framework-wide anchor turn a key bound to one entity into another entity', async () => {
    const suspended = entity('b', ['CREDENTIAL_ISSUER'], [{ type: 'DNS', value: 'verifier.example' }], { status: 'SUSPENDED' });
    const active = entity('a', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://a.example' }]);
    const d = await ev.evaluate({ role: 'issuer', subject: { identifier: 'https://a.example', x5c: [b64('rp')] }, context: { credentialFormat: 'dc+sd-jwt' } },
      data([suspended, active]));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.entity?.id).not.toBe('a');
  });

  it('accepts an identifier listed on two entities when the key is bound to one of them', async () => {
    const q = { role: 'issuer' as const, subject: { identifier: 'https://issuer.example', x5c: [b64('ds')] },
      context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } };
    const here = entity('here', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://issuer.example' }]);
    const elsewhere = { ...(entity('elsewhere', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://issuer.example' }]) as object), frameworkId: 'other' };
    const d = await ev.evaluate(q, data([elsewhere, here], { entityId: 'here' }));
    expect(d.decision).toBe('TRUSTED');
    expect(d.entity?.id).toBe('here');
  });

  it('compares the response_uri host only for a plain https URL, and refuses any other (mirrors TrustEvaluatorTest)', async () => {
    const verify = (responseUri: string) => ev.evaluate({ role: 'verifier', subject: { identifier: 'x509_san_dns:verifier.example', x5c: [b64('rp')] },
      context: { protocol: 'oid4vp', responseUri } }, data([]));
    expect((await verify('https://verifier.example/cb')).decision).toBe('TRUSTED');
    expect((await verify('https://verifier.example:8443/cb?x=1')).decision).toBe('TRUSTED');
    for (const uri of ['https://collector_1.example/cb', 'https://Verifier.example/cb', 'https://verifier.example@evil.example/cb',
      'https://verifier.example\\@evil.example/cb', 'http://verifier.example/cb', 'https://evil.example/cb', 'https://verifier.example.evil.example/cb']) {
      const d = await verify(uri);
      expect(d.decision, uri).toBe('NOT_TRUSTED');
      expect(d.reasons.filter((r) => r.severity === 'ERROR').map((r) => r.code), uri).toEqual(['client_id.response_uri_host']);
    }
  });

  it('matches a URL identifier only as it is written', async () => {
    expect((await ev.evaluate({ role: 'issuer', subject: { identifier: 'https://verifier.example' } }, data([gov]))).entity?.id).toBe('gov-issuer');
    for (const other of ['HTTPS://Verifier.Example:443/', 'https://verifier.example/', 'https://verifier.example:443', 'https://verifier.example?']) {
      const d = await ev.evaluate({ role: 'issuer', subject: { identifier: other } }, data([gov]));
      expect([d.decision, d.entity], other).toEqual(['UNKNOWN', null]);
    }
  });

  it('treats an empty JWK as no key, as the service does', async () => {
    const d = await ev.evaluate({ role: 'issuer', subject: { identifier: 'https://verifier.example', jwk: {} as never } }, data([gov]));
    expect(d.decision).toBe('TRUSTED');
  });
});

describe('identifier comparison (mirrors the Java IdentifierTest)', () => {
  it('compares URLs byte for byte, DNS names without case, DIDs without a fragment', () => {
    expect(identifierKey('URL', 'https://Issuer.example/a/')).toBe('https://Issuer.example/a/');
    expect(identifierKey('FEDERATION_ENTITY', 'https://fed.example:443')).toBe('https://fed.example:443');
    expect(identifierKey('DNS', 'Verifier.Example')).toBe('verifier.example');
    expect(identifierKey('DID', 'did:web:issuer.example#key-1')).toBe('did:web:issuer.example');
    expect(identifierKey('CLIENT_ID', 'My-Client')).toBe('My-Client');
  });

  it('reads a host only from a plain https URL', () => {
    expect(httpsHost('https://verifier.example/cb')).toBe('verifier.example');
    expect(httpsHost('https://verifier.example')).toBe('verifier.example');
    expect(httpsHost('https://verifier.example:8443/cb')).toBe('verifier.example');
    expect(httpsHost('https://verifier.example?x#y')).toBe('verifier.example');
    expect(httpsHost('https://10.0.2.2:8443/cb')).toBe('10.0.2.2');
    for (const no of ['http://verifier.example/cb', 'HTTPS://verifier.example/cb', 'https://Verifier.example/cb', 'https://user@verifier.example/cb',
      'https://verifier.example@evil.example', 'https://verifier_1.example', 'https://verifier.example:port/', 'https://xn--bcher-kva.example./', 'https:///cb',
      'https://verifier.example\\evil', 'https://[::1]/cb', ' https://verifier.example', 'https://-verifier.example']) {
      expect(httpsHost(no), no).toBeUndefined();
    }
  });
});

describe('on-demand registries are asked where the service asks them', () => {
  // Mirrors TrustEvaluatorTest's on-demand cases: a registry too large for the snapshot (OpenID Federation, EBSI).
  const registry = [
    entity('fed-issuer', ['CREDENTIAL_ISSUER'], [{ type: 'URL', value: 'https://fed.example/issuer' }]),
    entity('fed-verifier', ['VERIFIER'], [{ type: 'URL', value: 'https://fed.example' }]),
    entity('fed-rp', ['VERIFIER'], [{ type: 'URL', value: 'https://fed.example/rp' }], { status: 'REVOKED' }),
    entity('ebsi-issuer', ['CREDENTIAL_ISSUER'], [{ type: 'DID', value: EBSI_DID }]),
  ];
  const run = async (q: Parameters<LocalEvaluator['evaluate']>[0], snapshot: unknown[] = [gov]) => {
    const asked: string[] = [];
    const d = await ev.evaluate(q, { ...data(snapshot), onDemand: async (ids) => {
      for (const id of ids) {
        asked.push(`${id.type}:${identifierKey(id.type, id.value)}`);
        const e = registry.find((x) => (x as { identifiers: Array<{ type: string; value: string }> }).identifiers
          .some((i) => identifierKey(i.type, i.value) === identifierKey(i.type, id.value)));
        if (e) return { entity: e, identifier: id };
      }
      return undefined;
    } });
    return { d, asked, errors: d.reasons.filter((r) => r.severity === 'ERROR').map((r) => r.code) };
  };

  it('asks about an issuer URL missing from the snapshot', async () => {
    const { d, asked } = await run({ role: 'issuer', subject: { identifier: 'https://fed.example/issuer' } });
    expect(asked[0]).toBe('URL:https://fed.example/issuer');
    expect([d.decision, d.entity?.id]).toEqual(['TRUSTED', 'fed-issuer']);
    expect(codes(d)).toContain('lookup.on_demand');
    expect(d.evidence?.matchedIdentifiers).toEqual(['URL:https://fed.example/issuer (on-demand)']);
  });

  it('asks about the origin of an unsigned DC API request', async () => {
    const { d, asked } = await run({ role: 'verifier', subject: { identifier: 'origin:https://fed.example' } });
    expect(asked).toEqual(['URL:https://fed.example']);
    expect([d.decision, d.entity?.id]).toEqual(['TRUSTED', 'fed-verifier']);
  });

  it('never asks about a pre-registered client id or a party the snapshot knows', async () => {
    expect((await run({ role: 'verifier', subject: { identifier: 'my-client' } })).asked).toEqual([]);
    const known = await run({ role: 'issuer', subject: { identifier: 'https://verifier.example' } });
    expect([known.asked, known.d.entity?.id]).toEqual([[], 'gov-issuer']);
  });

  it('with a key, asks about the key\'s identifiers, not the claimed one', async () => {
    const { d, asked } = await run({ role: 'issuer', subject: { identifier: 'https://fed.example/issuer', kid: `${EBSI_DID}#key-1` } });
    expect(asked).toEqual([`DID:${EBSI_DID}`]);
    expect([d.decision, d.entity?.id]).toEqual(['TRUSTED', 'ebsi-issuer']);
    expect(codes(d)).toContain('did.unresolved');
  });

  it('never sends a DID that is a public key itself', async () => {
    const { d, asked } = await run({ role: 'issuer', subject: { identifier: OTHER_DID, kid: `${OTHER_DID}#0` } });
    expect([asked, d.decision]).toEqual([[], 'UNKNOWN']);
  });

  it('asks about a validated certificate\'s URI names even when its anchor alone is trusted', async () => {
    const leaf = parseCertificate(pem('rp-uri'));
    const { d, asked, errors } = await run({ role: 'verifier', subject: { identifier: `x509_hash:${leaf.sha256}`, x5c: [b64('rp-uri')] } });
    expect(asked).toEqual(['URL:https://fed.example/rp']);
    expect([d.decision, d.entity?.id, errors]).toEqual(['NOT_TRUSTED', 'fed-rp', ['entity.status']]);
  });
});
