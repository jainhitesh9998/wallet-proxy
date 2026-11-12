/**
 * The device uses a trust anchor's constraints.crlUrls: when the snapshot carries no CRL for the anchor (the service
 * leaves out one that is too large, or could not load it), a certificate the anchor issued is checked against the CRL
 * at those locations, fetched like any other CRL and kept only when the anchor issued it. Pinned anchors the same.
 */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createTrustClient, MemoryCacheStore, type TrustClientConfig, type TrustQuery } from '../src/index.js';
import { jwkThumbprint, parseCertificate, parseCrl } from '../src/primitives.js';
import { b64, down, es256Key, fakeFetch, fixture, json, pem, signJwt } from './helpers.js';
import * as P from './pki.js';
import { anchorCrlUrls, crlUrlsToFetch, MAX_CRL_URLS } from '../src/x509/revocation.js';

const BASE = 'https://trust.example';
const PROXY_CRL = `${BASE}/api/v1/proxy/crl`;
/** Where the IACA's record says its CA publishes; no certificate names it as a distribution point. */
const ANCHOR_URL = 'http://pki.utopia.example/iaca.crl';
const ROOT_URL = 'http://pki.chained.example/root.crl';
const serviceKey = es256Key();
const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };

const keyPair = (name: string): P.KeyPair => {
  const privateKey = createPrivateKey(readFileSync(new URL(`../../../conformance/pki/${name}.key`, import.meta.url)));
  return { privateKey, publicKey: createPublicKey(privateKey) };
};
const iaca = parseCertificate(pem('iaca'));
const iacaKey = keyPair('iaca');
/** conformance/pki/iaca.crl: lists ds-revoked and ds-hold, signed by the IACA. */
const iacaCrl = new Uint8Array(fixture('pki/iaca.crl'));
/** The same CRL, signed by another CA (the rogue IACA). */
const otherCaCrl = P.seq(Buffer.from(parseCrl(iacaCrl).tbs), P.ALG.ecdsaSha256, P.bitstr(P.sign(keyPair('rogue-iaca'), parseCrl(iacaCrl).tbs)));
const revokedSerial = BigInt(`0x${parseCertificate(pem('ds-revoked')).serialNumber}`);
/** A Document Signer of the IACA, revoked in iaca.crl (it has ds-revoked's serial), that names no distribution point. */
const dsRevokedNoDp = P.cert({ subject: P.name([['C', 'UT'], ['O', 'Utopia DMV'], ['CN', 'Utopia DS (revoked, no distribution point)']]),
  issuer: Buffer.from(iaca.subjectRaw), key: P.ecKey(), signer: iacaKey, serial: revokedSerial,
  exts: [P.X.ku([0]), P.X.eku(['1.0.18013.5.1.2'], true)] });

const mdl = { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' };
const issued = (x5c: string[]): TrustQuery => ({ role: 'issuer', subject: { x5c }, context: mdl });
const ds = issued([b64(pem('ds'))]);
const dsRevoked = issued([Buffer.from(dsRevokedNoDp).toString('base64')]);
const crlResponse = (der: Uint8Array) => () => new Response(new Uint8Array(der), { headers: { 'Content-Type': 'application/pkix-crl' } });

const iacaAnchor = (constraints: Record<string, unknown> = { crlUrls: [ANCHOR_URL] }) =>
  ({ id: 'iaca', domain: 'mdoc-iaca', frameworkId: 'utopia', status: 'ACTIVE', constraints, certificate: b64(pem('iaca')) });

/** A snapshot with these anchors and CRLs; by default the IACA with crlUrls, and no CRL (as when it is too large to ship). */
function snapshotRoutes(claims: Record<string, unknown> = {}): Record<string, () => Response> {
  const iat = Math.floor(Date.now() / 1000);
  const jwt = signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: 'svc-1' }, { iss: BASE, aud: 'wallet-1', iat, exp: iat + 3600, format: 4,
    frameworks: [{ id: 'utopia', name: 'Utopia' }], entities: [], anchors: [iacaAnchor()], crls: [], ...claims }, serviceKey.privateKey);
  return {
    [`${BASE}/api/v1/snapshot`]: () => new Response(jwt, { headers: { 'Content-Type': 'application/jwt' } }),
    [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
  };
}

function client(fetch: typeof globalThis.fetch, extra: Partial<TrustClientConfig> = {}) {
  return createTrustClient({ service: { url: BASE, clientId: 'wallet-1', keys: { thumbprints: [jwkThumbprint(serviceJwk)] } },
    storage: new MemoryCacheStore(), ...extra, http: { fetch, retries: 0, timeoutMs: 500 } });
}

const toAnchorUrl = (calls: string[]) => calls.filter((x) => x.includes('pki.utopia.example') || x.includes(encodeURIComponent(ANCHOR_URL)));

describe("a trust anchor's crlUrls on the device", () => {
  it('are fetched through the relay for a certificate the anchor issued that names no distribution point: GOOD and REVOKED', async () => {
    const storage = new MemoryCacheStore();
    const { fetch, calls } = fakeFetch({ ...snapshotRoutes(), [PROXY_CRL]: crlResponse(iacaCrl) }, down);
    const c = client(fetch, { storage });
    const good = await c.evaluate(ds);
    expect([good.decision, good.source]).toEqual(['TRUSTED', 'snapshot']);
    expect(good.evidence?.x509?.revocation).toEqual([expect.objectContaining({ status: 'GOOD', source: 'proxy', crlUrl: ANCHOR_URL })]);
    expect(good.reasons.map((r) => r.code)).not.toContain('x509.revocation_unknown');

    const revoked = await c.evaluate(dsRevoked);
    expect(revoked.decision).toBe('NOT_TRUSTED');
    expect(revoked.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revoked');
    expect(revoked.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', reason: 'keyCompromise', source: 'cache', crlUrl: ANCHOR_URL });

    // Once, through the relay, by the anchor's URL; the CRL is kept for the next decision.
    expect(toAnchorUrl(calls)).toEqual([`GET ${PROXY_CRL}?url=${encodeURIComponent(ANCHOR_URL)}`]);
    expect(await storage.get(`crl:${ANCHOR_URL}`)).not.toBeNull();
  });

  it('go to the URL itself when the relay cannot serve, and only there with lookups direct', async () => {
    const fallback = fakeFetch({ ...snapshotRoutes(), [PROXY_CRL]: down, [ANCHOR_URL]: crlResponse(iacaCrl) }, down);
    const d = await client(fallback.fetch).evaluate(dsRevoked);
    expect(d.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', source: 'fallback', crlUrl: ANCHOR_URL });
    expect(toAnchorUrl(fallback.calls)).toEqual([`GET ${PROXY_CRL}?url=${encodeURIComponent(ANCHOR_URL)}`, `GET ${ANCHOR_URL}`]);

    const direct = fakeFetch({ ...snapshotRoutes(), [ANCHOR_URL]: crlResponse(iacaCrl) }, down);
    expect((await client(direct.fetch, { lookups: 'direct' }).evaluate(ds)).evidence?.x509?.revocation?.[0])
      .toMatchObject({ status: 'GOOD', source: 'direct' });
    expect(direct.calls.some((x) => x.includes('/api/v1/proxy/'))).toBe(false);
  });

  it('count only when the anchor issued the CRL: signed by another CA, or naming another issuer, it is refused and not kept', async () => {
    const otherIssuer = P.crl({ issuer: [['C', 'UT'], ['O', 'Utopia DMV'], ['CN', 'Utopia IACA 2']], signer: iacaKey, entries: [{ serial: revokedSerial }] });
    for (const [name, der] of [['signed by another CA', otherCaCrl], ['signed by the anchor key, another issuer', otherIssuer]] as const) {
      const storage = new MemoryCacheStore();
      // The relay and the location itself both serve it: neither route yields a CRL that counts.
      const c = client(fakeFetch({ ...snapshotRoutes(), [PROXY_CRL]: crlResponse(der), [ANCHOR_URL]: crlResponse(der) }, down).fetch, { storage });
      for (const q of [ds, dsRevoked]) {
        const d = await c.evaluate(q);
        expect(d.decision, name).toBe('TRUSTED');
        expect(d.evidence?.x509?.revocation?.[0], name).toMatchObject({ status: 'UNKNOWN', reason: 'CRL unavailable: CRL is not signed by the issuing CA' });
        expect(d.reasons.find((r) => r.code === 'x509.revocation_unknown')?.severity, name).toBe('WARNING');
      }
      expect(await storage.get(`crl:${ANCHOR_URL}`), name).toBeNull();
    }
  });

  it('a relay that answers with a CRL that does not count has not served the lookup: the location itself is asked', async () => {
    const notACrl = () => new Response('<html>maintenance</html>', { headers: { 'Content-Type': 'application/pkix-crl' } });
    for (const [name, relayed] of [['a CRL signed by another CA', crlResponse(otherCaCrl)], ['something that is not a CRL', notACrl]] as const) {
      const { fetch, calls } = fakeFetch({ ...snapshotRoutes(), [PROXY_CRL]: relayed, [ANCHOR_URL]: crlResponse(iacaCrl) }, down);
      const c = client(fetch);
      expect((await c.evaluate(dsRevoked)).evidence?.x509?.revocation?.[0], name).toMatchObject({ status: 'REVOKED', source: 'fallback', crlUrl: ANCHOR_URL });
      expect(toAnchorUrl(calls), name).toEqual([`GET ${PROXY_CRL}?url=${encodeURIComponent(ANCHOR_URL)}`, `GET ${ANCHOR_URL}`]);
    }
  });

  it('download nothing with lookups.crl none', async () => {
    const { fetch, calls } = fakeFetch({ ...snapshotRoutes(), [PROXY_CRL]: crlResponse(iacaCrl), [ANCHOR_URL]: crlResponse(iacaCrl) }, down);
    const d = await client(fetch, { lookups: { crl: 'none' } }).evaluate(dsRevoked);
    expect(d.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'UNKNOWN', reason: 'CRL unavailable: CRL downloads are disabled on this device' });
    expect(new Set(calls.map((x) => x.split('?')[0]))).toEqual(new Set([`GET ${BASE}/api/v1/snapshot`, `GET ${BASE}/.well-known/jwks.json`]));
  });

  it("are not consulted for a chain under an unknown anchor, nor under another anchor", async () => {
    const rpCa = { id: 'rp-ca', domain: 'verifier-access', frameworkId: 'utopia', status: 'ACTIVE', constraints: {}, certificate: b64(pem('rp-ca')) };
    const { fetch, calls } = fakeFetch({ ...snapshotRoutes({ anchors: [iacaAnchor(), rpCa] }), [PROXY_CRL]: crlResponse(iacaCrl) }, down);
    const c = client(fetch);
    const rogue = await c.evaluate(issued([b64(pem('rogue-ds'))]));
    expect(rogue.decision).toBe('UNKNOWN');
    expect(rogue.reasons.map((r) => r.code)).toContain('x509.no_anchor');
    const verifier = await c.evaluateVerifier({ clientId: 'x509_san_dns:verifier.example', x5c: [b64(pem('rp'))], responseUri: 'https://verifier.example/response' });
    expect(verifier.evidence?.x509?.revocation?.[0]?.status).toBe('UNKNOWN');
    expect(calls.some((x) => x.includes('/proxy/crl'))).toBe(false);
  });

  it('are for the certificate the anchor issued: a certificate below an intermediate is not sent there', async () => {
    const root = parseCertificate(pem('rsa-root'));
    const rootCrl = P.crl({ issuer: Buffer.from(root.subjectRaw), signer: keyPair('rsa-root'), entries: [{ serial: 0x7777n }] });
    const rootAnchor = { id: 'issuer-root', domain: 'credential-issuer', frameworkId: 'utopia', status: 'ACTIVE', constraints: { crlUrls: [ROOT_URL] },
      certificate: b64(pem('rsa-root')) };
    const chain: TrustQuery = { role: 'issuer', subject: { x5c: [b64(pem('chain-leaf')), b64(pem('chain-ca'))] }, context: { credentialFormat: 'dc+sd-jwt' } };

    // The intermediate's status is unknown: the root's CRL is fetched for it, and says nothing about the leaf.
    const fetched = fakeFetch({ ...snapshotRoutes({ anchors: [rootAnchor] }), [PROXY_CRL]: crlResponse(rootCrl) }, down);
    const d = await client(fetched.fetch).evaluate(chain);
    expect(d.evidence?.x509?.revocation?.map((r) => [r.index, r.status])).toEqual([[0, 'UNKNOWN'], [1, 'GOOD']]);
    expect(fetched.calls.filter((x) => x.includes('/proxy/crl'))).toEqual([`GET ${PROXY_CRL}?url=${encodeURIComponent(ROOT_URL)}`]);

    // The snapshot carries the root's CRL: only the leaf is unknown, and the root's locations are not asked.
    const held = fakeFetch({ ...snapshotRoutes({ anchors: [rootAnchor], crls: [{ issuer: 'root', crl: rootCrl.toString('base64') }] }),
      [PROXY_CRL]: crlResponse(rootCrl) }, down);
    const e = await client(held.fetch).evaluate(chain);
    expect(e.evidence?.x509?.revocation?.map((r) => [r.index, r.status, r.source])).toEqual([[0, 'UNKNOWN', undefined], [1, 'GOOD', 'snapshot']]);
    expect(held.calls.some((x) => x.includes('/proxy/crl'))).toBe(false);
  });

  it('keep the rule that a CRL scoped by an issuing distribution point covers only certificates naming that point', async () => {
    const scoped = P.crl({ issuer: Buffer.from(iaca.subjectRaw), signer: iacaKey, entries: [{ serial: revokedSerial }], exts: [P.CX.idp({ uri: ANCHOR_URL })] });
    const storage = new MemoryCacheStore();
    const c = client(fakeFetch({ ...snapshotRoutes(), [PROXY_CRL]: crlResponse(scoped) }, down).fetch, { storage });
    for (const q of [ds, dsRevoked]) expect((await c.evaluate(q)).evidence?.x509?.revocation?.[0]?.status).toBe('UNKNOWN');
    // The anchor issued it, so it is kept; it just does not speak for these certificates.
    expect(await storage.get(`crl:${ANCHOR_URL}`)).not.toBeNull();
  });
});

describe("a pinned anchor's crlUrls", () => {
  it('let pinned trust check revocation without a snapshot', async () => {
    for (const crlUrls of [[ANCHOR_URL], ANCHOR_URL]) {
      const { fetch, calls } = fakeFetch({ [ANCHOR_URL]: crlResponse(iacaCrl) }, down);
      const c = createTrustClient({ http: { fetch, retries: 0 }, policy: { requireRevocationStatus: true },
        pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca'), constraints: { crlUrls } }] } });
      const good = await c.evaluate(ds);
      expect([good.decision, good.source]).toEqual(['TRUSTED', 'pinned']);
      expect(good.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'GOOD', source: 'direct', crlUrl: ANCHOR_URL });
      const revoked = await c.evaluate(dsRevoked);
      expect([revoked.decision, revoked.source]).toEqual(['NOT_TRUSTED', 'pinned']);
      expect(revoked.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revoked');
      expect(calls).toEqual([`GET ${ANCHOR_URL}`]);
    }
  });

  it('at most the first eight locations are fetched, as many as the list names', async () => {
    const many = Array.from({ length: 20 }, (_, i) => `http://pki${i}.utopia.example/iaca.crl`);
    const { fetch, calls } = fakeFetch({ [many[7]!]: crlResponse(iacaCrl) }, down);
    const c = createTrustClient({ http: { fetch, retries: 0 },
      pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca'), constraints: { crlUrls: ['ldap://pki.utopia.example/cn=iaca', ...many] } }] } });
    expect((await c.evaluate(dsRevoked)).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', crlUrl: many[7] });
    expect(calls).toEqual(many.slice(0, 8).map((u) => `GET ${u}`));
  });

  it('only http(s) locations are fetched', async () => {
    const { fetch, calls } = fakeFetch({}, down);
    const c = createTrustClient({ http: { fetch, retries: 0 },
      pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca'), constraints: { crlUrls: ['ldap://pki.utopia.example/cn=iaca', 'file:///etc/iaca.crl'] } }] } });
    expect((await c.evaluate(ds)).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'UNKNOWN', reason: 'no CRL is published for it' });
    expect(calls).toEqual([]);
  });
});

/**
 * The service's rule (CrlService): an anchor whose record names no CRL location publishes at the distribution point of
 * its own certificate when it is self-issued. A root does; the certificate of an intermediate CA names where the CA
 * above it publishes, which says nothing about the certificates the intermediate issues.
 */
describe('an anchor whose record names no CRL location', () => {
  const OWN_URL = 'http://pki.rooted.example/root.crl';
  const ABOVE_URL = 'http://pki.rooted.example/above.crl';
  const DS_EXTS = [P.X.ku([0]), P.X.eku(['1.0.18013.5.1.2'], true)];
  const subject = (cn: string): P.Rdns => [['C', 'UT'], ['O', 'Rooted'], ['CN', cn]];
  const b64der = (der: Buffer) => der.toString('base64');
  const query = (leaf: Buffer) => issued([b64der(leaf)]);

  it('a self-issued anchor is asked at the distribution point its own certificate names', async () => {
    const key = P.ecKey();
    const root = P.cert({ subject: subject('Rooted IACA'), issuer: subject('Rooted IACA'), key, signer: key,
      exts: [P.X.bc(true, 0), P.X.ku([5, 6]), P.X.crlDp([OWN_URL])] });
    const leaf = (serial: bigint) => P.cert({ subject: subject('Rooted DS'), issuer: subject('Rooted IACA'), key: P.ecKey(), signer: key, serial, exts: DS_EXTS });
    const rootCrl = P.crl({ issuer: subject('Rooted IACA'), signer: key, entries: [{ serial: 0x51n }] });
    const { fetch, calls } = fakeFetch({ [OWN_URL]: crlResponse(rootCrl) }, down);
    const c = createTrustClient({ http: { fetch, retries: 0 }, pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: b64der(root) }] } });
    expect((await c.evaluate(query(leaf(0x50n)))).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'GOOD', source: 'direct', crlUrl: OWN_URL });
    const revoked = await c.evaluate(query(leaf(0x51n)));
    expect([revoked.decision, revoked.reasons.find((r) => r.severity === 'ERROR')?.code]).toEqual(['NOT_TRUSTED', 'x509.revoked']);
    expect(calls).toEqual([`GET ${OWN_URL}`]);

    // What the record names comes first: the certificate's own distribution point is then not asked.
    const named = fakeFetch({ [ANCHOR_URL]: crlResponse(rootCrl), [OWN_URL]: crlResponse(rootCrl) }, down);
    const n = createTrustClient({ http: { fetch: named.fetch, retries: 0 },
      pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: b64der(root), constraints: { crlUrls: [ANCHOR_URL] } }] } });
    expect((await n.evaluate(query(leaf(0x51n)))).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', crlUrl: ANCHOR_URL });
    expect(named.calls).toEqual([`GET ${ANCHOR_URL}`]);
  });

  it('at most the first eight distribution points of the anchor certificate are counted', async () => {
    const key = P.ecKey();
    const points = Array.from({ length: 12 }, (_, i) => `http://pki${i}.rooted.example/root.crl`);
    const root = parseCertificate(b64der(P.cert({ subject: subject('Rooted IACA'), issuer: subject('Rooted IACA'), key, signer: key,
      exts: [P.X.bc(true, 0), P.X.ku([5, 6]), P.X.crlDp(points)] })));
    expect(anchorCrlUrls({ certificate: root })).toEqual(points.slice(0, MAX_CRL_URLS));
    expect(anchorCrlUrls({ certificate: root, constraints: { crlUrls: ['ftp://x', ...points.slice(2), points[0]] } }))
      .toEqual([...points.slice(2, 10)]);
    expect(MAX_CRL_URLS).toBe(8);
  });

  it('an intermediate CA listed as an anchor is not asked at the distribution point in its certificate', async () => {
    const above = P.ecKey();
    const key = P.ecKey();
    const intermediate = P.cert({ subject: subject('Rooted Issuing CA'), issuer: subject('Rooted Root'), key, signer: above,
      exts: [P.X.bc(true, 0), P.X.ku([5, 6]), P.X.crlDp([ABOVE_URL])] });
    const leaf = P.cert({ subject: subject('Rooted DS'), issuer: subject('Rooted Issuing CA'), key: P.ecKey(), signer: key, exts: DS_EXTS });
    // Even a CRL the intermediate itself signed would be found there: the location is not the intermediate's to publish at.
    const { fetch, calls } = fakeFetch({ [ABOVE_URL]: crlResponse(P.crl({ issuer: subject('Rooted Issuing CA'), signer: key })) }, down);
    const c = createTrustClient({ http: { fetch, retries: 0 }, pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: b64der(intermediate) }] } });
    const d = await c.evaluate(query(leaf));
    expect([d.decision, d.evidence?.x509?.revocation?.[0]?.status, d.evidence?.x509?.revocation?.[0]?.reason]).toEqual(['TRUSTED', 'UNKNOWN', 'no CRL is published for it']);
    expect(calls).toEqual([]);
  });
});

/**
 * A certificate decides how many distribution points it names, and each is a request: at most the first eight http(s)
 * ones are fetched, in the order it names them, as on the service (RevocationChecker).
 */
describe('the distribution points a certificate names', () => {
  const subject = (cn: string): P.Rdns => [['C', 'UT'], ['O', 'Pointed'], ['CN', cn]];
  const key = P.ecKey();
  const root = P.cert({ subject: subject('Pointed IACA'), issuer: subject('Pointed IACA'), key, signer: key, exts: [P.X.bc(true, 0), P.X.ku([5, 6])] });
  const points = Array.from({ length: 20 }, (_, i) => `http://pki${i}.pointed.example/iaca.crl`);
  const leaf = P.cert({ subject: subject('Pointed DS'), issuer: subject('Pointed IACA'), key: P.ecKey(), signer: key, serial: 0x77n,
    exts: [P.X.ku([0]), P.X.eku(['1.0.18013.5.1.2'], true), P.X.crlDp(['ldap://pki.pointed.example/cn=iaca', ...points])] });
  const revoking = P.crl({ issuer: subject('Pointed IACA'), signer: key, entries: [{ serial: 0x77n }] });

  it('at most the first eight http(s) ones are fetched', async () => {
    // The CRL that revokes it is at the ninth http location: it is never asked for.
    const { fetch, calls } = fakeFetch({ [points[8]!]: crlResponse(revoking) }, down);
    const c = createTrustClient({ http: { fetch, retries: 0 }, pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: root.toString('base64') }] } });
    const d = await c.evaluate(issued([leaf.toString('base64')]));
    expect(d.evidence?.x509?.revocation?.[0]?.status).toBe('UNKNOWN');
    expect(calls).toEqual(points.slice(0, 8).map((u) => `GET ${u}`));
    expect(crlUrlsToFetch([parseCertificate(leaf)], [{ index: 0, status: 'UNKNOWN' } as never])).toEqual(points.slice(0, 8));

    // At the eighth, it is.
    const eighth = fakeFetch({ [points[7]!]: crlResponse(revoking) }, down);
    const e = createTrustClient({ http: { fetch: eighth.fetch, retries: 0 }, pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: root.toString('base64') }] } });
    expect((await e.evaluate(issued([leaf.toString('base64')]))).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', crlUrl: points[7] });
    expect(MAX_CRL_URLS).toBe(8);
  });
});
