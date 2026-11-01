import { describe, expect, it } from 'vitest';
import { createTrustClient, TrustServiceError, TrustIntegrityError, MemoryCacheStore, jwkThumbprint } from '../src/index.js';
import { b64, down, es256Key, fakeFetch, fixture, json, pem, signJwt } from './helpers.js';

const BASE = 'https://trust.example';
const serviceKey = es256Key();
const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };

function snapshotJwt(overrides: Record<string, unknown> = {}, key = serviceKey.privateKey, kid = 'svc-1') {
  const now = Math.floor(Date.now() / 1000);
  return signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid }, {
    iss: BASE, aud: 'wallet-1', iat: now, exp: now + 3600, version: 7,
    frameworks: [{ id: 'utopia', name: 'Utopia' }],
    entities: [{ id: 'utopia-dmv', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE',
      identifiers: [{ type: 'URL', value: 'https://issuer.example' }], display: [{ locale: 'en', name: 'Utopia DMV' }],
      authorizations: [{ format: 'mso_mdoc', type: 'org.iso.18013.5.1.mDL' }] }],
    anchors: [{ id: 'a1', domain: 'mdoc-iaca', frameworkId: 'utopia', entityId: 'utopia-dmv', status: 'ACTIVE', constraints: {}, certificate: b64(pem('iaca')) }],
    ...overrides,
  }, key);
}

const remoteDecision = { decision: 'TRUSTED', summary: 'ok', reasons: [], evaluatedAt: 'x', validUntil: 'y', source: 'trust-service' };

/** 'service' mode: the service decides; device-side evaluation only while it is unreachable. */
function client(fetch: typeof globalThis.fetch, extra: Record<string, unknown> = {}) {
  return createTrustClient({ baseUrl: BASE, apiKey: 'k', clientId: 'wallet-1', fetch, retries: 0, timeoutMs: 500, decisions: 'service',
    serviceKeys: { thumbprints: [jwkThumbprint(serviceJwk)] }, cache: new MemoryCacheStore(), ...extra });
}

describe('TrustClient (service mode)', () => {
  it('uses the trust service when available', async () => {
    const { fetch, calls } = fakeFetch({ [`${BASE}/api/v1/evaluate`]: () => json(remoteDecision) });
    const c = client(fetch);
    const d = await c.evaluateIssuer({ credentialIssuer: 'https://issuer.example' });
    expect(d.decision).toBe('TRUSTED');
    expect(d.source).toBe('trust-service');
    expect(calls[0]).toBe(`POST ${BASE}/api/v1/evaluate`);
    expect(c.status).toBe('online');
  });

  it('falls back to the verified snapshot when the service goes down', async () => {
    let online = true;
    const { fetch } = fakeFetch({
      [`${BASE}/api/v1/snapshot`]: () => (online ? new Response(snapshotJwt(), { headers: { 'Content-Type': 'application/jwt', ETag: '"s7"' } }) : down()),
      [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
      [`${BASE}/api/v1/evaluate`]: () => (online ? json(remoteDecision) : down()),
    });
    const c = client(fetch);
    const snap = await c.syncSnapshot();
    expect(snap.version).toBe(7);
    online = false;
    const d = await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } });
    expect(d.source).toBe('snapshot');
    expect(d.decision).toBe('TRUSTED');
    expect(d.entity?.id).toBe('utopia-dmv');
    expect(c.status).toBe('offline');
    const rogue = await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('rogue-ds'))] }, context: { credentialFormat: 'mso_mdoc' } });
    expect(rogue.decision).toBe('UNKNOWN');
    const byUrl = await c.evaluateIssuer({ credentialIssuer: 'https://issuer.example/', format: 'mso_mdoc', type: 'eu.europa.ec.eudi.pid.1' });
    expect(byUrl.decision).toBe('NOT_TRUSTED');
  });

  it('without snapshot or local anchors an offline decision is UNKNOWN, never TRUSTED', async () => {
    const c = client(fakeFetch({}, down).fetch);
    const d = await c.evaluateIssuer({ credentialIssuer: 'https://issuer.example' });
    expect(d.decision).toBe('UNKNOWN');
    expect(d.source).toBe('fallback');
  });

  it('uses app-bundled anchors offline', async () => {
    const c = client(fakeFetch({}, down).fetch, { fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca') }] } });
    const d = await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: { credentialFormat: 'mso_mdoc' } });
    expect(d.decision).toBe('TRUSTED');
    expect(d.source).toBe('fallback');
  });

  it('rejects snapshots signed by an unpinned key', async () => {
    const other = es256Key();
    const { fetch } = fakeFetch({
      [`${BASE}/api/v1/snapshot`]: () => new Response(snapshotJwt({}, other.privateKey, 'evil'), { headers: { 'Content-Type': 'application/jwt' } }),
      [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [{ ...other.jwk, kid: 'evil' }] }),
    });
    await expect(client(fetch).syncSnapshot()).rejects.toBeInstanceOf(TrustIntegrityError);
  });

  it('rejects snapshots for another audience', async () => {
    const { fetch } = fakeFetch({
      [`${BASE}/api/v1/snapshot`]: () => new Response(snapshotJwt({ aud: 'someone-else' }), { headers: { 'Content-Type': 'application/jwt' } }),
      [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
    });
    await expect(client(fetch).syncSnapshot()).rejects.toThrow(/audience/i);
  });

  it('does not bypass policy answers with fallback', async () => {
    const { fetch, calls } = fakeFetch({
      [`${BASE}/api/v1/issuers/metadata`]: () => json({ code: 'issuer_not_registered', detail: 'nope', status: 403 }, 403),
    });
    await expect(client(fetch).getIssuerMetadata('https://issuer.example')).rejects.toBeInstanceOf(TrustServiceError);
    expect(calls.some((c) => c.includes('.well-known/openid-credential-issuer'))).toBe(false);
  });

  it('falls back to standard OpenID4VCI discovery for metadata', async () => {
    const { fetch, calls } = fakeFetch({
      [`${BASE}/`]: down,
      'https://issuer.example/.well-known/openid-credential-issuer/tenant': () => json({ credential_issuer: 'https://issuer.example/tenant',
        credential_endpoint: 'https://issuer.example/tenant/credential', credential_configurations_supported: {} }),
      'https://issuer.example/.well-known/oauth-authorization-server/tenant': () => json({ issuer: 'https://issuer.example/tenant', token_endpoint: 'https://issuer.example/tenant/token' }),
    });
    const md = await client(fetch).getIssuerMetadata('https://issuer.example/tenant');
    expect(md.source).toBe('fallback');
    expect(md.authorizationServers['https://issuer.example/tenant']?.token_endpoint).toBe('https://issuer.example/tenant/token');
    expect(md.trust.decision).toBe('UNKNOWN');
    expect(calls.filter((c) => c.startsWith('GET https://issuer.example'))).toHaveLength(2);
  });

  it('serves cached metadata while offline', async () => {
    let online = true;
    const env = { credentialIssuer: 'https://issuer.example', credentialIssuerMetadata: { credential_issuer: 'https://issuer.example' },
      authorizationServers: {}, policyApplied: false, fetchedAt: 'x', expiresAt: new Date(Date.now() + 600_000).toISOString(),
      stale: false, warnings: [], trust: remoteDecision };
    const { fetch } = fakeFetch({ [`${BASE}/api/v1/issuers/metadata`]: () => (online ? json(env) : down()) }, down);
    const c = client(fetch);
    expect((await c.getIssuerMetadata('https://issuer.example')).source).toBe('trust-service');
    online = false;
    expect((await c.getIssuerMetadata('https://issuer.example')).source).toBe('cache');
  });

  it('opens the circuit after repeated failures', async () => {
    const { fetch, calls } = fakeFetch({}, down);
    const c = client(fetch, { circuitBreaker: { failureThreshold: 2, resetAfterMs: 60_000 } });
    for (let i = 0; i < 4; i++) await c.evaluateIssuer({ credentialIssuer: 'https://x.example' });
    expect(calls.filter((x) => x.includes('/api/v1/evaluate'))).toHaveLength(2);
  });

  it('passes DID resolution errors through instead of falling back', async () => {
    const notFound = { didDocument: null, didResolutionMetadata: { error: { type: 'https://www.w3.org/ns/did#NOT_FOUND' } }, didDocumentMetadata: {} };
    const { fetch } = fakeFetch({ [`${BASE}/api/v1/did/`]: () => json(notFound, 404) });
    const r = await client(fetch).resolveDid('did:web:missing.example');
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.source).toBe('trust-service');
  });

  it('resolves DIDs locally when offline', async () => {
    const r = await client(fakeFetch({}, down).fetch).resolveDid('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    expect(r.didDocument?.id).toBe('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    expect(r.didResolutionMetadata.source).toBe('fallback');
  });

  it('works with no service configured (standards-only mode)', async () => {
    const c = createTrustClient({ fetch: fakeFetch({}).fetch, fallback: { localAnchors: [{ domain: 'verifier-access', certificate: pem('rp-ca') }] } });
    const d = await c.evaluateVerifier({ clientId: 'x509_san_dns:verifier.example', x5c: [b64(pem('rp'))], responseUri: 'https://verifier.example/post' });
    expect(d.decision).toBe('TRUSTED');
    const wrongHost = await c.evaluateVerifier({ clientId: 'x509_san_dns:verifier.example', x5c: [b64(pem('rp'))], responseUri: 'https://evil.example/post' });
    expect(wrongHost.decision).toBe('NOT_TRUSTED');
  });
});

/** 'local' mode (the default): decisions on this device from the signed snapshot. */
function localClient(fetch: typeof globalThis.fetch, extra: Record<string, unknown> = {}) {
  return createTrustClient({ baseUrl: BASE, apiKey: 'k', clientId: 'wallet-1', fetch, retries: 0, timeoutMs: 500,
    serviceKeys: { thumbprints: [jwkThumbprint(serviceJwk)] }, cache: new MemoryCacheStore(), ...extra });
}

const snapshotRoute = (claims: () => Record<string, unknown> = () => ({})): Record<string, (url: string) => Response> => ({
  [`${BASE}/api/v1/snapshot`]: () => new Response(snapshotJwt(claims()), { headers: { 'Content-Type': 'application/jwt' } }),
  [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
});
const mdl = { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' };
const didKey = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

describe('TrustClient (local mode, default)', () => {
  it('decides on the device; the service only ever sees snapshot requests', async () => {
    const { fetch, calls } = fakeFetch(snapshotRoute());
    const c = localClient(fetch);
    expect(c.decisions).toBe('local');
    const d = await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: mdl });
    expect(d.decision).toBe('TRUSTED');
    expect(d.source).toBe('snapshot');
    expect(d.snapshot?.version).toBe(7);
    expect(d.reasons.map((r) => r.code)).toContain('local.snapshot');
    expect((await c.evaluateIssuer({ credentialIssuer: 'https://issuer.example' })).decision).toBe('TRUSTED');
    expect((await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('rogue-ds'))] }, context: mdl })).decision).toBe('UNKNOWN');
    const service = calls.filter((x) => x.includes(BASE));
    expect(service.every((x) => x.endsWith('/api/v1/snapshot') || x.endsWith('/.well-known/jwks.json'))).toBe(true);
    expect(service.filter((x) => x.endsWith('/api/v1/snapshot'))).toHaveLength(1);
  });

  it('keeps deciding from the held snapshot when the service goes down', async () => {
    let online = true;
    const routes = snapshotRoute();
    const { fetch } = fakeFetch({ ...routes, [`${BASE}/api/v1/snapshot`]: (u) => (online ? routes[`${BASE}/api/v1/snapshot`]!(u) : down()) });
    const c = localClient(fetch, { snapshotRefreshMs: 0, snapshotRetryMs: 0 });
    await c.syncSnapshot();
    online = false;
    const d = await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: mdl });
    expect(d.decision).toBe('TRUSTED');
    expect(d.source).toBe('snapshot');
  });

  it('waits for the first snapshot; without a pinned key nothing is trusted', async () => {
    const d = await localClient(fakeFetch(snapshotRoute()).fetch).evaluateIssuer({ credentialIssuer: 'https://issuer.example' });
    expect(d.decision).toBe('TRUSTED');
    const unpinned = localClient(fakeFetch(snapshotRoute()).fetch, { serviceKeys: {} });
    const u = await unpinned.evaluateIssuer({ credentialIssuer: 'https://issuer.example' });
    expect(u.decision).toBe('UNKNOWN');
    expect(u.source).toBe('fallback');
  });

  it('applies the client policy carried in the snapshot (strict authorization)', async () => {
    const entity = { id: 'open', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [],
      identifiers: [{ type: 'URL', value: 'https://open.example' }], authorizations: [] };
    const q = { credentialIssuer: 'https://open.example', format: 'dc+sd-jwt', type: 'urn:eu.europa.ec.eudi:pid:1' };
    const lenient = localClient(fakeFetch(snapshotRoute(() => ({ entities: [entity] }))).fetch);
    expect((await lenient.evaluateIssuer(q)).decision).toBe('TRUSTED');
    const strict = localClient(fakeFetch(snapshotRoute(() => ({ entities: [entity], policy: { frameworks: [], strictAuthorization: true } }))).fetch);
    const d = await strict.evaluateIssuer(q);
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.reasons.map((r) => r.code)).toContain('entity.not_authorized');
  });

  it('never rolls back to an older snapshot, and refuses expired ones', async () => {
    const now = Math.floor(Date.now() / 1000);
    let claims: Record<string, unknown> = { iat: now, version: 9 };
    const c = localClient(fakeFetch(snapshotRoute(() => claims)).fetch);
    expect((await c.syncSnapshot()).version).toBe(9);
    claims = { iat: now - 600, version: 3 };
    expect((await c.syncSnapshot()).version).toBe(9);
    claims = { iat: now + 1, exp: now - 10, version: 10 };
    await expect(c.syncSnapshot()).rejects.toThrow(/expired/);
    expect((await c.snapshotInfo())?.version).toBe(9);
  });

  it('marks decisions from an expired snapshot within the grace period', async () => {
    let online = true;
    const now = Math.floor(Date.now() / 1000);
    const routes = snapshotRoute(() => ({ iat: now, exp: now + 2 }));
    const { fetch } = fakeFetch({ ...routes, [`${BASE}/api/v1/snapshot`]: (u) => (online ? routes[`${BASE}/api/v1/snapshot`]!(u) : down()) });
    const c = localClient(fetch, { snapshotRetryMs: 0 });
    await c.syncSnapshot();
    online = false;
    await new Promise((r) => setTimeout(r, 2_200));
    const d = await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: mdl });
    expect(d.decision).toBe('TRUSTED');
    expect(d.snapshot?.stale).toBe(true);
    expect(d.reasons.map((r) => r.code)).toContain('snapshot.stale');
  });

  it('serves DID documents from the snapshot, resolving directly when a key is missing from it', async () => {
    const stale = { id: didKey, verificationMethod: [], assertionMethod: [] };
    const { fetch, calls } = fakeFetch(snapshotRoute(() => ({ didDocuments: { [didKey]: stale } })));
    const c = localClient(fetch);
    const r = await c.resolveDid(didKey);
    expect(r.didResolutionMetadata.source).toBe('snapshot');
    const rotated = await c.resolveDid(`${didKey}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`);
    expect(rotated.didResolutionMetadata.source).toBe('direct');
    expect(rotated.didDocument?.verificationMethod?.length).toBe(1);
    expect(calls.some((x) => x.includes('/api/v1/did/'))).toBe(false);
  });

  it('fetches issuer metadata directly and applies the registry metadata policy', async () => {
    const entity = { id: 'utopia-dmv', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [], authorizations: [],
      identifiers: [{ type: 'URL', value: 'https://issuer.example' }],
      metadataPolicy: { oauth_authorization_server: { token_endpoint: { value: 'https://issuer.example/pinned-token' } } } };
    const { fetch, calls } = fakeFetch({
      ...snapshotRoute(() => ({ entities: [entity] })),
      'https://issuer.example/.well-known/openid-credential-issuer': () => json({ credential_issuer: 'https://issuer.example',
        credential_endpoint: 'https://issuer.example/credential', credential_configurations_supported: {} }),
      'https://issuer.example/.well-known/oauth-authorization-server': () => json({ issuer: 'https://issuer.example', token_endpoint: 'https://issuer.example/token' }),
    });
    const md = await localClient(fetch).getIssuerMetadata('https://issuer.example');
    expect(md.source).toBe('direct');
    expect(md.policyApplied).toBe(true);
    expect(md.authorizationServers['https://issuer.example']?.token_endpoint).toBe('https://issuer.example/pinned-token');
    expect(md.trust.decision).toBe('TRUSTED');
    expect(calls.some((x) => x.includes('/api/v1/issuers/metadata'))).toBe(false);
  });

  it('asks the service about unknown parties only when enabled, and verifies the signed answer', async () => {
    const found = [{ id: 'fed-issuer', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [], authorizations: [],
      identifiers: [{ type: 'URL', value: 'https://fed.example' }] }];
    const now = Math.floor(Date.now() / 1000);
    let signer = serviceKey.privateKey;
    const routes = { ...snapshotRoute(), [`${BASE}/api/v1/entities/lookup`]: () => new Response(signJwt({ alg: 'ES256', typ: 'trust-registry+jwt', kid: 'svc-1' },
      { iss: BASE, aud: 'wallet-1', iat: now, exp: now + 600, data: found }, signer), { headers: { 'Content-Type': 'application/jwt' } }) };
    const off = fakeFetch(routes);
    expect((await localClient(off.fetch).evaluateIssuer({ credentialIssuer: 'https://fed.example' })).decision).toBe('UNKNOWN');
    expect(off.calls.some((x) => x.includes('/entities/lookup'))).toBe(false);

    const on = fakeFetch(routes);
    const d = await localClient(on.fetch, { lookups: { unknownParties: true } }).evaluateIssuer({ credentialIssuer: 'https://fed.example' });
    expect(d.decision).toBe('TRUSTED');
    expect(d.reasons.map((r) => r.code)).toContain('lookup.on_demand');
    expect(on.calls.find((x) => x.includes('/entities/lookup'))).toContain('onDemand=true');

    signer = es256Key().privateKey;
    const forged = await localClient(fakeFetch(routes).fetch, { lookups: { unknownParties: true } }).evaluateIssuer({ credentialIssuer: 'https://fed.example' });
    expect(forged.decision).toBe('UNKNOWN');
  });
});

describe('TrustClient revocation (local mode)', () => {
  const crl = new Uint8Array(fixture('pki/iaca.crl'));
  const CRL_URL = 'http://crl.utopia.example/iaca.crl';
  const issued = (name: string) => ({ role: 'issuer' as const, subject: { x5c: [b64(pem(name))] }, context: mdl });
  const withCrl = () => ({ crls: [{ issuer: 'iaca', crl: Buffer.from(crl).toString('base64'), thisUpdate: 'x' }] });
  const crlRoute = (calls: { n: number }) => ({ [CRL_URL]: () => { calls.n++; return new Response(crl, { headers: { 'Content-Type': 'application/pkix-crl' } }); } });

  it('checks certificates against the anchor CRLs carried in the snapshot, without any other request', async () => {
    const { fetch, calls } = fakeFetch(snapshotRoute(withCrl));
    const c = localClient(fetch);
    const ok = await c.evaluate(issued('ds'));
    expect(ok.decision).toBe('TRUSTED');
    expect(ok.evidence?.x509?.revocation).toEqual([expect.objectContaining({ status: 'GOOD', source: 'snapshot' })]);
    const revoked = await c.evaluate(issued('ds-revoked'));
    expect(revoked.decision).toBe('NOT_TRUSTED');
    expect(revoked.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revoked');
    expect((await c.evaluate(issued('ds-hold'))).reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.on_hold');
    expect(new Set(calls.map((x) => x.split('?')[0]))).toEqual(new Set([`GET ${BASE}/api/v1/snapshot`, `GET ${BASE}/.well-known/jwks.json`]));
    expect((await c.snapshotInfo())?.crls).toBe(1);
  });

  it('fetches a CRL the snapshot lacks from its distribution point, caches it, and verifies it', async () => {
    const n = { n: 0 };
    const c = localClient(fakeFetch({ ...snapshotRoute(), ...crlRoute(n) }).fetch);
    const d = await c.evaluate(issued('ds-revoked'));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', source: 'direct', crlUrl: CRL_URL });
    expect((await c.evaluate(issued('ds-crldp'))).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'GOOD', source: 'cache' });
    expect(n.n).toBe(1);
    // A certificate without a distribution point under an anchor without a CRL: unknown, a warning only.
    const plain = await c.evaluate(issued('ds'));
    expect(plain.decision).toBe('TRUSTED');
    expect(plain.reasons.find((r) => r.code === 'x509.revocation_unknown')).toMatchObject({ severity: 'WARNING' });
  });

  it("downloads nothing with lookups.crl 'none', and uses the service relay with 'service'", async () => {
    const n = { n: 0 };
    const none = await localClient(fakeFetch({ ...snapshotRoute(), ...crlRoute(n) }).fetch, { lookups: { crl: 'none' } }).evaluate(issued('ds-revoked'));
    expect(none.decision).toBe('TRUSTED');
    expect(none.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'UNKNOWN', reason: 'CRL unavailable: CRL downloads are disabled on this device' });
    expect(n.n).toBe(0);
    const relay = fakeFetch({ ...snapshotRoute(), [`${BASE}/api/v1/revocation/crl`]: () => new Response(crl, { headers: { 'Content-Type': 'application/pkix-crl' } }) });
    const d = await localClient(relay.fetch, { lookups: { crl: 'service' } }).evaluate(issued('ds-revoked'));
    expect(d.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', source: 'trust-service' });
    expect(relay.calls.find((x) => x.includes('/revocation/crl'))).toContain(encodeURIComponent(CRL_URL));
  });

  it('applies the policy that requires a revocation status', async () => {
    const strict = () => ({ policy: { frameworks: [], strictAuthorization: false, requireRevocationStatus: true } });
    const c = localClient(fakeFetch(snapshotRoute(strict)).fetch);
    const d = await c.evaluate(issued('ds-ocsp'));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.reasons.find((r) => r.severity === 'ERROR')).toMatchObject({ code: 'x509.revocation_unknown', message: expect.stringMatching(/only OCSP/) });
    expect((await c.snapshotInfo())?.requireRevocationStatus).toBe(true);
  });

  it("fetches status lists directly, or through the relay with lookups.statusLists 'service'", async () => {
    const list = () => new Response('eyJ0', { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    const direct = fakeFetch({ ...snapshotRoute(), 'https://issuer.example/status/1': list });
    const a = await localClient(direct.fetch).fetchStatusList('https://issuer.example/status/1', 'application/statuslist+jwt');
    expect(a).toMatchObject({ source: 'direct', contentType: 'application/statuslist+jwt' });
    const relay = fakeFetch({ ...snapshotRoute(), [`${BASE}/api/v1/revocation/status-list`]: list });
    const b = await localClient(relay.fetch, { lookups: { statusLists: 'service' } }).fetchStatusList('https://issuer.example/status/1', 'application/statuslist+jwt');
    expect(b.source).toBe('trust-service');
    expect(new TextDecoder().decode(b.body)).toBe('eyJ0');
    expect(relay.calls.some((x) => x.startsWith('GET https://issuer.example'))).toBe(false);
    const fallback = fakeFetch({ ...snapshotRoute(), 'https://issuer.example/status/1': list, [`${BASE}/api/v1/revocation/status-list`]: down });
    expect((await localClient(fallback.fetch, { lookups: { statusLists: 'service' } }).fetchStatusList('https://issuer.example/status/1', '*/*')).source).toBe('fallback');
  });
});
