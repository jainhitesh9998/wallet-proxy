import { describe, expect, it } from 'vitest';
import { createTrustClient, TrustServiceError, TrustIntegrityError, MemoryCacheStore, jwkThumbprint } from '../src/index.js';
import { b64, down, es256Key, fakeFetch, json, pem, signJwt } from './helpers.js';

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

function client(fetch: typeof globalThis.fetch, extra: Record<string, unknown> = {}) {
  return createTrustClient({ baseUrl: BASE, apiKey: 'k', clientId: 'wallet-1', fetch, retries: 0, timeoutMs: 500,
    serviceKeys: { thumbprints: [jwkThumbprint(serviceJwk)] }, cache: new MemoryCacheStore(), ...extra });
}

describe('TrustClient', () => {
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
    await expect(client(fetch).syncSnapshot()).rejects.toThrow(/audience/);
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
