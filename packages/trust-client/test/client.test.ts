import { createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createTrustClient, TrustIntegrityError, MemoryCacheStore, type TrustClientConfig } from '../src/index.js';
import { isSecureUrl, jwkThumbprint } from '../src/primitives.js';
import { b64, down, es256Key, fakeFetch, fixture, json, pem, signJwt } from './helpers.js';

const BASE = 'https://trust.example';
const serviceKey = es256Key();
const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };
const seconds = () => Math.floor(Date.now() / 1000);

function snapshotJwt(overrides: Record<string, unknown> = {}, key = serviceKey.privateKey, kid = 'svc-1') {
  return signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid }, {
    iss: BASE, aud: 'wallet-1', iat: seconds(), exp: seconds() + 3600, format: 4,
    frameworks: [{ id: 'utopia', name: 'Utopia' }],
    entities: [{ id: 'utopia-dmv', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE',
      identifiers: [{ type: 'URL', value: 'https://issuer.example' }], display: [{ locale: 'en', name: 'Utopia DMV' }],
      authorizations: [{ format: 'mso_mdoc', type: 'org.iso.18013.5.1.mDL' }] }],
    anchors: [{ id: 'a1', domain: 'mdoc-iaca', frameworkId: 'utopia', entityId: 'utopia-dmv', status: 'ACTIVE', constraints: {}, certificate: b64(pem('iaca')) }],
    ...overrides,
  }, key);
}

/** A response signed by the service for this client, as the proxy and the on-demand lookup give it. */
function signedByService(typ: string, data: unknown, key = serviceKey.privateKey, aud = 'wallet-1') {
  return new Response(signJwt({ alg: 'ES256', typ, kid: 'svc-1' }, { iss: BASE, aud, iat: seconds(), exp: seconds() + 600, data }, key),
    { headers: { 'Content-Type': 'application/jwt' } });
}

function client(fetch: typeof globalThis.fetch, extra: Partial<TrustClientConfig> = {}) {
  return createTrustClient({ service: { url: BASE, clientId: 'wallet-1', apiKey: 'k', keys: { thumbprints: [jwkThumbprint(serviceJwk)] } },
    storage: new MemoryCacheStore(), ...extra, http: { fetch, retries: 0, timeoutMs: 500, ...extra.http } });
}

const snapshotRoute = (claims: () => Record<string, unknown> = () => ({})): Record<string, (url: string) => Response> => ({
  [`${BASE}/api/v1/snapshot`]: () => new Response(snapshotJwt(claims()), { headers: { 'Content-Type': 'application/jwt', ETag: '"abc123.1"' } }),
  [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
});
const mdl = { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' };
const dsChain = { role: 'issuer' as const, subject: { x5c: [b64(pem('ds'))] }, context: mdl };
const didKey = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

describe('decisions from the signed snapshot', () => {
  it('decides on the device; the service only ever sees snapshot requests', async () => {
    const { fetch, calls } = fakeFetch(snapshotRoute());
    const c = client(fetch);
    const d = await c.evaluate(dsChain);
    expect(d.decision).toBe('TRUSTED');
    expect(d.source).toBe('snapshot');
    expect(d.snapshot?.id).toBe('abc123');
    expect(d.reasons.map((r) => r.code)).toContain('local.snapshot');
    expect((await c.evaluateIssuer({ credentialIssuer: 'https://issuer.example' })).decision).toBe('TRUSTED');
    expect((await c.evaluate({ role: 'issuer', subject: { x5c: [b64(pem('rogue-ds'))] }, context: mdl })).decision).toBe('UNKNOWN');
    const service = calls.filter((x) => x.includes(BASE));
    expect(service.every((x) => x.endsWith('/api/v1/snapshot') || x.endsWith('/.well-known/jwks.json'))).toBe(true);
    expect(service.filter((x) => x.endsWith('/api/v1/snapshot'))).toHaveLength(1);
    expect(await c.status()).toMatchObject({ service: 'online', degraded: false, snapshot: { entities: 1, anchors: 1 } });
  });

  it('compares identifiers byte for byte', async () => {
    const c = client(fakeFetch(snapshotRoute()).fetch);
    for (const other of ['https://issuer.example/', 'https://Issuer.example', 'https://issuer.example:443', 'HTTPS://issuer.example']) {
      expect((await c.evaluateIssuer({ credentialIssuer: other })).decision, other).toBe('UNKNOWN');
    }
  });

  it('starts cold once: concurrent first decisions share one snapshot download', async () => {
    const { fetch, calls } = fakeFetch(snapshotRoute());
    const c = client(fetch);
    const decisions = await Promise.all(Array.from({ length: 5 }, () => c.evaluate(dsChain)));
    expect(decisions.map((d) => d.decision)).toEqual(Array(5).fill('TRUSTED'));
    expect(calls.filter((x) => x.endsWith('/api/v1/snapshot'))).toHaveLength(1);
  });

  it('keeps deciding from the held snapshot when the service goes down', async () => {
    let online = true;
    const routes = snapshotRoute();
    const { fetch } = fakeFetch({ ...routes, [`${BASE}/api/v1/snapshot`]: (u) => (online ? routes[`${BASE}/api/v1/snapshot`]!(u) : down()) });
    const c = client(fetch, { snapshot: { refreshMs: 0, retryMs: 0 } });
    await c.sync();
    online = false;
    const d = await c.evaluate(dsChain);
    expect([d.decision, d.source]).toEqual(['TRUSTED', 'snapshot']);
  });

  it('without a snapshot nothing is trusted, the reason is visible, and the service is not hammered', async () => {
    const { fetch, calls } = fakeFetch({}, down);
    const c = client(fetch);
    const d = await c.evaluateIssuer({ credentialIssuer: 'https://issuer.example' });
    expect([d.decision, d.source]).toEqual(['UNKNOWN', 'pinned']);
    expect(d.reasons.find((r) => r.code === 'local.pinned')?.severity).toBe('WARNING');
    await c.evaluate(dsChain);
    await c.evaluate(dsChain);
    // One failed refresh; the next is not attempted before the retry interval.
    expect(calls.filter((x) => x.endsWith('/api/v1/snapshot'))).toHaveLength(1);
    expect(await c.status()).toMatchObject({ service: 'offline', snapshot: null, degraded: true, lastSyncError: expect.stringMatching(/unavailable/i) });
  });

  it('refuses a configuration that would accept anything the service signs for anyone', () => {
    const f = fakeFetch({}).fetch;
    expect(() => createTrustClient({ service: { url: BASE, clientId: '', keys: { thumbprints: ['x'] } }, http: { fetch: f } })).toThrow(/clientId is required/);
    expect(() => createTrustClient({ service: { url: BASE, clientId: 'w', keys: {} }, http: { fetch: f } })).toThrow(/keys is required/);
    expect(() => createTrustClient({ service: { url: 'http://trust.example', clientId: 'w', keys: { thumbprints: ['x'] } }, http: { fetch: f } })).toThrow(/https/);
    // Loopback development is an explicit exception.
    expect(() => createTrustClient({ service: { url: 'http://localhost:8090', clientId: 'w', keys: { trustOnFirstUse: true } },
      http: { fetch: f, insecureHosts: ['localhost'] } })).not.toThrow();
  });

  it('rejects snapshots that are not for this client, not from the pinned key, or not readable', async () => {
    const other = es256Key();
    const serve = (jwt: () => string, keys: unknown[] = [serviceJwk]) => client(fakeFetch({
      [`${BASE}/api/v1/snapshot`]: () => new Response(jwt(), { headers: { 'Content-Type': 'application/jwt' } }),
      [`${BASE}/.well-known/jwks.json`]: () => json({ keys }),
    }).fetch);
    await expect(serve(() => snapshotJwt({}, other.privateKey, 'evil'), [{ ...other.jwk, kid: 'evil' }]).sync()).rejects.toBeInstanceOf(TrustIntegrityError);
    await expect(serve(() => snapshotJwt({ aud: 'someone-else' })).sync()).rejects.toThrow(/audience/i);
    await expect(serve(() => snapshotJwt({ format: 3 })).sync()).rejects.toThrow(/format 3/);
    await expect(serve(() => snapshotJwt({ exp: undefined })).sync()).rejects.toThrow(/iat and exp/);
    // Dated in the future, it would outrank every later, correctly dated snapshot.
    await expect(serve(() => snapshotJwt({ iat: seconds() + 3600, exp: seconds() + 7200 })).sync()).rejects.toThrow(/future/);
    const bad = serve(() => snapshotJwt({ aud: 'someone-else' }));
    expect((await bad.evaluate(dsChain)).decision).toBe('UNKNOWN');
    expect((await bad.status()).lastSyncError).toMatch(/audience/i);
  });

  it('never rolls back to an older snapshot, and refuses expired ones', async () => {
    let claims: Record<string, unknown> = { iat: seconds(), entities: [] };
    const c = client(fakeFetch(snapshotRoute(() => claims)).fetch);
    const first = await c.sync();
    claims = { iat: seconds() - 600 };
    expect((await c.sync()).issuedAt).toBe(first.issuedAt);
    expect((await c.sync()).entities).toBe(0);
    claims = { iat: seconds() - 20, exp: seconds() - 10 };
    await expect(c.sync()).rejects.toThrow(/expired/);
    expect((await c.status()).snapshot?.issuedAt).toBe(first.issuedAt);
  });

  it('applies the client policy carried in the snapshot (strict authorization)', async () => {
    const entity = { id: 'open', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [],
      identifiers: [{ type: 'URL', value: 'https://open.example' }], authorizations: [] };
    const q = { credentialIssuer: 'https://open.example', format: 'dc+sd-jwt', type: 'urn:eu.europa.ec.eudi:pid:1' };
    const lenient = client(fakeFetch(snapshotRoute(() => ({ entities: [entity] }))).fetch);
    expect((await lenient.evaluateIssuer(q)).decision).toBe('TRUSTED');
    const strict = client(fakeFetch(snapshotRoute(() => ({ entities: [entity], policy: { frameworks: [], strictAuthorization: true } }))).fetch);
    const d = await strict.evaluateIssuer(q);
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.reasons.map((r) => r.code)).toContain('entity.not_authorized');
  });

  it('marks decisions from an expired snapshot within the grace period, and stops using it after', async () => {
    let online = true;
    let now = Date.now();
    const routes = snapshotRoute();
    const { fetch } = fakeFetch({ ...routes, [`${BASE}/api/v1/snapshot`]: (u) => (online ? routes[`${BASE}/api/v1/snapshot`]!(u) : down()) });
    const c = client(fetch, { clock: () => new Date(now), snapshot: { retryMs: 0, graceMs: 24 * 3600_000 } });
    await c.sync();
    online = false;
    now += 2 * 3600_000;
    const stale = await c.evaluate(dsChain);
    expect(stale.decision).toBe('TRUSTED');
    expect(stale.snapshot?.stale).toBe(true);
    expect(stale.reasons.map((r) => r.code)).toContain('snapshot.stale');
    expect((await c.status()).degraded).toBe(true);
    now += 48 * 3600_000;
    expect((await c.evaluate(dsChain)).decision).toBe('UNKNOWN');
  });

  it('tells a listener when the snapshot in use or the refresh outcome changes, not on every refresh', async () => {
    let online = true;
    let etag = '"one.1"';
    const routes = snapshotRoute();
    const { fetch } = fakeFetch({ ...routes, [`${BASE}/api/v1/snapshot`]: () => (online
      ? new Response(snapshotJwt(), { headers: { 'Content-Type': 'application/jwt', ETag: etag } }) : down()) });
    const c = client(fetch);
    const events: string[] = [];
    c.onStatusChange((e) => events.push(`${e.status}:${e.reason ?? ''}`));
    await c.sync();
    await c.sync();
    expect(events.filter((e) => e.endsWith(':snapshot'))).toHaveLength(1);
    etag = '"two.2"';
    await c.sync();
    expect(events.filter((e) => e.endsWith(':snapshot'))).toHaveLength(2);
    online = false;
    await c.sync().catch(() => undefined);
    await c.sync().catch(() => undefined);
    expect(events.filter((e) => /unavailable|failed/i.test(e)).length).toBeGreaterThanOrEqual(1);
    const failures = events.length;
    online = true;
    await c.sync();
    expect(events.length).toBeGreaterThan(failures);
  });

  it('a stored key set that no longer parses does not stop the client', async () => {
    const storage = new MemoryCacheStore();
    await storage.set('service-keys', '[{"kty":"EC"');
    const c = client(fakeFetch(snapshotRoute()).fetch, { storage });
    expect((await c.evaluate(dsChain)).decision).toBe('TRUSTED');
  });
});

describe('trust pinned in the app', () => {
  const pinned = { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca') }] };

  it('decides when there is no service, and says what it rests on', async () => {
    const c = createTrustClient({ http: { fetch: fakeFetch({}).fetch }, pinned: { anchors: [{ domain: 'verifier-access', certificate: pem('rp-ca') }] } });
    const d = await c.evaluateVerifier({ clientId: 'x509_san_dns:verifier.example', x5c: [b64(pem('rp'))], responseUri: 'https://verifier.example/post' });
    expect([d.decision, d.source]).toEqual(['TRUSTED', 'pinned']);
    const wrongHost = await c.evaluateVerifier({ clientId: 'x509_san_dns:verifier.example', x5c: [b64(pem('rp'))], responseUri: 'https://evil.example/post' });
    expect(wrongHost.decision).toBe('NOT_TRUSTED');
    expect(await c.status()).toMatchObject({ service: 'unconfigured', snapshot: null, degraded: true });
  });

  it('stands in while the service cannot be reached', async () => {
    const d = await client(fakeFetch({}, down).fetch, { pinned }).evaluate(dsChain);
    expect([d.decision, d.source]).toEqual(['TRUSTED', 'pinned']);
  });

  it('never overrides the service: an anchor the snapshot suspends is not trusted because the app also bundles it', async () => {
    const suspended = () => ({ anchors: [{ id: 'a1', domain: 'mdoc-iaca', frameworkId: 'utopia', status: 'SUSPENDED', constraints: {}, certificate: b64(pem('iaca')) }] });
    const d = await client(fakeFetch(snapshotRoute(suspended)).fetch, { pinned }).evaluate(dsChain);
    expect(d.decision).not.toBe('TRUSTED');
    expect(d.source).toBe('snapshot');
  });
});

describe('lookups: the proxy first, the standard mechanism when it cannot serve', () => {
  const ISSUER = 'https://issuer.example/tenant';
  const envelope = { credentialIssuer: ISSUER, credentialIssuerMetadata: { credential_issuer: ISSUER, credential_endpoint: `${ISSUER}/credential` },
    authorizationServers: { [ISSUER]: { issuer: ISSUER, token_endpoint: `${ISSUER}/token` } }, policyApplied: false, fetchedAt: 'x',
    expiresAt: new Date(Date.now() + 600_000).toISOString(), stale: false, warnings: [], trust: { decision: 'TRUSTED' } };
  const issuerRoutes = {
    'https://issuer.example/.well-known/openid-credential-issuer/tenant': () => json({ credential_issuer: ISSUER,
      credential_endpoint: `${ISSUER}/credential`, credential_configurations_supported: {} }),
    'https://issuer.example/.well-known/oauth-authorization-server/tenant': () => json({ issuer: ISSUER, token_endpoint: `${ISSUER}/token` }),
  };
  const proxyPath = `${BASE}/api/v1/proxy/issuer-metadata`;

  it('takes issuer metadata from the proxy, verified with the pinned service key, and decides trust itself', async () => {
    const { fetch, calls } = fakeFetch({ ...snapshotRoute(), ...issuerRoutes, [proxyPath]: () => signedByService('trust-metadata+jwt', envelope) });
    const md = await client(fetch).getIssuerMetadata(ISSUER);
    expect(md.source).toBe('proxy');
    expect(md.authorizationServers[ISSUER]?.token_endpoint).toBe(`${ISSUER}/token`);
    // The proxy's own opinion of the issuer is not taken over: this issuer is in no snapshot.
    expect(md.trust.decision).toBe('UNKNOWN');
    expect(calls.find((x) => x.includes('/proxy/issuer-metadata'))).toContain(`issuer=${encodeURIComponent(ISSUER)}`);
    expect(calls.some((x) => x.startsWith('GET https://issuer.example'))).toBe(false);
  });

  it('falls back to the issuer itself when the proxy is down, declines, or answers with something that does not verify', async () => {
    const other = es256Key();
    const cases: Array<[string, () => Response]> = [
      ['down', down],
      ['declines (issuer not registered)', () => json({ code: 'issuer_not_registered', detail: 'nope', status: 403 }, 403)],
      ['signed by another key', () => signedByService('trust-metadata+jwt', envelope, other.privateKey)],
      ['signed for another client', () => signedByService('trust-metadata+jwt', envelope, serviceKey.privateKey, 'someone-else')],
      ['about another issuer', () => signedByService('trust-metadata+jwt', { ...envelope, credentialIssuer: 'https://other.example' })],
      ['a captive portal page', () => new Response('<html>sign in</html>', { headers: { 'Content-Type': 'text/html' } })],
    ];
    for (const [name, proxy] of cases) {
      const { fetch, calls } = fakeFetch({ ...snapshotRoute(), ...issuerRoutes, [proxyPath]: proxy });
      const md = await client(fetch).getIssuerMetadata(ISSUER);
      expect(md.source, name).toBe('fallback');
      expect(md.credentialIssuerMetadata.credential_endpoint, name).toBe(`${ISSUER}/credential`);
      expect(calls.filter((x) => x.startsWith('GET https://issuer.example')), name).toHaveLength(2);
    }
  });

  it("goes to the issuer only with lookups 'direct', applying the registry's metadata policy", async () => {
    const entity = { id: 'tenant', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [], authorizations: [],
      identifiers: [{ type: 'URL', value: ISSUER }],
      metadataPolicy: { oauth_authorization_server: { token_endpoint: { value: `${ISSUER}/pinned-token` } } } };
    const { fetch, calls } = fakeFetch({ ...snapshotRoute(() => ({ entities: [entity] })), ...issuerRoutes });
    const md = await client(fetch, { lookups: 'direct' }).getIssuerMetadata(ISSUER);
    expect(md.source).toBe('direct');
    expect(md.policyApplied).toBe(true);
    expect(md.authorizationServers[ISSUER]?.token_endpoint).toBe(`${ISSUER}/pinned-token`);
    expect(md.trust.decision).toBe('TRUSTED');
    expect(calls.some((x) => x.includes('/api/v1/proxy/'))).toBe(false);
  });

  it('follows OpenID4VCI 1.0 discovery exactly: one location, an identical credential_issuer, https', async () => {
    const mismatch = fakeFetch({ ...snapshotRoute(),
      'https://issuer.example/.well-known/openid-credential-issuer/tenant': () => json({ credential_issuer: `${ISSUER}/`, credential_endpoint: 'x', credential_configurations_supported: {} }) });
    await expect(client(mismatch.fetch, { lookups: 'direct' }).getIssuerMetadata(ISSUER)).rejects.toThrow(/not identical/);
    const legacy = fakeFetch({ ...snapshotRoute(),
      [`${ISSUER}/.well-known/openid-credential-issuer`]: () => json({ credential_issuer: ISSUER, credential_endpoint: 'x', credential_configurations_supported: {} }) });
    await expect(client(legacy.fetch, { lookups: 'direct' }).getIssuerMetadata(ISSUER)).rejects.toThrow(/No OpenID4VCI metadata/);
    await expect(client(fakeFetch(snapshotRoute()).fetch).getIssuerMetadata('http://issuer.example')).rejects.toThrow(/https/);
  });

  it('serves the last metadata it had when neither the proxy nor the issuer answers', async () => {
    let online = true;
    let now = Date.now();
    const { fetch } = fakeFetch({ ...snapshotRoute(), [proxyPath]: () => (online ? signedByService('trust-metadata+jwt', envelope) : down()) }, down);
    const c = client(fetch, { clock: () => new Date(now) });
    expect((await c.getIssuerMetadata(ISSUER)).source).toBe('proxy');
    online = false;
    expect((await c.getIssuerMetadata(ISSUER)).source).toBe('cache');
    now += 2 * 3600_000;
    expect(await c.getIssuerMetadata(ISSUER)).toMatchObject({ source: 'cache', stale: true });
  });

  it('asks the service about unknown parties only when enabled, and verifies the signed answer', async () => {
    const found = [{ id: 'fed-issuer', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [], authorizations: [],
      identifiers: [{ type: 'URL', value: 'https://fed.example' }] }];
    let signer = serviceKey.privateKey;
    const routes = { ...snapshotRoute(), [`${BASE}/api/v1/entities/lookup`]: () => signedByService('trust-registry+jwt', found, signer) };
    const off = fakeFetch(routes);
    expect((await client(off.fetch).evaluateIssuer({ credentialIssuer: 'https://fed.example' })).decision).toBe('UNKNOWN');
    expect(off.calls.some((x) => x.includes('/entities/lookup'))).toBe(false);

    const on = fakeFetch(routes);
    const d = await client(on.fetch, { lookups: { unknownParties: true } }).evaluateIssuer({ credentialIssuer: 'https://fed.example' });
    expect(d.decision).toBe('TRUSTED');
    expect(d.reasons.map((r) => r.code)).toContain('lookup.on_demand');
    expect(on.calls.find((x) => x.includes('/entities/lookup'))).toContain('onDemand=true');
    expect(on.calls.find((x) => x.includes('/entities/lookup'))).toContain('type=URL');

    // A genuine signed answer about fed.example, replayed for another identifier, does not vouch for that one.
    const replayed = await client(fakeFetch(routes).fetch, { lookups: { unknownParties: true } }).evaluateIssuer({ credentialIssuer: 'https://attacker.example' });
    expect(replayed.decision).toBe('UNKNOWN');
    expect(replayed.entity).toBeNull();

    signer = es256Key().privateKey;
    const forged = await client(fakeFetch(routes).fetch, { lookups: { unknownParties: true } }).evaluateIssuer({ credentialIssuer: 'https://fed.example' });
    expect(forged.decision).toBe('UNKNOWN');
  });
});

describe('authorization servers under signed issuer metadata', () => {
  // The rp certificate's SAN is verifier.example, so it may sign this issuer's metadata; rp-ca is its anchor.
  const ISSUER = 'https://verifier.example';
  const AS1 = 'https://as.verifier.example';
  const AS2 = 'https://as2.verifier.example';
  const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const wellKnown = (as: string) => `${as}/.well-known/oauth-authorization-server`;
  const signedBy = (servers: string[]) => signJwt({ alg: 'ES256', typ: 'openidvci-issuer-metadata+jwt', x5c: [b64(pem('rp'))] },
    { credential_issuer: ISSUER, sub: ISSUER, iat: seconds(), credential_endpoint: `${ISSUER}/credential`, credential_configurations_supported: {},
      authorization_servers: servers }, createPrivateKey(fixture('pki/rp.key')));
  // The registry lists the issuer with a policy for its authorization servers; the service applies it to what it relays.
  const policy = { oauth_authorization_server: { grant_types_supported: { add: [PRE_AUTH] } } };
  const snapshot = snapshotRoute(() => ({
    entities: [{ id: 'verifier-inc', frameworkId: 'utopia', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [], authorizations: [],
      identifiers: [{ type: 'URL', value: ISSUER }], metadataPolicy: policy }],
    anchors: [{ id: 'rp-ca', domain: 'credential-issuer', frameworkId: 'utopia', status: 'ACTIVE', constraints: {}, certificate: b64(pem('rp-ca')) }],
  }));
  const envelope = (servers: string[], relayed: Record<string, Record<string, unknown>>) => ({
    credentialIssuer: ISSUER, credentialIssuerMetadata: { credential_issuer: ISSUER }, authorizationServers: relayed, signedMetadata: signedBy(servers),
    signedMetadataVerified: true, policyApplied: true, fetchedAt: 'x', expiresAt: new Date(Date.now() + 600_000).toISOString(), stale: false, warnings: [],
    trust: { decision: 'TRUSTED' } });
  const relayedCopy = (as: string, issuer = as) => ({ issuer, token_endpoint: `${as}/relayed-token`, grant_types_supported: ['authorization_code', PRE_AUTH] });
  const own = (as: string) => () => json({ issuer: as, token_endpoint: `${as}/own-token`, grant_types_supported: ['authorization_code'] });
  const serve = (env: ReturnType<typeof envelope>) => fakeFetch({ ...snapshot, [`${BASE}/api/v1/proxy/issuer-metadata`]: () => signedByService('trust-metadata+jwt', env),
    [wellKnown(AS1)]: own(AS1), [wellKnown(AS2)]: own(AS2) });
  const asked = (calls: string[], as: string) => calls.filter((x) => x === `GET ${wellKnown(as)}`).length;

  it('takes a server the envelope carries from the envelope, without a request to the server', async () => {
    const { fetch, calls } = serve(envelope([AS1], { [AS1]: relayedCopy(AS1) }));
    const md = await client(fetch, { issuerMetadata: { signed: 'verify' } }).getIssuerMetadata(ISSUER);
    expect([md.source, md.signedMetadataVerified]).toEqual(['proxy', true]);
    // The registry's policy is applied as before: once more on the copy the service applied it to, with the same result.
    expect(md.authorizationServers).toEqual({ [AS1]: relayedCopy(AS1) });
    expect(asked(calls, AS1)).toBe(0);
    // A copy the policy was not applied to (a service that has not seen the registry's change yet) gets it here.
    const unpoliced = serve(envelope([AS1], { [AS1]: { ...relayedCopy(AS1), grant_types_supported: ['authorization_code'] } }));
    const applied = await client(unpoliced.fetch, { issuerMetadata: { signed: 'verify' } }).getIssuerMetadata(ISSUER);
    expect(applied.authorizationServers[AS1]).toEqual(relayedCopy(AS1));
    expect(asked(unpoliced.calls, AS1)).toBe(0);
  });

  it('asks a server the envelope does not carry itself, and applies the policy to that copy too', async () => {
    const { fetch, calls } = serve(envelope([AS1, AS2], { [AS1]: relayedCopy(AS1) }));
    const md = await client(fetch, { issuerMetadata: { signed: 'verify' } }).getIssuerMetadata(ISSUER);
    expect(md.authorizationServers[AS1]).toEqual(relayedCopy(AS1));
    expect(md.authorizationServers[AS2]).toEqual({ issuer: AS2, token_endpoint: `${AS2}/own-token`, grant_types_supported: ['authorization_code', PRE_AUTH] });
    expect([asked(calls, AS1), asked(calls, AS2)]).toEqual([0, 1]);
    // Only the servers the signed metadata names: an entry the envelope has for another one is not taken over.
    const extra = serve(envelope([AS1], { [AS1]: relayedCopy(AS1), [AS2]: relayedCopy(AS2) }));
    expect(Object.keys((await client(extra.fetch, { issuerMetadata: { signed: 'verify' } }).getIssuerMetadata(ISSUER)).authorizationServers)).toEqual([AS1]);
  });

  it("does not take an entry whose issuer is another server's: the server named is asked itself", async () => {
    for (const entry of [relayedCopy(AS1, AS2), relayedCopy(AS1, `${AS1}/`), { ...relayedCopy(AS1), issuer: undefined }]) {
      const { fetch, calls } = serve(envelope([AS1], { [AS1]: entry as Record<string, unknown> }));
      const md = await client(fetch, { issuerMetadata: { signed: 'verify' } }).getIssuerMetadata(ISSUER);
      expect(md.source).toBe('proxy');
      expect(md.authorizationServers[AS1]?.token_endpoint, String(entry.issuer)).toBe(`${AS1}/own-token`);
      expect(asked(calls, AS1)).toBe(1);
    }
  });

  it('holds a relayed server to the https rule a direct fetch is held to', async () => {
    const plain = 'http://as.verifier.example';
    const { fetch, calls } = fakeFetch({ ...snapshot,
      [`${BASE}/api/v1/proxy/issuer-metadata`]: () => signedByService('trust-metadata+jwt', envelope([plain], { [plain]: relayedCopy(plain) })),
      [`${ISSUER}/.well-known/openid-credential-issuer`]: () => new Response(signedBy([plain]), { headers: { 'Content-Type': 'application/jwt' } }) });
    const md = await client(fetch, { issuerMetadata: { signed: 'verify' } }).getIssuerMetadata(ISSUER);
    // The relayed answer does not count; discovery at the issuer reports the server and does not reach it.
    expect(md.source).toBe('fallback');
    expect(md.authorizationServers).toEqual({});
    expect(md.warnings.join()).toMatch(/Authorization server http:\/\/as\.verifier\.example: .*must be an https URL/);
    expect(calls.some((x) => x.startsWith(`GET ${plain}`))).toBe(false);
  });
});

describe('DID documents', () => {
  const DID = 'did:web:issuer.example';
  const doc = (keys: string[]) => ({ id: DID, verificationMethod: keys.map((k) => ({ id: `${DID}#${k}`, type: 'JsonWebKey2020', controller: DID,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } })), assertionMethod: keys.map((k) => `${DID}#${k}`) });

  it('computes did:key and did:jwk on the device', async () => {
    const { fetch, calls } = fakeFetch({}, down);
    const r = await client(fetch).resolveDid(didKey);
    expect(r.didDocument?.id).toBe(didKey);
    expect(calls.some((x) => x.includes('did'))).toBe(false);
  });

  it('for a listed DID the snapshot is the resolver: a key it lacks is looked for in a fresh snapshot, never at the host', async () => {
    let keys = ['key-1'];
    const { fetch, calls } = fakeFetch({ ...snapshotRoute(() => ({ didDocuments: { [DID]: doc(keys) } })),
      'https://issuer.example/.well-known/did.json': () => json(doc(['key-1', 'attacker-key'])) });
    const c = client(fetch);
    expect((await c.resolveDid(`${DID}#key-1`)).didResolutionMetadata.source).toBe('snapshot');
    // A key only the host's did.json has is not the listed party's as far as the service knows.
    const unknown = await c.resolveDid(`${DID}#attacker-key`);
    expect(unknown.didResolutionMetadata.source).toBe('snapshot');
    expect(unknown.didDocument?.verificationMethod?.map((v) => v.id)).toEqual([`${DID}#key-1`]);
    expect(calls.some((x) => x.includes('did.json') || x.includes('/proxy/did/'))).toBe(false);
    expect(calls.filter((x) => x.endsWith('/api/v1/snapshot'))).toHaveLength(2);
  });

  it('a rotated key appears with the next snapshot', async () => {
    let keys = ['key-1'];
    let now = Date.now();
    const c = client(fakeFetch(snapshotRoute(() => ({ didDocuments: { [DID]: doc(keys) }, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 3600 }))).fetch,
      { clock: () => new Date(now) });
    await c.sync();
    keys = ['key-1', 'key-2'];
    now += 61_000;
    const rotated = await c.resolveDid(`${DID}#key-2`);
    expect(rotated.didDocument?.verificationMethod?.map((v) => v.id)).toContain(`${DID}#key-2`);
  });

  it('resolves a DID the snapshot does not carry through the proxy, and at its host when the proxy cannot', async () => {
    const result = { didDocument: doc(['key-1']), didDocumentMetadata: {}, didResolutionMetadata: { contentType: 'application/did+ld+json' } };
    const proxied = fakeFetch({ ...snapshotRoute(), [`${BASE}/api/v1/proxy/did/`]: () => signedByService('trust-did-resolution+jwt', result) }, down);
    expect((await client(proxied.fetch).resolveDid(DID)).didResolutionMetadata.source).toBe('proxy');
    const other = fakeFetch({ ...snapshotRoute(), 'https://issuer.example/.well-known/did.json': () => json(doc(['key-1'])),
      [`${BASE}/api/v1/proxy/did/`]: () => signedByService('trust-did-resolution+jwt', { ...result, didDocument: { ...doc(['key-1']), id: 'did:web:other.example' } }) });
    expect((await client(other.fetch).resolveDid(DID)).didResolutionMetadata.source).toBe('fallback');
    const offline = fakeFetch({ ...snapshotRoute(), 'https://issuer.example/.well-known/did.json': () => json(doc(['key-1'])), [`${BASE}/api/v1/proxy/did/`]: down });
    const r = await client(offline.fetch).resolveDid(DID);
    expect([r.didResolutionMetadata.source, r.didDocument?.id]).toEqual(['fallback', DID]);
  });
});

describe('JSON-LD contexts', () => {
  const URL_ = 'https://issuer.example/contexts/degree/v1';
  const document = { '@context': { degree: 'https://vocab.example/degree' } };
  const bytes = new TextEncoder().encode(JSON.stringify(document));
  const digest = async () => Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString('base64url');

  it('come from the snapshot, without a request to their host', async () => {
    const sha256 = await digest();
    const { fetch, calls } = fakeFetch(snapshotRoute(() => ({ contexts: { [URL_]: { sha256, document } } })));
    expect(await client(fetch).context(URL_)).toEqual({ document, sha256, source: 'snapshot', vouched: true });
    expect(calls.some((x) => x.includes('issuer.example'))).toBe(false);
  });

  const ld = (body: Uint8Array<ArrayBuffer> | string) => new Response(body, { headers: { 'Content-Type': 'application/ld+json' } });
  const relay = `${BASE}/api/v1/proxy/context`;
  /** A snapshot that knows the context by its digest only. */
  const knownByDigest = async () => {
    const sha256 = await digest();
    return snapshotRoute(() => ({ contexts: { [URL_]: { sha256 } } }));
  };
  const toHost = (calls: string[]) => calls.filter((x) => x.startsWith(`GET ${URL_}`));
  const toRelay = (calls: string[]) => calls.filter((x) => x.startsWith(`GET ${relay}`));

  it("fetched from the host with lookups 'direct', must match the digest the snapshot carries", async () => {
    const sha256 = await digest();
    const host = { [URL_]: () => ld(bytes) };
    const { fetch, calls } = fakeFetch({ ...snapshotRoute(() => ({ contexts: { [URL_]: { sha256 } } })), ...host, [relay]: () => ld(bytes) });
    const ok = await client(fetch, { lookups: { contexts: 'direct' } }).context(URL_);
    expect(ok).toMatchObject({ source: 'direct', vouched: true, sha256 });
    expect(toRelay(calls)).toEqual([]);
    const swapped = client(fakeFetch({ ...snapshotRoute(() => ({ contexts: { [URL_]: { sha256: 'another-digest' } } })), ...host }).fetch,
      { lookups: { contexts: 'direct' } });
    await expect(swapped.context(URL_)).rejects.toBeInstanceOf(TrustIntegrityError);
  });

  it("one the snapshot does not know is returned as not vouched for (lookups 'direct')", async () => {
    const { fetch, calls } = fakeFetch({ ...snapshotRoute(), [URL_]: () => ld(bytes), [relay]: () => ld(bytes) });
    expect(await client(fetch, { lookups: 'direct' }).context(URL_)).toMatchObject({ source: 'direct', vouched: false });
    expect(calls.some((x) => x.includes('/api/v1/proxy/'))).toBe(false);
    await expect(client(fetch).context('http://issuer.example/contexts/v1')).rejects.toThrow(/https/);
  });

  it('go through the relay first, never to their host while it serves; vouched only with the digest of the snapshot', async () => {
    // The snapshot knows the digest: the relayed bytes are held to it.
    const known = fakeFetch({ ...(await knownByDigest()), [relay]: () => ld(bytes), [URL_]: () => ld(bytes) });
    const c = client(known.fetch);
    expect(await c.context(URL_)).toEqual({ document, sha256: await digest(), source: 'proxy', vouched: true });
    expect(toRelay(known.calls)).toEqual([`GET ${relay}?url=${encodeURIComponent(URL_)}`]);
    expect(toHost(known.calls)).toEqual([]);
    expect(await c.context(URL_)).toMatchObject({ source: 'cache', vouched: true });
    expect(toRelay(known.calls)).toHaveLength(1);

    // The snapshot does not know it: relayed all the same, and not vouched for, from the relay or the cache.
    const unknown = fakeFetch({ ...snapshotRoute(), [relay]: () => ld(bytes), [URL_]: () => ld(bytes) });
    const u = client(unknown.fetch);
    expect(await u.context(URL_)).toEqual({ document, sha256: await digest(), source: 'proxy', vouched: false });
    expect(await u.context(URL_)).toMatchObject({ source: 'cache', vouched: false });
    expect(toHost(unknown.calls)).toEqual([]);
  });

  it('are fetched from their URL when the relay cannot serve, or answers with something that does not count', async () => {
    const other = new TextEncoder().encode(JSON.stringify({ '@context': { degree: 'https://evil.example/degree' } }));
    // [case, the relay's answer, whether the snapshot knows the digest]. The shape and size cases are asked about a
    // context the snapshot does not know, so that nothing but the rule under test can refuse them.
    const cases: Array<[string, () => Response, boolean]> = [
      ['down', down, true],
      ['down, not known', down, false],
      ['switched off', () => json({ code: 'not_found', detail: 'The JSON-LD context relay is disabled', status: 404 }, 404), true],
      ['the host failed it', () => json({ code: 'upstream_unavailable', detail: 'unavailable', status: 502 }, 502), true],
      ['another document than the snapshot vouches for', () => ld(other), true],
      ['not a context', () => ld(JSON.stringify({ internal: true })), false],
      ['a list', () => ld(JSON.stringify([{ '@context': {} }])), false],
      ['not JSON', () => ld('<html>sign in</html>'), false],
      ['larger than a context may be', () => ld(JSON.stringify({ '@context': {}, pad: 'x'.repeat(1024 * 1024) })), false],
    ];
    for (const [name, answer, known] of cases) {
      const { fetch, calls } = fakeFetch({ ...(known ? await knownByDigest() : snapshotRoute()), [relay]: answer, [URL_]: () => ld(bytes) });
      expect(await client(fetch).context(URL_), name).toEqual({ document, sha256: await digest(), source: 'fallback', vouched: known });
      expect(toRelay(calls), name).toHaveLength(1);
      expect(toHost(calls), name).toHaveLength(1);
    }
  });

  it('fail with the integrity error when the relay and the host both have another document than the snapshot vouches for', async () => {
    const other = new TextEncoder().encode(JSON.stringify({ '@context': { degree: 'https://evil.example/degree' } }));
    const { fetch, calls } = fakeFetch({ ...(await knownByDigest()), [relay]: () => ld(other), [URL_]: () => ld(other) });
    const c = client(fetch);
    await expect(c.context(URL_)).rejects.toBeInstanceOf(TrustIntegrityError);
    expect([toRelay(calls).length, toHost(calls).length]).toEqual([1, 1]);
    // Nothing of it was kept: a later lookup asks again.
    await expect(c.context(URL_)).rejects.toBeInstanceOf(TrustIntegrityError);
  });

  it('without a service go to their URL', async () => {
    const { fetch, calls } = fakeFetch({ [URL_]: () => ld(bytes) });
    const c = createTrustClient({ http: { fetch, retries: 0 } });
    expect(c.lookups.contexts).toBe('direct');
    expect(await c.context(URL_)).toMatchObject({ source: 'direct', vouched: false });
    expect(calls).toEqual([`GET ${URL_}`]);
  });
});

describe('revocation', () => {
  const crl = new Uint8Array(fixture('pki/iaca.crl'));
  const CRL_URL = 'http://crl.utopia.example/iaca.crl';
  const issued = (name: string) => ({ role: 'issuer' as const, subject: { x5c: [b64(pem(name))] }, context: mdl });
  const withCrl = () => ({ crls: [{ issuer: 'iaca', crl: Buffer.from(crl).toString('base64'), thisUpdate: 'x' }] });
  const crlRoute = (calls: { n: number }) => ({ [CRL_URL]: () => { calls.n++; return new Response(crl, { headers: { 'Content-Type': 'application/pkix-crl' } }); } });
  const proxyCrl = `${BASE}/api/v1/proxy/crl`;

  it('checks certificates against the anchor CRLs carried in the snapshot, without any other request', async () => {
    const { fetch, calls } = fakeFetch(snapshotRoute(withCrl));
    const c = client(fetch);
    const ok = await c.evaluate(issued('ds'));
    expect(ok.decision).toBe('TRUSTED');
    expect(ok.evidence?.x509?.revocation).toEqual([expect.objectContaining({ status: 'GOOD', source: 'snapshot' })]);
    const revoked = await c.evaluate(issued('ds-revoked'));
    expect(revoked.decision).toBe('NOT_TRUSTED');
    expect(revoked.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revoked');
    expect((await c.evaluate(issued('ds-hold'))).reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.on_hold');
    expect(new Set(calls.map((x) => x.split('?')[0]))).toEqual(new Set([`GET ${BASE}/api/v1/snapshot`, `GET ${BASE}/.well-known/jwks.json`]));
    expect((await c.status()).snapshot?.crls).toBe(1);
  });

  it('gets a CRL the snapshot lacks through the proxy, verifies it against its CA, and caches it', async () => {
    const proxy = fakeFetch({ ...snapshotRoute(), [proxyCrl]: () => new Response(crl, { headers: { 'Content-Type': 'application/pkix-crl' } }) });
    const c = client(proxy.fetch);
    const d = await c.evaluate(issued('ds-revoked'));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', source: 'proxy', crlUrl: CRL_URL });
    expect(proxy.calls.find((x) => x.includes('/proxy/crl'))).toContain(encodeURIComponent(CRL_URL));
    expect((await c.evaluate(issued('ds-crldp'))).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'GOOD', source: 'cache' });
    expect(proxy.calls.filter((x) => x.includes('/proxy/crl'))).toHaveLength(1);
    // A certificate without a distribution point under an anchor without a CRL: unknown, a warning only.
    const plain = await c.evaluate(issued('ds'));
    expect(plain.decision).toBe('TRUSTED');
    expect(plain.reasons.find((r) => r.code === 'x509.revocation_unknown')).toMatchObject({ severity: 'WARNING' });
  });

  it("gets it from the distribution point when the proxy cannot serve, or with lookups 'direct'; not at all with 'none'", async () => {
    const n = { n: 0 };
    const fallback = await client(fakeFetch({ ...snapshotRoute(), ...crlRoute(n), [proxyCrl]: down }).fetch).evaluate(issued('ds-revoked'));
    expect(fallback.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', source: 'fallback' });
    const direct = fakeFetch({ ...snapshotRoute(), ...crlRoute(n) });
    expect((await client(direct.fetch, { lookups: 'direct' }).evaluate(issued('ds-revoked'))).evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', source: 'direct' });
    expect(direct.calls.some((x) => x.includes('/api/v1/proxy/'))).toBe(false);
    expect(n.n).toBe(2);
    const none = await client(fakeFetch({ ...snapshotRoute(), ...crlRoute(n) }).fetch, { lookups: { crl: 'none' } }).evaluate(issued('ds-revoked'));
    expect(none.decision).toBe('TRUSTED');
    expect(none.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'UNKNOWN', reason: 'CRL unavailable: CRL downloads are disabled on this device' });
    expect(n.n).toBe(2);
  });

  it('applies the policy that requires a revocation status', async () => {
    const strict = () => ({ policy: { frameworks: [], strictAuthorization: false, requireRevocationStatus: true } });
    const c = client(fakeFetch(snapshotRoute(strict)).fetch);
    const d = await c.evaluate(issued('ds-ocsp'));
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.reasons.find((r) => r.severity === 'ERROR')).toMatchObject({ code: 'x509.revocation_unknown', message: expect.stringMatching(/only OCSP/) });
    expect((await c.status()).snapshot?.requireRevocationStatus).toBe(true);
  });
});

describe('which URLs are fetched', () => {
  const dev = (routes: Record<string, (url: string) => Response> = {}) => {
    const f = fakeFetch(routes, down);
    return { c: createTrustClient({ http: { fetch: f.fetch, insecureHosts: ['localhost'], retries: 0 } }), calls: f.calls };
  };

  it('reads the host of a URL strictly: userinfo does not make another host an allowed one', async () => {
    const { c, calls } = dev();
    for (const url of ['http://localhost@evil.example/ctx', 'http://localhost:80@evil.example/ctx', 'http://localhost\\@evil.example/ctx', 'http://evil.example/ctx',
      'http://localhost.evil.example/ctx', 'ftp://localhost/ctx', '//localhost/ctx']) {
      await expect(c.context(url), url).rejects.toThrow(/must be an https URL/);
      await expect(c.getIssuerMetadata(url), url).rejects.toThrow(/must be an https URL/);
    }
    expect(calls).toEqual([]);
    expect(isSecureUrl('http://localhost:8791/x', ['localhost'])).toBe(true);
    expect(isSecureUrl('https://issuer.example/x')).toBe(true);
    expect(isSecureUrl('https://user@issuer.example/x')).toBe(false);
  });

  it('holds the authorization servers an issuer names to the same rule', async () => {
    const ISSUER = 'https://issuer.example';
    const { c, calls } = dev({ [`${ISSUER}/.well-known/openid-credential-issuer`]: () => json({ credential_issuer: ISSUER, credential_endpoint: `${ISSUER}/c`,
      credential_configurations_supported: {}, authorization_servers: ['http://as.internal:8080/tenant'] }) });
    const md = await c.getIssuerMetadata(ISSUER);
    expect(md.authorizationServers).toEqual({});
    expect(md.warnings.join()).toMatch(/Authorization server http:\/\/as\.internal:8080\/tenant: .*must be an https URL/);
    expect(calls.some((x) => x.includes('as.internal'))).toBe(false);
  });

  it('reads a did:web host as a host and nothing else', async () => {
    const { c, calls } = dev();
    for (const did of ['did:web:localhost%40evil.example', 'did:web:evil.example%2Fpath', 'did:web:issuer.example:..:secret', 'did:web:issuer.example:a%2Fb']) {
      const r = await c.resolveDid(did);
      expect(r.didDocument, did).toBeNull();
    }
    expect(calls).toEqual([]);
  });

  it('does not follow a redirect from https to plain http', async () => {
    const f = (async () => Object.defineProperty(new Response('{}', { headers: { 'Content-Type': 'application/json' } }), 'url', { value: 'http://elsewhere.example/ctx' })) as unknown as typeof fetch;
    const c = createTrustClient({ http: { fetch: f, retries: 0 } });
    await expect(c.context('https://issuer.example/contexts/v1')).rejects.toThrow(/redirected to a location that is not https/);
  });
});
