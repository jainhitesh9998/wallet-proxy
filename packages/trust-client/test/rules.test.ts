/**
 * The rules outlive the data: a strict client profile stays in force when no snapshot is usable, and an app can state
 * its own minimum. Each rule in force is the stricter of the app's minimum and the client profile of the most recent
 * snapshot that verified; data that does not verify states no rule; nothing of an unusable snapshot but its rules is used.
 */
import { describe, expect, it } from 'vitest';
import { createTrustClient, MemoryCacheStore, type CacheStore, type TrustClientConfig, type TrustDecision, type TrustQuery } from '../src/index.js';
import { jwkThumbprint } from '../src/primitives.js';
import { b64, down, es256Key, fakeFetch, json, pem, signJwt } from './helpers.js';

const BASE = 'https://trust.example';
const HOUR = 3600_000;
const GRACE = 24 * HOUR;
const serviceKey = es256Key();
const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };

const LENIENT = { frameworks: ['utopia'], strictAuthorization: false, requireRevocationStatus: false, requireSignedIssuerMetadata: false };
const STRICT_REVOCATION = { ...LENIENT, requireRevocationStatus: true };
const IACA_ANCHOR = { id: 'a1', domain: 'mdoc-iaca', frameworkId: 'utopia', status: 'ACTIVE', constraints: {}, certificate: b64(pem('iaca')) };

const mdl = { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' };
/** A Document Signer with no distribution point, and one whose distribution point does not answer: no status can be had for either. */
const ds: TrustQuery = { role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: mdl };
const dsRevoked: TrustQuery = { role: 'issuer', subject: { x5c: [b64(pem('ds-revoked'))] }, context: mdl };

/** An issuer listed only in the app, with no authorizations: who it may issue for is a question of strictAuthorization. */
const OPEN = 'https://open.example';
const openEntity = { id: 'open', frameworkId: 'app', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [], authorizations: [],
  identifiers: [{ type: 'URL', value: OPEN }] };
const openQuery = { credentialIssuer: OPEN, format: 'dc+sd-jwt', type: 'urn:eu.europa.ec.eudi:pid:1' };

/** An issuer that serves only unsigned (JSON) metadata. */
const ISSUER = 'https://issuer.example';
const issuerMetadata = { credential_issuer: ISSUER, credential_endpoint: `${ISSUER}/credential`, credential_configurations_supported: {} };

const severity = (d: TrustDecision, code: string) => d.reasons.find((r) => r.code === code)?.severity;

/**
 * A service that signs snapshots stating {@code policy} (and listing {@code anchors}), and that can go away; a clock the
 * test moves; one storage that every client of the world shares, as an app does across restarts.
 */
function world(policy: Record<string, unknown>, opts: { anchors?: unknown[]; storage?: CacheStore } = {}) {
  const w = { online: true, now: Date.now(), policy, anchors: opts.anchors ?? [], storage: opts.storage ?? new MemoryCacheStore() };
  const snapshot = (claims: Record<string, unknown> = {}) => {
    const iat = Math.floor(w.now / 1000);
    return signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: 'svc-1' }, { iss: BASE, aud: 'wallet-1', iat, exp: iat + 3600, format: 4,
      policy: w.policy, frameworks: [{ id: 'utopia', name: 'Utopia' }], entities: [], anchors: w.anchors, ...claims }, serviceKey.privateKey);
  };
  const { fetch, calls } = fakeFetch({
    [`${BASE}/api/v1/snapshot`]: () => (w.online ? new Response(snapshot(), { headers: { 'Content-Type': 'application/jwt' } }) : down()),
    [`${BASE}/.well-known/jwks.json`]: () => (w.online ? json({ keys: [serviceJwk] }) : down()),
    [`${ISSUER}/.well-known/openid-credential-issuer`]: () => json(issuerMetadata),
    [`${ISSUER}/.well-known/oauth-authorization-server`]: () => json({ issuer: ISSUER, token_endpoint: `${ISSUER}/token` }),
  }, down);
  const client = (extra: Partial<TrustClientConfig> = {}) => createTrustClient({
    service: { url: BASE, clientId: 'wallet-1', keys: { thumbprints: [jwkThumbprint(serviceJwk)] } },
    pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca') }], entities: [openEntity as never] },
    storage: w.storage, clock: () => new Date(w.now), snapshot: { graceMs: GRACE, retryMs: 0 },
    ...extra, http: { fetch, retries: 0, timeoutMs: 500 } });
  /** The service goes away, and the snapshot held runs past its expiry and its grace period. */
  const lapse = () => { w.online = false; w.now += HOUR + GRACE + 60_000; };
  return { w, client, lapse, calls, snapshot };
}

describe("the app's own minimum", () => {
  it('holds with no snapshot ever: an unknown revocation status under a pinned anchor is an error', async () => {
    const { w, client } = world(LENIENT);
    w.online = false;
    for (const q of [ds, dsRevoked]) {
      // As before: without the option, pinned trust accepts a signer whose status cannot be had, with a warning.
      const lenient = await client().evaluate(q);
      expect([lenient.decision, lenient.source]).toEqual(['TRUSTED', 'pinned']);
      expect(severity(lenient, 'x509.revocation_unknown')).toBe('WARNING');

      const strict = await client({ policy: { requireRevocationStatus: true } }).evaluate(q);
      expect([strict.decision, strict.source, strict.snapshot]).toEqual(['NOT_TRUSTED', 'pinned', null]);
      expect(strict.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revocation_unknown');
      expect(severity(strict, 'local.pinned')).toBe('WARNING');
    }
    const c = client({ policy: { requireRevocationStatus: true } });
    expect((await c.status()).rules).toEqual({ requireRevocationStatus: true, strictAuthorization: false, requireSignedIssuerMetadata: false });
  });

  it('is not relaxed by a lenient snapshot, in use or no longer usable', async () => {
    const { client, lapse } = world(LENIENT, { anchors: [IACA_ANCHOR] });
    const c = client({ policy: { requireRevocationStatus: true } });
    const inUse = await c.evaluate(ds);
    expect([inUse.decision, inUse.source]).toEqual(['NOT_TRUSTED', 'snapshot']);
    expect(inUse.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revocation_unknown');
    expect((await c.status()).rules?.requireRevocationStatus).toBe(true);
    // The same snapshot without the app's minimum: as the service decides for this profile.
    expect((await client().evaluate(ds)).decision).toBe('TRUSTED');

    lapse();
    const held = await c.evaluate(ds);
    expect([held.decision, held.source]).toEqual(['NOT_TRUSTED', 'pinned']);
    expect(held.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revocation_unknown');
  });

  it('refuses a rule it does not know, and a value that is not true or false', () => {
    const f = fakeFetch({}).fetch;
    expect(() => createTrustClient({ http: { fetch: f }, policy: { requireRevocation: true } as never })).toThrow(/Unknown rule policy\.requireRevocation/);
    expect(() => createTrustClient({ http: { fetch: f }, policy: { strictAuthorization: 'yes' } as never })).toThrow(/must be true or false/);
    expect(() => createTrustClient({ http: { fetch: f }, policy: ['requireRevocationStatus'] as never })).toThrow(/must be an object/);
    expect(() => createTrustClient({ http: { fetch: f }, policy: { requireRevocationStatus: false } })).not.toThrow();
  });
});

describe("the service's last word is remembered", () => {
  it('a strict profile stays in force once its snapshot is past expiry and grace, also for a new client on the same storage', async () => {
    const { client, lapse } = world(STRICT_REVOCATION, { anchors: [IACA_ANCHOR] });
    const c = client();
    const inUse = await c.evaluate(ds);
    expect([inUse.decision, inUse.source]).toEqual(['NOT_TRUSTED', 'snapshot']);

    lapse();
    for (const [name, k] of [['the same client', c], ['a new client', client()]] as const) {
      const d = await k.evaluate(ds);
      expect([d.decision, d.source, d.snapshot], name).toEqual(['NOT_TRUSTED', 'pinned', null]);
      expect(d.reasons.find((r) => r.severity === 'ERROR'), name).toMatchObject({ code: 'x509.revocation_unknown' });
      expect(severity(d, 'local.pinned'), name).toBe('WARNING');
      expect(await k.status(), name).toMatchObject({ snapshot: null, degraded: true, rules: { requireRevocationStatus: true } });
    }
  });

  it('remembering the rules does not make the expired snapshot\'s data usable again', async () => {
    // The snapshot lists a verifier CA the app does not pin: once the snapshot is unusable, that CA vouches for nobody.
    const rpAnchor = { id: 'rp', domain: 'verifier-access', frameworkId: 'utopia', status: 'ACTIVE', constraints: {}, certificate: b64(pem('rp-ca')) };
    const { client, lapse } = world(LENIENT, { anchors: [IACA_ANCHOR, rpAnchor] });
    const c = client();
    const verifier = { clientId: 'x509_san_dns:verifier.example', x5c: [b64(pem('rp'))], responseUri: 'https://verifier.example/response' };
    const inUse = await c.evaluateVerifier(verifier);
    expect([inUse.decision, inUse.source]).toEqual(['TRUSTED', 'snapshot']);
    lapse();
    const d = await client().evaluateVerifier(verifier);
    expect([d.decision, d.source]).toEqual(['UNKNOWN', 'pinned']);
    expect(d.reasons.map((r) => r.code)).toContain('x509.no_anchor');
  });

  it('a strict snapshot in use is strict without any option, as before', async () => {
    const { client } = world(STRICT_REVOCATION, { anchors: [IACA_ANCHOR] });
    const c = client();
    const d = await c.evaluate(ds);
    expect([d.decision, d.source]).toEqual(['NOT_TRUSTED', 'snapshot']);
    expect((await c.status()).rules).toEqual({ requireRevocationStatus: true, strictAuthorization: false, requireSignedIssuerMetadata: false });
  });

  it('a lenient snapshot held, then past its grace: lenient without the option, strict with it', async () => {
    const { client, lapse } = world(LENIENT, { anchors: [IACA_ANCHOR] });
    await client().sync();
    lapse();
    const lenient = await client().evaluate(ds);
    expect([lenient.decision, lenient.source]).toEqual(['TRUSTED', 'pinned']);
    expect(severity(lenient, 'x509.revocation_unknown')).toBe('WARNING');
    const strict = await client({ policy: { requireRevocationStatus: true } }).evaluate(ds);
    expect([strict.decision, strict.source]).toEqual(['NOT_TRUSTED', 'pinned']);
  });

  it('a newer snapshot that verifies is the last word, also when it relaxes the profile', async () => {
    const { w, client, lapse } = world(STRICT_REVOCATION, { anchors: [IACA_ANCHOR] });
    const c = client({ snapshot: { graceMs: GRACE, retryMs: 0, refreshMs: 0 } });
    await c.sync();
    w.now += 60_000;
    w.policy = LENIENT;
    await c.sync();
    lapse();
    expect((await client().evaluate(ds)).decision).toBe('TRUSTED');
  });

  it('strictAuthorization: an issuer the app lists without authorizations is authorized for nothing', async () => {
    const { client, lapse } = world({ ...LENIENT, strictAuthorization: true });
    await client().sync();
    lapse();
    for (const k of [client(), client()]) {
      const d = await k.evaluateIssuer(openQuery);
      expect([d.decision, d.source]).toEqual(['NOT_TRUSTED', 'pinned']);
      expect(d.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('entity.not_authorized');
      expect(d.evidence?.authorization?.rule).toBe('strict: no authorizations registered');
    }
    // A lenient profile, remembered the same way, lets the same issuer through.
    const lenient = world(LENIENT);
    await lenient.client().sync();
    lenient.lapse();
    expect((await lenient.client().evaluateIssuer(openQuery)).decision).toBe('TRUSTED');
  });

  it('requireSignedIssuerMetadata: unsigned metadata is refused once the snapshot is no longer usable and the issuer is asked directly', async () => {
    const { client, lapse } = world({ ...LENIENT, requireSignedIssuerMetadata: true });
    const c = client();
    await c.sync();
    lapse();
    await expect(c.getIssuerMetadata(ISSUER)).rejects.toThrow(/no signed metadata/);
    await expect(client().getIssuerMetadata(ISSUER)).rejects.toThrow(/no signed metadata/);
    expect((await client().status()).rules?.requireSignedIssuerMetadata).toBe(true);

    const lenient = world(LENIENT);
    await lenient.client().sync();
    lenient.lapse();
    expect((await lenient.client().getIssuerMetadata(ISSUER)).credentialIssuerMetadata.credential_endpoint).toBe(`${ISSUER}/credential`);
    // The app's minimum alone does the same, with no snapshot ever.
    await expect(lenient.client({ policy: { requireSignedIssuerMetadata: true } }).getIssuerMetadata(ISSUER)).rejects.toThrow(/no signed metadata/);
  });
});

describe('only verified data states rules', () => {
  it('a stored snapshot that no longer verifies, or is for another client, states nothing', async () => {
    const tamperings: Array<[string, (jwt: string, sign: (claims: Record<string, unknown>) => string) => string]> = [
      // A strict profile written over the payload of a lenient snapshot: the signature no longer holds.
      ['signature broken', (jwt) => {
        const [h, p, s] = jwt.split('.');
        const claims = JSON.parse(Buffer.from(p!, 'base64url').toString()) as Record<string, unknown>;
        return [h, Buffer.from(JSON.stringify({ ...claims, policy: STRICT_REVOCATION })).toString('base64url'), s].join('.');
      }],
      // Genuinely signed by the service, strict, but for another client.
      ['another audience', (_jwt, sign) => sign({ aud: 'someone-else', policy: STRICT_REVOCATION })],
    ];
    for (const [name, tamper] of tamperings) {
      const { w, client, lapse, snapshot } = world(LENIENT);
      await client().sync();
      const stored = JSON.parse((await w.storage.get('snapshot'))!) as { jwt: string };
      await w.storage.set('snapshot', JSON.stringify({ ...stored, jwt: tamper(stored.jwt, snapshot) }));
      lapse();
      const c = client();
      expect((await c.status()).rules, name).toEqual({ requireRevocationStatus: false, strictAuthorization: false, requireSignedIssuerMetadata: false });
      const d = await c.evaluate(ds);
      expect([d.decision, d.source], name).toEqual(['TRUSTED', 'pinned']);
      expect(severity(d, 'x509.revocation_unknown'), name).toBe('WARNING');
      expect(await w.storage.get('snapshot'), name).toBeNull();
    }
  });

  it('a store that cannot be read leaves the app\'s minimum in force', async () => {
    const broken: CacheStore = { get: async () => { throw new Error('locked'); }, set: async () => undefined, delete: async () => undefined };
    const { w, client } = world(STRICT_REVOCATION, { storage: broken });
    w.online = false;
    expect((await client().evaluate(ds)).decision).toBe('TRUSTED');
    const strict = await client({ policy: { requireRevocationStatus: true } }).evaluate(ds);
    expect([strict.decision, strict.source]).toEqual(['NOT_TRUSTED', 'pinned']);
  });
});
