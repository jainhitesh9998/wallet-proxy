/**
 * Regressions from an independent review of the client library: input that must not hang, inflate, linger in a
 * cache or keep a revoked key trusted; and policies that must hold on every route.
 */
import { describe, expect, it } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { MemoryCacheStore, TrustClient } from '../src/index.js';
import { checkTokenStatus, extractIssuerInfo, fetchIssuerMetadata, issuerTrustQuery, jwkThumbprint, publicKeyFromJwk, type Jwk } from '../src/primitives.js';
import { LocalEvaluator } from '../src/evaluation/local.js';
import { SnapshotManager } from '../src/snapshot/snapshot.js';
import { fetchWithTimeout } from '../src/did/resolver.js';

const b64u = (s: string | Buffer) => Buffer.from(s).toString('base64url');
const es256 = (header: object, payload: object, key: import('node:crypto').KeyObject) => {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  return `${input}.${b64u(createSign('SHA256').update(input).sign({ key, dsaEncoding: 'ieee-p1363' }))}`;
};
const serviceKey = (kid: string) => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, jwk: { ...(publicKey.export({ format: 'jwk' }) as Record<string, string>), kid } as unknown as Jwk & { kid: string } };
};
const snapshotJwt = (k: ReturnType<typeof serviceKey>, iat: number, policy: Record<string, unknown> = {}) =>
  es256({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: k.jwk.kid }, { iat, exp: iat + 86400, aud: 'w', format: 4, policy, entities: [], anchors: [] }, k.privateKey);

describe('client hardening', () => {
  it('stops asking for metadata when an issuer answers every request with an invalid JWT', async () => {
    let calls = 0;
    const f = (async () => { calls++; return new Response('eyJhbGciOiJFUzI1NiJ9.e30.AA', { headers: { 'Content-Type': 'application/jwt' } }); }) as typeof fetch;
    await expect(fetchIssuerMetadata('https://issuer.example', f, 1000, undefined, { mode: 'verify', trustSigner: async () => ({ ok: true, detail: '' }) }))
      .rejects.toThrow(/not asked for/);
    expect(calls).toBeLessThanOrEqual(3);
  });

  it('un-pins a stored service key once the configuration no longer lists its thumbprint', async () => {
    const [k1, k2] = [serviceKey('k1'), serviceKey('k2')];
    const store = new MemoryCacheStore();
    const now = Math.floor(Date.now() / 1000);
    let snap = snapshotJwt(k1, now - 10);
    const transport = { request: async (_m: string, path: string) => (path.includes('jwks')
      ? { status: 200, body: { keys: [k1.jwk, k2.jwk] }, headers: new Headers() } : { status: 200, body: snap, headers: new Headers() }) } as never;
    await new SnapshotManager(transport, store, { thumbprints: [jwkThumbprint(k1.jwk)] }, 'w', 0).sync();
    await store.delete('snapshot');
    snap = snapshotJwt(k1, now);
    await expect(new SnapshotManager(transport, store, { thumbprints: [jwkThumbprint(k2.jwk)] }, 'w', 0).sync()).rejects.toThrow();
  });

  it('requires every specific type of a W3C VC to be authorized', async () => {
    const vc = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'LandStatementCredential', 'EUPidCredential'],
      issuer: 'did:web:land.example', credentialSubject: {}, proof: { verificationMethod: 'did:web:land.example#k' } };
    const q = issuerTrustQuery(extractIssuerInfo(vc, 'ldp_vc'));
    expect(q.context?.credentialTypes).toEqual(['LandStatementCredential', 'EUPidCredential']);
    const doc = { id: 'did:web:land.example', verificationMethod: [{ id: 'did:web:land.example#k', type: 'Multikey', controller: 'did:web:land.example' }],
      assertionMethod: ['did:web:land.example#k'] };
    const d = await new LocalEvaluator(async () => ({ didDocument: doc, didResolutionMetadata: {}, didDocumentMetadata: {} } as never)).evaluate(q, {
      entities: [{ id: 'land', frameworkId: 'fw', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [{ name: 'Land' }],
        identifiers: [{ type: 'DID', value: 'did:web:land.example' }], authorizations: [{ format: 'ldp_vc', type: 'LandStatementCredential' }] } as never],
      anchors: [], frameworks: [], source: 'snapshot', policy: { strictAuthorization: true } });
    expect(d.decision).toBe('NOT_TRUSTED');
    expect(d.reasons.find((r) => r.code === 'entity.not_authorized')?.message).toMatch(/EUPidCredential/);
  });

  it('keeps requiring signed issuer metadata when the proxy is down and the issuer is asked directly', async () => {
    const k = serviceKey('s1');
    const snapshot = snapshotJwt(k, Math.floor(Date.now() / 1000), { frameworks: ['f'], requireSignedIssuerMetadata: true });
    let up = true;
    const md = { credential_issuer: 'https://issuer.example', credential_endpoint: 'https://issuer.example/c', credential_configurations_supported: {} };
    const f = (async (u: string) => {
      const url = String(u);
      if (url.startsWith('https://trust.example')) {
        if (!up) throw new TypeError('fetch failed');
        if (url.includes('jwks')) return Response.json({ keys: [k.jwk] });
        if (url.includes('/snapshot')) return new Response(snapshot, { headers: { 'Content-Type': 'application/jwt' } });
      }
      if (url === 'https://issuer.example/.well-known/openid-credential-issuer') return Response.json(md);
      return new Response('nf', { status: 404 });
    }) as typeof fetch;
    const c = new TrustClient({ service: { url: 'https://trust.example', clientId: 'w', keys: { thumbprints: [jwkThumbprint(k.jwk)] } },
      http: { fetch: f, retries: 0 } });
    await c.sync();
    up = false;
    await expect(c.getIssuerMetadata('https://issuer.example')).rejects.toThrow(/signed metadata/);
  });

  it('refuses a status list that inflates past the limit instead of inflating it', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const lst = deflateSync(Buffer.alloc(64 * 1024 * 1024), { level: 9 });
    const jwt = es256({ alg: 'ES256', typ: 'statuslist+jwt' }, { sub: 'https://evil.example/sl', iat: Math.floor(Date.now() / 1000), status_list: { bits: 1, lst: b64u(lst) } }, privateKey);
    const r = await checkTokenStatus({ idx: 0, uri: 'https://evil.example/sl' }, {
      fetchList: async () => ({ body: new TextEncoder().encode(jwt), contentType: 'application/statuslist+jwt', source: 'direct' }),
      signerKey: publicKeyFromJwk(publicKey.export({ format: 'jwk' }) as never) });
    expect(r.status).toBe('unknown');
    expect(r.detail).toMatch(/larger than/);
  });

  it('caps response bodies and keeps the deadline while the body is read', async () => {
    const huge = (async () => new Response(new Uint8Array(11 * 1024 * 1024))) as typeof fetch;
    await expect(fetchWithTimeout(huge, 'https://x.example/a', {}, 5000)).rejects.toThrow(/larger than/);
    const declared = (async () => new Response('x', { headers: { 'Content-Length': String(50 * 1024 * 1024) } })) as typeof fetch;
    await expect(fetchWithTimeout(declared, 'https://x.example/a', {}, 5000)).rejects.toThrow(/larger than/);
    const slow = (async (_u: string, init?: RequestInit) => new Response(new ReadableStream({
      start(c) { c.enqueue(new Uint8Array([123])); init?.signal?.addEventListener('abort', () => c.error(new Error('aborted'))); } }))) as typeof fetch;
    await expect(fetchWithTimeout(slow, 'https://x.example/a', {}, 100)).rejects.toThrow(/abort/);
    const ok = await fetchWithTimeout((async () => Response.json({ a: 1 })) as typeof fetch, 'https://x.example/a', {}, 1000);
    expect(await ok.json()).toEqual({ a: 1 });
  });

  it('serves a cached DID document only after a transient failure, and never after the DID is gone', async () => {
    const did = 'did:web:issuer.example';
    const doc = { id: did, verificationMethod: [{ id: `${did}#k`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } }] };
    const seed = async (ageMs: number) => {
      const store = new MemoryCacheStore();
      const at = Date.now() - ageMs;
      await store.set(`did:${did}`, JSON.stringify({ value: { didDocument: doc, didResolutionMetadata: {}, didDocumentMetadata: {} }, storedAt: at, expiresAt: at + 60_000 }));
      return store;
    };
    const gone = (async () => new Response('gone', { status: 410 })) as typeof fetch;
    const down = (async () => new Response('busy', { status: 503 })) as typeof fetch;
    expect((await new TrustClient({ http: { fetch: gone }, storage: await seed(3600_000) }).resolveDid(did)).didDocument).toBeNull();
    const recent = await new TrustClient({ http: { fetch: down }, storage: await seed(3600_000) }).resolveDid(did);
    expect(recent.didDocument?.id).toBe(did);
    expect(recent.didResolutionMetadata).toMatchObject({ stale: true });
    expect((await new TrustClient({ http: { fetch: down }, storage: await seed(180 * 24 * 3600_000) }).resolveDid(did)).didDocument).toBeNull();
  });
});
