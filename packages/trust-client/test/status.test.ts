/** Token Status List (JWT) and Bitstring checks in the client: signer rules, ttl-bound caching, multi-bit entries. */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deflateSync, gzipSync } from 'node:zlib';
import { bytes, checkBitstringStatus, checkTokenStatus, createTrustClient, parseCertificate } from '../src/index.js';

const PKI = new URL('./fixtures/pki/', import.meta.url);
const pemBody = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const URI = 'https://issuer.example/status/1';

/** statuslist+jwt, 2-bit entries: index 0 VALID, 1 INVALID, 2 SUSPENDED, 3 application-specific (3). */
function statusJwt(opts: { signer?: string; x5c?: boolean; sub?: string; exp?: number; ttl?: number; typ?: string; bits?: number } = {}): string {
  const signer = opts.signer ?? 'ds';
  const header = { alg: 'ES256', typ: opts.typ ?? 'statuslist+jwt', ...(opts.x5c === false ? {} : { x5c: [pemBody(signer)] }) };
  const now = Math.floor(Date.now() / 1000);
  const payload = { sub: opts.sub ?? URI, iat: now, exp: opts.exp ?? now + 3600, ...(opts.ttl !== undefined ? { ttl: opts.ttl } : {}),
    status_list: { bits: opts.bits ?? 2, lst: bytes.base64UrlEncode(new Uint8Array(deflateSync(Buffer.from([0b11_10_01_00])))) } };
  const input = `${bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(header)))}.${bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(payload)))}`;
  const sig = createSign('SHA256').update(input).sign({ key: createPrivateKey(readFileSync(new URL(`${signer}.key`, PKI))), dsaEncoding: 'ieee-p1363' });
  return `${input}.${bytes.base64UrlEncode(new Uint8Array(sig))}`;
}

const fetched = (body: string, contentType = 'application/statuslist+jwt') => async () => ({ body: bytes.utf8Encode(body), contentType, source: 'direct' as const });
const dsChain = [pemBody('ds')];

describe('Token Status List (JWT)', () => {
  it('reads 2-bit values from a list signed by the credential signer', async () => {
    const ctx = { fetchList: fetched(statusJwt()), signerX5c: dsChain };
    expect(await checkTokenStatus({ idx: 0, uri: URI }, ctx)).toMatchObject({ status: 'valid', value: 0 });
    expect(await checkTokenStatus({ idx: 1, uri: URI }, ctx)).toMatchObject({ status: 'revoked', value: 1 });
    expect(await checkTokenStatus({ idx: 2, uri: URI }, ctx)).toMatchObject({ status: 'suspended', value: 2 });
    expect(await checkTokenStatus({ idx: 3, uri: URI }, ctx)).toMatchObject({ status: 'unknown', value: 3, detail: expect.stringMatching(/application-specific/) });
    expect((await checkTokenStatus({ idx: 4, uri: URI }, ctx)).detail).toMatch(/out of bounds/);
  });

  it('accepts a list without a certificate only when signed by the credential key', async () => {
    const dsKey = parseCertificate(pemBody('ds')).publicKey!;
    const rogueKey = parseCertificate(pemBody('rogue-ds')).publicKey!;
    expect(await checkTokenStatus({ idx: 1, uri: URI }, { fetchList: fetched(statusJwt({ x5c: false })), signerKey: dsKey }))
      .toMatchObject({ status: 'revoked', detail: expect.stringMatching(/signer the credential signer/) });
    expect((await checkTokenStatus({ idx: 1, uri: URI }, { fetchList: fetched(statusJwt({ x5c: false })), signerKey: rogueKey })).detail)
      .toMatch(/not signed by the credential signer/);
    expect((await checkTokenStatus({ idx: 1, uri: URI }, { fetchList: fetched(statusJwt({ x5c: false })) })).detail).toMatch(/no signing certificate/);
  });

  it('rejects other signers, typ, subject, expiry and bits values', async () => {
    const check = (jwt: string) => checkTokenStatus({ idx: 1, uri: URI }, { fetchList: fetched(jwt), signerX5c: dsChain });
    expect((await check(statusJwt({ signer: 'rogue-ds' }))).detail).toMatch(/signer not trusted/);
    expect((await check(statusJwt({ typ: 'JWT' }))).detail).toMatch(/Unexpected status list typ/);
    expect((await check(statusJwt({ sub: 'https://elsewhere.example' }))).detail).toMatch(/sub does not match/);
    expect((await check(statusJwt({ exp: 1000 }))).detail).toMatch(/expired/);
    expect((await check(statusJwt({ bits: 3 }))).detail).toMatch(/invalid bits/);
    expect((await checkTokenStatus({ idx: 1, uri: URI }, { fetchList: async () => { throw new Error('offline'); } })).detail).toMatch(/unavailable: offline/);
  });

  it('caches a verified list for its ttl and never caches a list that failed', async () => {
    let calls = 0;
    let body = statusJwt({ ttl: 600 });
    const trust = createTrustClient({ fetch: (async (url: string) => {
      if (String(url) !== URI) return new Response('no', { status: 404 });
      calls++;
      return new Response(body, { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    }) as typeof fetch });
    expect((await trust.checkTokenStatus({ idx: 1, uri: URI }, { signerX5c: dsChain })).status).toBe('revoked');
    expect(await trust.checkTokenStatus({ idx: 0, uri: URI }, { signerX5c: dsChain })).toMatchObject({ status: 'valid', detail: expect.stringMatching(/\(cached\)/) });
    expect(calls).toBe(1);

    const other = 'https://issuer.example/status/2';
    const trust2 = createTrustClient({ fetch: (async () => { calls++; return new Response(body, { headers: { 'Content-Type': 'application/statuslist+jwt' } }); }) as typeof fetch });
    body = statusJwt({ ttl: 0, sub: other });
    calls = 0;
    await trust2.checkTokenStatus({ idx: 1, uri: other }, { signerX5c: dsChain });
    await trust2.checkTokenStatus({ idx: 1, uri: other }, { signerX5c: dsChain });
    expect(calls).toBe(2);                                           // ttl 0: not reused
    body = statusJwt({ signer: 'rogue-ds', sub: other });
    calls = 0;
    await trust2.checkTokenStatus({ idx: 1, uri: other }, { signerX5c: dsChain });
    await trust2.checkTokenStatus({ idx: 1, uri: other }, { signerX5c: dsChain });
    expect(calls).toBe(2);                                           // untrusted signer: not cached
  });
});

describe('Bitstring Status List', () => {
  const LIST = 'https://issuer.example/status/ldp';
  const listVc = (bits: number[], subject: Record<string, unknown> = {}) => JSON.stringify({ issuer: 'did:example:issuer',
    credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: `u${bytes.base64UrlEncode(new Uint8Array(gzipSync(Buffer.from(bits))))}`, ...subject } });
  const entry = (index: number, extra: Record<string, unknown> = {}) => ({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: LIST, ...extra });

  it('reads multi-bit message entries as values, not as a revocation verdict', async () => {
    const ctx = { fetchList: fetched(listVc([0b1001_0000], { statusPurpose: 'message' }), 'application/vc+ld+json'), issuer: 'did:example:issuer' };
    expect(await checkBitstringStatus(entry(0, { statusPurpose: 'message', statusSize: 2 }), ctx)).toMatchObject({ status: 'unknown', value: 2 });
    expect(await checkBitstringStatus(entry(1, { statusPurpose: 'message', statusSize: 2 }), ctx)).toMatchObject({ status: 'unknown', value: 1 });
  });

  it('honours the list ttl (milliseconds) and validUntil for reuse', async () => {
    const r = await checkBitstringStatus(entry(0), { fetchList: fetched(listVc([0], { ttl: 120_000 }), 'application/vc+ld+json'), issuer: 'did:example:issuer' });
    expect(r).toMatchObject({ status: 'valid', ttlMs: 120_000 });
  });
});
