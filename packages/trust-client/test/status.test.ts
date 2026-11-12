/** Token Status List (JWT) and Bitstring checks in the client: signer rules, ttl-bound caching, multi-bit entries. */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deflateSync, gzipSync } from 'node:zlib';
import { createTrustClient, type TrustClientConfig } from '../src/index.js';
import { bytes, checkBitstringStatus, checkTokenStatus, jwkThumbprint, parseCertificate } from '../src/primitives.js';
import { MAX_STATUS_LIST_AGE_MS, MIN_BITSTRING_ENTRIES } from '../src/status/status.js';
import { down, es256Key, fakeFetch, json, signJwt } from './helpers.js';

const PKI = new URL('../../../conformance/pki/', import.meta.url);
const pemBody = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const URI = 'https://issuer.example/status/1';

/** statuslist+jwt, 2-bit entries: index 0 VALID, 1 INVALID, 2 SUSPENDED, 3 application-specific (3). */
function statusJwt(opts: { signer?: string; x5c?: boolean; sub?: string; exp?: number | null; iat?: number | null; ttl?: number; typ?: string; bits?: number;
  list?: Uint8Array } = {}): string {
  const signer = opts.signer ?? 'ds';
  const header = { alg: 'ES256', typ: opts.typ ?? 'statuslist+jwt', ...(opts.x5c === false ? {} : { x5c: [pemBody(signer)] }) };
  const now = Math.floor(Date.now() / 1000);
  const payload = { sub: opts.sub ?? URI, ...(opts.iat === null ? {} : { iat: opts.iat ?? now }), ...(opts.exp === null ? {} : { exp: opts.exp ?? now + 3600 }),
    ...(opts.ttl !== undefined ? { ttl: opts.ttl } : {}),
    status_list: { bits: opts.bits ?? 2, lst: bytes.base64UrlEncode(new Uint8Array(deflateSync(Buffer.from(opts.list ?? [0b11_10_01_00])))) } };
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
    const trust = createTrustClient({ http: { fetch: (async (url: string) => {
      if (String(url) !== URI) return new Response('no', { status: 404 });
      calls++;
      return new Response(body, { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    }) as typeof fetch } });
    expect((await trust.checkTokenStatus({ idx: 1, uri: URI }, { signerX5c: dsChain })).status).toBe('revoked');
    expect(await trust.checkTokenStatus({ idx: 0, uri: URI }, { signerX5c: dsChain })).toMatchObject({ status: 'valid', detail: expect.stringMatching(/\(cached\)/) });
    expect(calls).toBe(1);

    const other = 'https://issuer.example/status/2';
    const trust2 = createTrustClient({ http: { fetch: (async () => { calls++; return new Response(body, { headers: { 'Content-Type': 'application/statuslist+jwt' } }); }) as typeof fetch } });
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

describe("Token Status List: a signer issued under the credential's trust anchor", () => {
  const BASE = 'https://trust.example';
  const serviceKey = es256Key();
  const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };
  const IACA = { id: 'iaca', domain: 'mdoc-iaca', frameworkId: 'utopia', status: 'ACTIVE', constraints: {}, certificate: pemBody('iaca') };
  /** The IACA's CRL: it revokes ds-revoked and puts ds-hold on hold; every other Document Signer of the IACA is good. */
  const IACA_CRL = readFileSync(new URL('iaca.crl', PKI)).toString('base64');
  const mdl = { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' };

  /**
   * The status of index 0 (VALID in the list) of a credential signed by ds-crldp, whose status list {@code signer} signed:
   * the service lists the IACA (with its CRL in the snapshot, or without it) under a client profile that requires a known
   * revocation status or not. No CRL is downloaded: without the snapshot's, a signer's status is unknown.
   */
  async function statusSignedBy(signer: string, opts: { crl: boolean; strict: boolean; app?: Partial<TrustClientConfig>; mechanisms?: unknown[] }) {
    const now = Math.floor(Date.now() / 1000);
    const snapshot = signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: 'svc-1' }, { iss: BASE, aud: 'wallet', iat: now, exp: now + 3600,
      ...(opts.mechanisms ? { format: 5, mechanisms: opts.mechanisms } : { format: 4 }),
      policy: { frameworks: ['utopia'], strictAuthorization: false, requireRevocationStatus: opts.strict, requireSignedIssuerMetadata: false },
      frameworks: [{ id: 'utopia', name: 'Utopia' }], entities: [], anchors: [IACA], crls: opts.crl ? [{ issuer: 'iaca', crl: IACA_CRL }] : [] },
    serviceKey.privateKey);
    const { fetch } = fakeFetch({
      [`${BASE}/api/v1/snapshot`]: () => new Response(snapshot, { headers: { 'Content-Type': 'application/jwt' } }),
      [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [serviceJwk] }),
      [URI]: () => new Response(statusJwt({ signer }), { headers: { 'Content-Type': 'application/statuslist+jwt' } }),
    }, down);
    const trust = createTrustClient({ service: { url: BASE, clientId: 'wallet', keys: { thumbprints: [jwkThumbprint(serviceJwk)] } },
      lookups: { statusLists: 'direct', crl: 'none' }, http: { fetch, retries: 0 }, ...opts.app });
    const credential = [pemBody('ds-crldp')];
    const decision = await trust.evaluate({ role: 'issuer', subject: { x5c: credential }, context: mdl });
    expect(decision.evidence?.x509?.anchorFound).toBe(true);
    return trust.checkTokenStatus({ idx: 0, uri: URI }, { signerX5c: credential, decision });
  }

  it('is never valid when the signer is revoked', async () => {
    const s = await statusSignedBy('ds-revoked', { crl: true, strict: false });
    expect(s.status).toBe('unknown');
    expect(s.detail).toMatch(/signer not trusted.*revoked/);
  });

  it('is never valid when the signer is on hold', async () => {
    const s = await statusSignedBy('ds-hold', { crl: true, strict: false });
    expect(s.status).toBe('unknown');
    expect(s.detail).toMatch(/signer not trusted.*on hold/);
  });

  it('is unknown when the signer\'s revocation status is unknown and the rules in force require one', async () => {
    for (const [name, opts] of [['the client profile', { crl: false, strict: true }],
      ["the app's own minimum", { crl: false, strict: false, app: { policy: { requireRevocationStatus: true } } }]] as const) {
      const s = await statusSignedBy('ds', opts);
      expect(s.status, name).toBe('unknown');
      expect(s.detail, name).toMatch(/signer not trusted.*[Rr]evocation status .* is unknown/);
    }
  });

  it('is read when the signer\'s revocation status is unknown under lenient rules', async () => {
    expect(await statusSignedBy('ds', { crl: false, strict: false })).toMatchObject({ status: 'valid', value: 0,
      detail: expect.stringMatching(/issued under the credential's trust anchor/) });
  });

  it('is unknown when the signer\'s revocation status is unknown and the mechanism that governed the credential requires one', async () => {
    const required = { id: 'mdl', for: { role: 'issuer', formats: ['mso_mdoc'] }, x509: { revocation: 'required' } };
    const s = await statusSignedBy('ds', { crl: false, strict: false, mechanisms: [required] });
    expect(s.status).toBe('unknown');
    expect(s.detail).toMatch(/signer not trusted.*[Rr]evocation status .* is unknown/);
    // A mechanism in force that did not govern the credential, or one that leaves revocation to the client profile, changes nothing.
    const other = { id: 'sd-jwt', for: { role: 'issuer', formats: ['dc+sd-jwt'] }, x509: { revocation: 'required' } };
    const lenient = { id: 'mdl', for: { role: 'issuer', formats: ['mso_mdoc'] }, keys: ['x5c'] };
    for (const mechanisms of [[other], [lenient, other]]) {
      expect(await statusSignedBy('ds', { crl: false, strict: false, mechanisms }), JSON.stringify(mechanisms)).toMatchObject({ status: 'valid', value: 0 });
    }
    // Under that mechanism a good signer is read.
    expect(await statusSignedBy('ds', { crl: true, strict: false, mechanisms: [required] })).toMatchObject({ status: 'valid', value: 0 });
  });

  it('is read when the signer is good', async () => {
    for (const strict of [false, true]) {
      expect(await statusSignedBy('ds', { crl: true, strict })).toMatchObject({ status: 'valid', value: 0,
        detail: expect.stringMatching(/issued under the credential's trust anchor/) });
    }
  });
});

describe('Token Status List: index arithmetic and freshness', () => {
  /** 8192 one-bit entries; index 1 is INVALID. */
  const list = () => { const b = new Uint8Array(1024); b[0] = 0b0000_0010; return b; };
  const check = (idx: number, jwt = statusJwt({ bits: 1, list: list() })) => checkTokenStatus({ idx, uri: URI }, { fetchList: fetched(jwt), signerX5c: dsChain });

  it('reads the entry it is asked for', async () => {
    expect(await check(0)).toMatchObject({ status: 'valid', value: 0 });
    expect(await check(1)).toMatchObject({ status: 'revoked', value: 1 });
    expect(await check(8191)).toMatchObject({ status: 'valid' });
    expect((await check(8192)).detail).toMatch(/out of bounds/);
  });

  it('does not wrap a large index at 32 bits into the list', async () => {
    // 2^31 used to read as VALID, 2^32 + 1 used to read entry 1.
    for (const idx of [2147483648, 3000000000, 4294967296, 4294967297, Number.MAX_SAFE_INTEGER]) {
      expect(await check(idx), String(idx)).toMatchObject({ status: 'unknown', detail: expect.stringMatching(/out of bounds/) });
    }
    // The same with wider entries: the byte position is index / (8 / bits), not a shifted product.
    const two = statusJwt({ bits: 2, list: new Uint8Array(1024).fill(0b01_01_01_01) });
    expect(await check(4095, two)).toMatchObject({ status: 'revoked', value: 1 });
    expect((await check(4096, two)).detail).toMatch(/out of bounds/);
    expect((await check(2147483648, two)).detail).toMatch(/out of bounds/);
    expect((await check(4294967297, two)).detail).toMatch(/out of bounds/);
  });

  it('rejects indexes that are not non-negative safe integers', async () => {
    for (const idx of [-1, 1.5, NaN, Infinity, 2 ** 53, '1' as unknown as number]) {
      expect(await check(idx), String(idx)).toMatchObject({ status: 'unknown', detail: 'Malformed status_list reference' });
    }
  });

  it('accepts a list without exp only for a limited time after iat', async () => {
    const now = Math.floor(Date.now() / 1000);
    const fresh = await check(1, statusJwt({ bits: 1, list: list(), exp: null, iat: now - 3600 }));
    expect(fresh).toMatchObject({ status: 'revoked' });
    const maxAge = MAX_STATUS_LIST_AGE_MS / 1000;
    expect(MAX_STATUS_LIST_AGE_MS).toBe(7 * 24 * 3600_000);
    expect(await check(0, statusJwt({ bits: 1, list: list(), exp: null, iat: now - maxAge + 60 }))).toMatchObject({ status: 'valid' });
    const old = await check(0, statusJwt({ bits: 1, list: list(), exp: null, iat: now - maxAge - 60 }));
    expect(old).toMatchObject({ status: 'unknown', detail: expect.stringMatching(/no exp and was issued more than 7 days ago/) });
    expect((await check(0, statusJwt({ bits: 1, list: list(), exp: null, iat: now - 3 * 365 * 86400 }))).status).toBe('unknown');
    // Neither exp nor iat: nothing says how old the list is.
    expect((await check(0, statusJwt({ bits: 1, list: list(), exp: null, iat: null }))).detail).toMatch(/neither exp nor iat/);
    // With exp, an old iat is the issuer's business; ttl still bounds reuse as before.
    expect(await check(0, statusJwt({ bits: 1, list: list(), iat: now - 30 * 86400, ttl: 60 }))).toMatchObject({ status: 'valid', ttlMs: 60_000 });
    // A list near the end of its allowed age is not reused beyond it.
    const nearEnd = await check(0, statusJwt({ bits: 1, list: list(), exp: null, iat: now - maxAge + 120, ttl: 3600 }));
    expect(nearEnd.ttlMs).toBeLessThanOrEqual(121_000);
  });
});

describe('Bitstring Status List', () => {
  const LIST = 'https://issuer.example/status/ldp';
  const ISSUER = 'did:example:issuer';
  /** A list of the minimum size (16 KB = 131,072 one-bit entries) whose first bytes are {@code bits}. */
  const bitstring = (bits: number[], length = MIN_BITSTRING_ENTRIES / 8) => { const b = new Uint8Array(length); b.set(bits); return b; };
  const encode = (b: Uint8Array) => `u${bytes.base64UrlEncode(new Uint8Array(gzipSync(Buffer.from(b))))}`;
  const listVc = (bits: number[] | Uint8Array, subject: Record<string, unknown> = {}, vc: Record<string, unknown> = {}) => JSON.stringify({
    type: ['VerifiableCredential', 'BitstringStatusListCredential'], issuer: ISSUER, validFrom: new Date(Date.now() - 3600_000).toISOString(), ...vc,
    credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: encode(bits instanceof Uint8Array ? bits : bitstring(bits)), ...subject } });
  const entry = (index: number | string, extra: Record<string, unknown> = {}) => ({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: LIST, ...extra });
  const verified = async () => ({ ok: true, detail: 'test proof' });
  const ctx = (body: string, extra: Record<string, unknown> = {}) => ({ fetchList: fetched(body, 'application/vc+ld+json'), issuer: ISSUER, verifyListCredential: verified, ...extra });
  const check = (e: Record<string, unknown>, body = listVc([0b0100_0000]), extra: Record<string, unknown> = {}) => checkBitstringStatus(e, ctx(body, extra));

  it('reads a bit of a verified list (index 0 is the left-most bit)', async () => {
    expect(await check(entry(0))).toMatchObject({ status: 'valid', value: 0, detail: expect.stringMatching(/list proof verified/) });
    expect(await check(entry(1))).toMatchObject({ status: 'revoked', value: 1 });
    expect(await check(entry(1, { statusPurpose: 'suspension' }), listVc([0b0100_0000], { statusPurpose: 'suspension' }))).toMatchObject({ status: 'suspended' });
    expect(await check(entry(MIN_BITSTRING_ENTRIES - 1))).toMatchObject({ status: 'valid' });
  });

  it('reads multi-bit message entries as values, not as a revocation verdict', async () => {
    const body = listVc(bitstring([0b1001_0000], MIN_BITSTRING_ENTRIES / 4), { statusPurpose: 'message' });
    expect(await check(entry(0, { statusPurpose: 'message', statusSize: 2 }), body)).toMatchObject({ status: 'unknown', value: 2 });
    expect(await check(entry(1, { statusPurpose: 'message', statusSize: 2 }), body)).toMatchObject({ status: 'unknown', value: 1 });
  });

  it('honours the list ttl (milliseconds) and validUntil for reuse', async () => {
    expect(await check(entry(0), listVc([0], { ttl: 120_000 }))).toMatchObject({ status: 'valid', ttlMs: 120_000 });
    const soon = new Date(Date.now() + 30_000).toISOString();
    expect((await check(entry(0), listVc([0], { ttl: 120_000 }, { validUntil: soon }))).ttlMs).toBeLessThanOrEqual(30_000);
  });

  it('is unknown when the list cannot be verified: a verifier and the expected issuer are both required', async () => {
    // An unsigned list served by anyone used to read as valid.
    const mallory = listVc([0], {}, { issuer: 'did:web:mallory.example' });
    let fetches = 0;
    const fetchList = async () => { fetches++; return { body: bytes.utf8Encode(mallory), contentType: 'application/json', source: 'direct' as const }; };
    const bare = await checkBitstringStatus(entry(0), { fetchList });
    expect(bare).toMatchObject({ status: 'unknown', detail: expect.stringMatching(/could not be verified/) });
    expect(bare.value).toBeUndefined();
    expect((await checkBitstringStatus(entry(0), { fetchList, issuer: ISSUER })).detail).toMatch(/could not be verified: a verifier for the list credential's proof was not supplied/);
    expect((await checkBitstringStatus(entry(0), { fetchList, verifyListCredential: verified })).detail).toMatch(/could not be verified: the issuer the list must come from was not supplied/);
    expect((await checkBitstringStatus(entry(1), { fetchList })).status).toBe('unknown');
    expect(fetches).toBe(0);
    // With both, the list of another issuer and a list whose proof fails are refused.
    expect((await checkBitstringStatus(entry(0), { fetchList, issuer: ISSUER, verifyListCredential: verified })).detail).toMatch(/issued by did:web:mallory.example, not by the credential issuer/);
    expect((await check(entry(0), listVc([0]), { verifyListCredential: async () => ({ ok: false, detail: 'bad proof' }) })).detail).toMatch(/does not verify: bad proof/);
    // The client facade has no built-in verifier either.
    const client = createTrustClient({ http: { fetch: (async () => new Response(mallory, { headers: { 'Content-Type': 'application/json' } })) as typeof fetch } });
    expect(await client.checkBitstringStatus(entry(0))).toMatchObject({ status: 'unknown', detail: expect.stringMatching(/could not be verified/) });
  });

  it('requires the entry and the list to agree on type and purpose (W3C Bitstring Status List v1.0)', async () => {
    const { statusPurpose: _p, ...noPurpose } = entry(0);
    expect((await check(noPurpose)).detail).toMatch(/no statusPurpose/);
    expect((await check(entry(0, { statusPurpose: 'suspension' }))).detail).toMatch(/purpose revocation does not match suspension/);
    expect((await check(entry(0), listVc([0], { statusPurpose: undefined }))).detail).toMatch(/purpose \(none\) does not match revocation/);
    expect(await check(entry(1, { statusPurpose: 'suspension' }), listVc([0b0100_0000], { statusPurpose: ['revocation', 'suspension'] }))).toMatchObject({ status: 'suspended' });
    expect((await check(entry(0), listVc([0], { type: 'SomethingElse' }))).detail).toMatch(/credentialSubject type is SomethingElse, not BitstringStatusList/);
    expect((await check(entry(0), listVc([0], { type: undefined }))).detail).toMatch(/type is missing, not BitstringStatusList/);
    expect((await check(entry(0), listVc([0], {}, { type: ['VerifiableCredential'] }))).detail).toMatch(/is not a BitstringStatusListCredential/);
    expect((await check(entry(0, { type: 'SomeOtherEntry' }))).detail).toMatch(/type is not BitstringStatusListEntry/);
    // The older StatusList2021 pairs with its own list type, not with a Bitstring list.
    expect((await check(entry(0, { type: 'StatusList2021Entry' }))).status).toBe('unknown');
    const list2021 = listVc([0b0100_0000], { type: 'StatusList2021' }, { type: ['VerifiableCredential', 'StatusList2021Credential'] });
    expect(await check(entry(1, { type: 'StatusList2021Entry' }), list2021)).toMatchObject({ status: 'revoked' });
  });

  it('requires at least 131,072 entries (16 KB for statusSize 1)', async () => {
    expect(MIN_BITSTRING_ENTRIES).toBe(131_072);
    expect((await check(entry(0), listVc(bitstring([0], 16 * 1024 - 1)))).detail).toMatch(/has 131064 entries, fewer than the minimum of 131072/);
    expect((await check(entry(0), listVc(bitstring([0], 1)))).status).toBe('unknown');
    // statusSize 2 needs twice the bits for the same number of entries.
    const message = (length: number) => listVc(bitstring([0b1001_0000], length), { statusPurpose: 'message' });
    expect((await check(entry(0, { statusPurpose: 'message', statusSize: 2 }), message(16 * 1024))).detail).toMatch(/fewer than the minimum/);
    expect(await check(entry(0, { statusPurpose: 'message', statusSize: 2 }), message(32 * 1024))).toMatchObject({ status: 'unknown', value: 2 });
  });

  it('bounds-checks the index without wrapping, and rejects indexes that are not base-10 integers', async () => {
    for (const idx of [MIN_BITSTRING_ENTRIES, 2147483648, 4294967296, 4294967297, Number.MAX_SAFE_INTEGER]) {
      expect(await check(entry(idx)), String(idx)).toMatchObject({ status: 'unknown', detail: 'Status index out of bounds' });
    }
    expect((await check(entry(Number.MAX_SAFE_INTEGER, { statusPurpose: 'message', statusSize: 32 }),
      listVc(bitstring([0], 32 * 16 * 1024), { statusPurpose: 'message' }))).detail).toBe('Status index out of bounds');
    for (const idx of ['', ' 1', '1.5', '-1', '0x10', '1e3', '9007199254740993', 'abc']) {
      expect(await check(entry(idx)), JSON.stringify(idx)).toMatchObject({ status: 'unknown', detail: 'Malformed status entry' });
    }
    expect((await check({ ...entry(0), statusListIndex: -1 })).detail).toBe('Malformed status entry');
    expect((await check({ ...entry(0), statusListIndex: 1.5 })).detail).toBe('Malformed status entry');
    expect((await check({ ...entry(0), statusSize: 0 })).detail).toBe('Malformed status entry');
  });

  it('accepts a list without validUntil only for a limited time after validFrom', async () => {
    const at = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
    expect(await check(entry(1), listVc([0b0100_0000], {}, { validFrom: at(MAX_STATUS_LIST_AGE_MS - 60_000) }))).toMatchObject({ status: 'revoked' });
    expect((await check(entry(0), listVc([0], {}, { validFrom: at(MAX_STATUS_LIST_AGE_MS + 60_000) }))).detail).toMatch(/no validUntil and is valid from more than 7 days ago/);
    expect((await check(entry(0), listVc([0], {}, { validFrom: undefined }))).detail).toMatch(/neither validUntil nor validFrom/);
    // With validUntil the list states its own end.
    expect(await check(entry(0), listVc([0], {}, { validFrom: at(30 * 86400_000), validUntil: new Date(Date.now() + 3600_000).toISOString() }))).toMatchObject({ status: 'valid' });
    expect((await check(entry(0), listVc([0], {}, { validUntil: at(1000) }))).detail).toMatch(/expired/);
    // A date that is not a date is not "no date".
    expect((await check(entry(0), listVc([0], {}, { validUntil: 'soon' }))).detail).toMatch(/invalid validity period/);
    expect((await check(entry(0), listVc([0], {}, { validFrom: 12345 }))).detail).toMatch(/invalid validity period/);
  });
});
