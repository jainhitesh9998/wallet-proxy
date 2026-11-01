/** Offline credential status tests: mdoc Token Status List (CWT), signer rules, W3C Bitstring Status List checks. */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deflateSync, gzipSync } from 'node:zlib';
import { bytes, cbor, createTrustClient, digest } from '@vctrust/trust-client';
import { checkBitstringStatus, SoftwareKey, verifyMdoc } from '../src/index.js';
import { jwkToCoseKey, sigStructure } from '../src/verify/mdoc.js';

const PKI = new URL('../../trust-client/test/fixtures/pki/', import.meta.url);
const der = (n: string) => new Uint8Array(Buffer.from(readFileSync(new URL(`${n}.pem`, PKI), 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'));
const sign = (keyName: string, data: Uint8Array) => new Uint8Array(createSign('SHA256').update(data)
  .sign({ key: createPrivateKey(readFileSync(new URL(`${keyName}.key`, PKI))), dsaEncoding: 'ieee-p1363' }));
const { Tagged } = cbor;
const STATUS_URI = 'https://issuer.example/status/mdl';

function coseSign1(keyName: string, payload: Uint8Array, protectedHeader: Map<number, unknown>): unknown[] {
  const p = cbor.encode(protectedHeader);
  return [p, new Map([[33, der(keyName)]]), payload, sign(keyName, sigStructure(p, payload))];
}

/** An mDL IssuerSigned signed by the test Document Signer, with an MSO status reference. */
function mdoc(idx: number, holder: SoftwareKey): string {
  const item = new Tagged(24, cbor.encode(new Map<string, unknown>([['digestID', 0], ['random', new Uint8Array(16).fill(7)],
    ['elementIdentifier', 'given_name'], ['elementValue', 'Ada']])));
  const t = (d: Date) => new Tagged(0, d.toISOString().replace(/\.\d+Z$/, 'Z'));
  const mso = new Map<string, unknown>([['version', '1.0'], ['digestAlgorithm', 'SHA-256'],
    ['valueDigests', new Map([['org.iso.18013.5.1', new Map([[0, digest('SHA-256', cbor.encode(item))]])]])],
    ['deviceKeyInfo', new Map([['deviceKey', jwkToCoseKey(holder.publicJwk)]])], ['docType', 'org.iso.18013.5.1.mDL'],
    ['validityInfo', new Map([['signed', t(new Date())], ['validFrom', t(new Date(Date.now() - 60_000))], ['validUntil', t(new Date(Date.now() + 86_400_000))]])],
    ['status', new Map([['status_list', new Map<string, unknown>([['idx', idx], ['uri', STATUS_URI]])]])]]);
  const issuerAuth = coseSign1('ds', cbor.encode(new Tagged(24, cbor.encode(mso))), new Map([[1, -7]]));
  return bytes.base64UrlEncode(cbor.encode(new Map<string, unknown>([['nameSpaces', new Map([['org.iso.18013.5.1', [item]]])], ['issuerAuth', issuerAuth]])));
}

/** statuslist+cwt with 2-bit entries: index 0 VALID, 1 INVALID, 2 SUSPENDED. */
function statusListCwt(opts: { signer?: string; sub?: string; exp?: number } = {}): Uint8Array {
  const lst = new Uint8Array(deflateSync(Buffer.from([0b00_10_01_00])));
  const claims = new Map<number, unknown>([[2, opts.sub ?? STATUS_URI], [6, Math.floor(Date.now() / 1000)], [4, opts.exp ?? Math.floor(Date.now() / 1000) + 3600],
    [65533, new Map<string, unknown>([['bits', 2], ['lst', lst]])]]);
  return cbor.encode(new Tagged(18, coseSign1(opts.signer ?? 'ds', cbor.encode(claims), new Map<number, unknown>([[1, -7], [16, 'application/statuslist+cwt']]))));
}

const trustWith = (list: () => Uint8Array) => createTrustClient({
  fetch: (async (url: string) => (String(url) === STATUS_URI ? new Response(list() as Uint8Array<ArrayBuffer>, { headers: { 'Content-Type': 'application/statuslist+cwt' } })
    : new Response('no', { status: 404 }))) as typeof fetch,
  fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: readFileSync(new URL('iaca.pem', PKI), 'utf8') }] },
});

describe('mdoc status (Token Status List, CWT)', () => {
  const holder = SoftwareKey.generate();
  const verify = (idx: number, list: () => Uint8Array = () => statusListCwt()) =>
    verifyMdoc(mdoc(idx, holder), { trust: trustWith(list), holderJwk: holder.publicJwk });
  const status = async (idx: number, list?: () => Uint8Array) => (await verify(idx, list)).checks.find((c) => c.id === 'mdoc.status')!;

  it('reads the MSO status reference and verifies the signed list', async () => {
    const r = await verify(0);
    expect(r.valid).toBe(true);
    expect(r.trusted).toBe(true);
    expect(r.checks.find((c) => c.id === 'mdoc.status')).toMatchObject({ status: 'pass', detail: expect.stringMatching(/VALID \(statuslist\+cwt, signer the credential signer\)/) });
  });

  it('fails revoked and suspended credentials', async () => {
    expect(await status(1)).toMatchObject({ status: 'fail', detail: expect.stringMatching(/^revoked/) });
    expect(await status(2)).toMatchObject({ status: 'fail', detail: expect.stringMatching(/^suspended/) });
  });

  it('accepts a list signer certified by the same trust anchor, and nothing else', async () => {
    expect((await status(1, () => statusListCwt({ signer: 'ds-crldp' }))).detail).toMatch(/issued under the credential's trust anchor/);
    expect(await status(1, () => statusListCwt({ signer: 'rogue-ds' }))).toMatchObject({ status: 'warn', detail: expect.stringMatching(/signer not trusted/) });
    expect((await status(0, () => statusListCwt({ sub: 'https://elsewhere.example/1' }))).detail).toMatch(/sub does not match/);
    expect((await status(0, () => statusListCwt({ exp: 1000 }))).detail).toMatch(/expired/);
    const tampered = () => { const b = statusListCwt(); b[b.length - 2]! ^= 0xff; return b; };
    expect((await status(1, tampered)).detail).toMatch(/signature invalid/);
  });
});

describe('W3C Bitstring Status List', () => {
  const URL_ = 'https://issuer.example/status/ldp';
  const listVc = (over: Record<string, unknown> = {}) => ({ '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: 'did:example:issuer', credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation',
      encodedList: `u${bytes.base64UrlEncode(new Uint8Array(gzipSync(Buffer.from([0b0100_0000]))))}` }, ...over });
  const check = (vc: Record<string, unknown>, index: number, ok = true) => checkBitstringStatus(
    { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: URL_ },
    { fetch: (async () => new Response(JSON.stringify(vc), { headers: { 'Content-Type': 'application/vc+ld+json' } })) as typeof fetch,
      issuer: 'did:example:issuer', verifyListCredential: async () => ({ ok, detail: ok ? '' : 'proof does not verify' }) });

  it('reads the bit once the list credential verifies and comes from the credential issuer', async () => {
    expect(await check(listVc(), 0)).toMatchObject({ status: 'valid', detail: expect.stringMatching(/list proof verified/) });
    expect((await check(listVc(), 1)).status).toBe('revoked');
  });

  it('does not trust a list that fails verification, comes from another issuer or has another purpose', async () => {
    expect(await check(listVc(), 1, false)).toMatchObject({ status: 'unknown', detail: expect.stringMatching(/does not verify/) });
    expect((await check(listVc({ issuer: 'did:example:other' }), 1)).detail).toMatch(/not by the credential issuer/);
    expect((await check(listVc({ credentialSubject: { ...listVc().credentialSubject, statusPurpose: 'suspension' } }), 1)).detail).toMatch(/purpose/);
  });
});
