import { describe, expect, it } from 'vitest';
import { resolveDidLocally, verificationMethodPublicKey, findVerificationMethod, hasRelationship, decodeJws, verifyJws,
  verifySignature, jwkThumbprint, didError, bytes } from '../src/primitives.js';
import type { DidDocument } from '../src/index.js';
import { es256Key, fakeFetch, fixture, json, signJwt } from './helpers.js';
import { createHash, createPrivateKey, sign as nodeSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { criticalHeaderProblem } from '../src/jose/jws.js';
import { rsaKeyProblem, verifyPkcs1 } from '../src/crypto/rsa.js';
import { isSupportedJoseAlg } from '../src/crypto/verify.js';

describe('local DID resolution', () => {
  it('resolves did:key (Ed25519) and did:jwk', async () => {
    const f = fakeFetch({}).fetch;
    const k = await resolveDidLocally('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#frag', { fetch: f });
    expect(k.didDocument?.id).toBe('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    const vm = k.didDocument!.verificationMethod![0]!;
    expect(verificationMethodPublicKey(vm).kty).toBe('OKP');
    const { jwk } = es256Key();
    const did = `did:jwk:${Buffer.from(JSON.stringify(jwk)).toString('base64url')}`;
    const j = await resolveDidLocally(did, { fetch: f });
    expect(findVerificationMethod(j.didDocument!, '#0')?.publicKeyJwk?.x).toBe(jwk.x);
  });

  it('decodes P-256 did:key to the spec vector', async () => {
    const r = await resolveDidLocally('did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169', { fetch: fakeFetch({}).fetch });
    const key = verificationMethodPublicKey(r.didDocument!.verificationMethod![0]!);
    expect(key.kty).toBe('EC');
  });

  it('resolves did:web with path and port encoding and checks the id', async () => {
    const doc = JSON.parse(fixture('mosip-land-key-did.json').toString());
    const { fetch, calls } = fakeFetch({ 'https://inji.github.io/inji-config/collab/landregistry/did.json': () => json(doc) });
    const r = await resolveDidLocally('did:web:inji.github.io:inji-config:collab:landregistry', { fetch });
    expect(r.didDocument?.id).toBe('did:web:inji.github.io:inji-config:collab:landregistry');
    expect(calls).toEqual(['GET https://inji.github.io/inji-config/collab/landregistry/did.json']);
    const vm = r.didDocument!.verificationMethod![0]!;
    expect(vm.type).toBe('Ed25519VerificationKey2020');
    expect(verificationMethodPublicKey(vm).kty).toBe('OKP');
    // MOSIP lists the bare DID under assertionMethod, not the verification method: that is not a relationship (DID Core 5.3)
    expect(hasRelationship(r.didDocument as DidDocument, 'assertionMethod', vm.id)).toBe(false);
    const bad = await resolveDidLocally('did:web:localhost%3A8080', { fetch: fakeFetch({ 'http://localhost:8080/.well-known/did.json': () => json({ id: 'did:web:other' }) }).fetch, httpHosts: ['localhost'] });
    expect(didError(bad)).toBe('INVALID_DID_DOCUMENT');
    const unsupported = await resolveDidLocally('did:ebsi:z123', { fetch });
    expect(didError(unsupported)).toBe('METHOD_NOT_SUPPORTED');
  });
});

describe('JOSE', () => {
  it('verifies ES256 JWS and rejects tampering and alg none', () => {
    const { privateKey, jwk } = es256Key();
    const jwt = signJwt({ alg: 'ES256', typ: 'JWT' }, { hello: 'world' }, privateKey);
    const jws = decodeJws(jwt);
    expect(verifyJws(jws, jwk as never)).toBe(true);
    const parts = jwt.split('.');
    const tampered = decodeJws(`${parts[0]}.${Buffer.from('{"hello":"mars"}').toString('base64url')}.${parts[2]}`);
    expect(verifyJws(tampered, jwk as never)).toBe(false);
    expect(verifyJws({ ...jws, header: { alg: 'none' } }, jwk as never)).toBe(false);
  });

  it('verifies EdDSA and RSA PSS / PKCS1 signatures', () => {
    const msg = new TextEncoder().encode('data');
    const ed = generateKeyPairSync('ed25519');
    const edJwk = ed.publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const edSig = nodeSign(null, msg, ed.privateKey);
    expect(verifySignature('EdDSA', { kty: 'OKP', crv: 'Ed25519', x: bytes.base64UrlDecode(edJwk.x!) }, msg, edSig)).toBe(true);
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rJwk = rsa.publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const pub = { kty: 'RSA' as const, n: bytes.bytesToBigInt(bytes.base64UrlDecode(rJwk.n!)), e: bytes.bytesToBigInt(bytes.base64UrlDecode(rJwk.e!)) };
    expect(verifySignature('RS256', pub, msg, nodeSign('sha256', msg, rsa.privateKey))).toBe(true);
    const pss = nodeSign('sha256', msg, { key: rsa.privateKey, padding: 6, saltLength: 32 });
    expect(verifySignature('PS256', pub, msg, pss)).toBe(true);
    expect(verifySignature('PS256', pub, new TextEncoder().encode('other'), pss)).toBe(false);
    void createPrivateKey;
  });

  it('computes the RFC 7638 thumbprint test vector', () => {
    const jwk = { kty: 'RSA', e: 'AQAB', n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw' };
    expect(jwkThumbprint(jwk)).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });
});

describe('JOSE: the algorithm must fit the key', () => {
  const b64u = (v: string | Uint8Array) => Buffer.from(v as string).toString('base64url');
  /** A compact JWS signed as node:crypto would for this key, whatever the header claims. */
  function jws(header: Record<string, unknown>, key: KeyObject, hash: string | null = 'sha256', options: Record<string, unknown> = {}): string {
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify({ a: 1 }))}`;
    return `${input}.${b64u(nodeSign(hash, Buffer.from(input), { key, dsaEncoding: 'ieee-p1363', ...options }))}`;
  }
  const ec = (namedCurve: string) => {
    const k = generateKeyPairSync('ec', { namedCurve });
    return { key: k.privateKey, jwk: k.publicKey.export({ format: 'jwk' }) as never };
  };
  const p256 = ec('prime256v1');
  const p384 = ec('secp384r1');
  const p521 = ec('secp521r1');
  const k256 = ec('secp256k1');
  const verify = (token: string, jwk: never, opts?: Parameters<typeof verifyJws>[2]) => verifyJws(decodeJws(token), jwk, opts);

  it('verifies each ECDSA algorithm with its own curve', () => {
    expect(verify(jws({ alg: 'ES256' }, p256.key, 'sha256'), p256.jwk)).toBe(true);
    expect(verify(jws({ alg: 'ES384' }, p384.key, 'sha384'), p384.jwk)).toBe(true);
    expect(verify(jws({ alg: 'ES512' }, p521.key, 'sha512'), p521.jwk)).toBe(true);
    expect(verify(jws({ alg: 'ES256K' }, k256.key, 'sha256'), k256.jwk)).toBe(true);
  });

  it('rejects an ECDSA algorithm used with another curve, though the signature is mathematically valid', () => {
    // each of these is a correct ECDSA signature with the stated hash under the given key
    expect(verify(jws({ alg: 'ES256' }, p384.key, 'sha256'), p384.jwk)).toBe(false); // was accepted
    expect(verify(jws({ alg: 'ES256' }, p521.key, 'sha256'), p521.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES384' }, p256.key, 'sha384'), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES512' }, p256.key, 'sha512'), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES512' }, p384.key, 'sha512'), p384.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES256K' }, p256.key, 'sha256'), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES256' }, k256.key, 'sha256'), k256.jwk)).toBe(false);
    // the same binding for COSE and any other raw-signature caller of verifySignature
    const msg = new TextEncoder().encode('data');
    const key384 = { kty: 'EC' as const, crv: 'P-384' as const, point: Buffer.concat([Buffer.from([4]), Buffer.from((p384.jwk as { x: string }).x, 'base64url'), Buffer.from((p384.jwk as { y: string }).y, 'base64url')]) };
    expect(verifySignature('ES256', key384, msg, nodeSign('sha256', msg, { key: p384.key, dsaEncoding: 'ieee-p1363' }))).toBe(false);
    expect(verifySignature('ES384', key384, msg, nodeSign('sha384', msg, { key: p384.key, dsaEncoding: 'ieee-p1363' }))).toBe(true);
    // X.509 names only the hash: ecdsa-with-SHA256 under a P-384 key is legitimate there (DER signatures)
    expect(verifySignature('ES256', key384, msg, nodeSign('sha256', msg, { key: p384.key, dsaEncoding: 'der' }), 'der')).toBe(true);
  });

  it('rejects an algorithm of another key type', () => {
    const ed = generateKeyPairSync('ed25519');
    const edJwk = ed.publicKey.export({ format: 'jwk' }) as never;
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaJwk = rsa.publicKey.export({ format: 'jwk' }) as never;
    expect(verify(jws({ alg: 'EdDSA' }, ed.privateKey, null), edJwk)).toBe(true);
    expect(verify(jws({ alg: 'RS256' }, rsa.privateKey), rsaJwk)).toBe(true);
    expect(verify(jws({ alg: 'PS256' }, rsa.privateKey, 'sha256', { padding: 6, saltLength: 32 }), rsaJwk)).toBe(true);
    expect(verify(jws({ alg: 'EdDSA' }, p256.key), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES256' }, ed.privateKey, null), edJwk)).toBe(false);
    expect(verify(jws({ alg: 'RS256' }, p256.key), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'PS256' }, p256.key), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES256' }, rsa.privateKey), rsaJwk)).toBe(false);
    expect(verify(jws({ alg: 'EdDSA' }, rsa.privateKey), rsaJwk)).toBe(false);
    // alg must be a string naming a supported algorithm: not an array, not a property of Object.prototype
    expect(verify(jws({ alg: ['ES256'] }, p256.key), p256.jwk)).toBe(false);
    for (const alg of ['toString', 'constructor', '__proto__', 'none', 'HS256']) {
      expect(isSupportedJoseAlg(alg), alg).toBe(false);
      expect(verify(jws({ alg }, p256.key), p256.jwk), alg).toBe(false);
    }
    // a key that cannot be read is a failed verification, not an exception
    expect(verify(jws({ alg: 'ES256' }, p256.key), { kty: 'EC', crv: 'P-999', x: 'AA', y: 'AA' } as never)).toBe(false);
  });

  it('rejects a JWS whose crit lists a header parameter that is not understood (RFC 7515 section 4.1.11)', () => {
    const ext = 'urn:example:ext';
    expect(verify(jws({ alg: 'ES256', crit: [ext], [ext]: true }, p256.key), p256.jwk)).toBe(false); // was accepted: crit ignored
    expect(verify(jws({ alg: 'ES256', crit: ['b64'], b64: false }, p256.key), p256.jwk)).toBe(false);
    expect(verify(jws({ alg: 'ES256', crit: ['exp'] }, p256.key), p256.jwk)).toBe(false);
    // malformed crit: empty, not an array, not strings
    for (const crit of [[], 'exp', [1], [''], null, {}]) expect(verify(jws({ alg: 'ES256', crit }, p256.key), p256.jwk), JSON.stringify(crit)).toBe(false);
    // a caller that processes an extension itself declares it; it must then really be in the header, and listed once
    expect(verify(jws({ alg: 'ES256', crit: [ext], [ext]: true }, p256.key), p256.jwk, { understoodCritical: [ext] })).toBe(true);
    expect(verify(jws({ alg: 'ES256', crit: [ext] }, p256.key), p256.jwk, { understoodCritical: [ext] })).toBe(false);
    expect(verify(jws({ alg: 'ES256', crit: [ext, ext], [ext]: true }, p256.key), p256.jwk, { understoodCritical: [ext] })).toBe(false);
    expect(verify(jws({ alg: 'ES256', crit: [ext, 'other'], [ext]: true, other: 1 }, p256.key), p256.jwk, { understoodCritical: [ext] })).toBe(false);
    expect(criticalHeaderProblem({ alg: 'ES256' })).toBeNull();
    expect(criticalHeaderProblem({ alg: 'ES256', crit: [ext], [ext]: 1 })).toBe(`critical header parameter ${ext} is not understood`);
    // without crit nothing changes
    expect(verify(jws({ alg: 'ES256', [ext]: true }, p256.key), p256.jwk)).toBe(true);
  });

  it('rejects RSA keys below 2048 bits and public exponents of 1 or even', () => {
    const msg = new TextEncoder().encode('msg');
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const weakJwk = weak.publicKey.export({ format: 'jwk' }) as never;
    expect(verify(jws({ alg: 'RS256' }, weak.privateKey), weakJwk)).toBe(false); // was accepted
    expect(verify(jws({ alg: 'PS256' }, weak.privateKey, 'sha256', { padding: 6, saltLength: 32 }), weakJwk)).toBe(false);
    // e = 1: the padded hash is its own signature, for any modulus
    const n = (1n << 2047n) + 1234567n;
    const t = Buffer.concat([Buffer.from('3031300d060960864801650304020105000420', 'hex'), createHash('sha256').update(msg).digest()]);
    const em = Buffer.alloc(256, 0xff);
    em[0] = 0; em[1] = 1; em[256 - t.length - 1] = 0;
    t.copy(em, 256 - t.length);
    expect(verifyPkcs1({ n, e: 1n }, 'SHA-256', msg, em)).toBe(false); // was accepted
    expect(verifySignature('RS256', { kty: 'RSA', n, e: 1n }, msg, em)).toBe(false);
    expect(rsaKeyProblem({ n, e: 1n })).toBe('the public exponent is 1');
    expect(rsaKeyProblem({ n, e: 65536n })).toBe('the public exponent is even');
    expect(rsaKeyProblem({ n: (1n << 2046n) + 1n, e: 65537n })).toMatch(/2047 bits, fewer than 2048/);
    expect(rsaKeyProblem({ n: (1n << 2047n) + 2n, e: 65537n })).toBe('the modulus is even');
    expect(rsaKeyProblem({ n: (1n << 16383n) + 1n, e: 65537n })).toMatch(/more than 8192/);
    expect(rsaKeyProblem({ n, e: (1n << 300n) + 1n })).toMatch(/exponent has more than 256 bits/);
    expect(rsaKeyProblem({ n, e: 3n })).toBeNull();
    expect(rsaKeyProblem({ n, e: 65537n })).toBeNull();
  });
});

