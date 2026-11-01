import { describe, expect, it } from 'vitest';
import { resolveDidLocally, verificationMethodPublicKey, findVerificationMethod, hasRelationship, decodeJws, verifyJws,
  verifySignature, jwkThumbprint, didError, bytes, type DidDocument } from '../src/index.js';
import { es256Key, fakeFetch, fixture, json, signJwt } from './helpers.js';
import { createPrivateKey, sign as nodeSign, generateKeyPairSync } from 'node:crypto';

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
    const doc = JSON.parse(fixture('Land-verificationMethod-did-web-inji.github.io-collab-landregistry.json').toString());
    const { fetch, calls } = fakeFetch({ 'https://inji.github.io/inji-config/collab/landregistry/did.json': () => json(doc) });
    const r = await resolveDidLocally('did:web:inji.github.io:inji-config:collab:landregistry', { fetch });
    expect(r.didDocument?.id).toBe('did:web:inji.github.io:inji-config:collab:landregistry');
    expect(calls).toEqual(['GET https://inji.github.io/inji-config/collab/landregistry/did.json']);
    const vm = r.didDocument!.verificationMethod![0]!;
    expect(vm.type).toBe('Ed25519VerificationKey2020');
    expect(verificationMethodPublicKey(vm).kty).toBe('OKP');
    // MOSIP lists the bare DID under assertionMethod: only accepted leniently
    expect(hasRelationship(r.didDocument as DidDocument, 'assertionMethod', vm.id, false)).toBe('no');
    expect(hasRelationship(r.didDocument as DidDocument, 'assertionMethod', vm.id, true)).toBe('lenient');
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
