import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import { bytes, cbor } from '@vctrust/trust-client/primitives';
import { concatKdf, decryptJwe, encryptJwe, openId4VpHandover, SoftwareKey, createPkce, Dpop, decodeDisclosure, type AuthorizationRequest } from '../src/index.js';
import { sha256 } from '@noble/hashes/sha2.js';

describe('spec test vectors', () => {
  it('OpenID4VP 1.0 B.2.6.1 SessionTranscript / OpenID4VPHandover', () => {
    const req = { clientId: 'x509_san_dns:example.com', nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA', responseUri: 'https://example.com/response' } as AuthorizationRequest;
    const jwk = { kty: 'EC', crv: 'P-256', x: 'DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0', y: 'XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc', use: 'enc', alg: 'ECDH-ES', kid: '1' };
    const transcript = cbor.encode([null, null, openId4VpHandover(req, jwk)]);
    expect(bytes.toHex(transcript)).toBe('83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac');
  });

  it('RFC 7518 Appendix C: ECDH-ES Concat KDF', () => {
    const alice = { d: '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo' };
    const bob = { x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ', y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck' };
    const z = p256.getSharedSecret(bytes.base64UrlDecode(alice.d),
      bytes.concatBytes(Uint8Array.of(4), bytes.base64UrlDecode(bob.x), bytes.base64UrlDecode(bob.y))).subarray(1);
    const key = concatKdf(z, 'A128GCM', bytes.utf8Encode('Alice'), bytes.utf8Encode('Bob'));
    expect(bytes.base64UrlEncode(key)).toBe('VqqN6vgjbSBcIijNcacQGg');
  });

  it('RFC 7636 PKCE S256 shape', () => {
    const p = createPkce();
    expect(p.challenge).toBe(bytes.base64UrlEncode(sha256(bytes.utf8Encode(p.verifier))));
    expect(p.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('SD-JWT disclosure digest (RFC 9901 example)', () => {
    const d = decodeDisclosure('WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd');
    expect(d.name).toBe('given_name');
    expect(d.digest).toBe('jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4');
  });
});

describe('JWE', () => {
  it('round-trips ECDH-ES + A128GCM / A256GCM', () => {
    const recipient = SoftwareKey.generate();
    for (const enc of ['A128GCM', 'A256GCM'] as const) {
      const jwe = encryptJwe(bytes.utf8Encode('{"vp_token":{}}'), { ...recipient.publicJwk, kid: 'k1', alg: 'ECDH-ES' }, enc);
      const header = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(jwe.split('.')[0]!)));
      expect(header).toMatchObject({ alg: 'ECDH-ES', enc, kid: 'k1' });
      expect(bytes.utf8Decode(decryptJwe(jwe, (p) => recipient.ecdh(p)).plaintext)).toBe('{"vp_token":{}}');
      const parts = jwe.split('.');
      parts[3] = bytes.base64UrlEncode(bytes.utf8Encode('tampered-cipher'));
      expect(() => decryptJwe(parts.join('.'), (p) => recipient.ecdh(p))).toThrow();
    }
  });
});

describe('DPoP', () => {
  it('binds proofs to method, URL (no query) and access token; tracks server nonces', async () => {
    const dpop = new Dpop(SoftwareKey.generate());
    let calls = 0;
    const f = (async (_u: string, init?: RequestInit) => {
      calls++;
      const proof = new Headers(init?.headers).get('DPoP')!;
      const payload = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(proof.split('.')[1]!)));
      expect(payload.htu).toBe('https://as.example/token');
      expect(payload.htm).toBe('POST');
      if (!payload.nonce) return new Response(JSON.stringify({ error: 'use_dpop_nonce' }), { status: 400, headers: { 'DPoP-Nonce': 'n1' } });
      expect(payload.nonce).toBe('n1');
      expect(payload.ath).toBe(bytes.base64UrlEncode(sha256(bytes.utf8Encode('AT'))));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;
    const r = await dpop.fetch(f, 'https://as.example/token?x=1#y', { method: 'POST' }, 'AT');
    expect(r.status).toBe(200);
    expect(calls).toBe(2);
  });
});
