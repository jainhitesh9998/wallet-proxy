/** Signed issuer metadata (OID4VCI §12.2.3, HAIP §4.1): verified on the device, untrusted or missing signatures refused. */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { bytes, createTrustClient } from '../src/index.js';

const PKI = new URL('./fixtures/pki/', import.meta.url);
const pem = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8');
const b64 = (n: string) => pem(n).replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const enc = (o: unknown) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(o)));
const ISSUER = 'https://issuer.example';

function sign(header: object, payload: object, key: string): string {
  const input = `${enc(header)}.${enc(payload)}`;
  const sig = createSign('SHA256').update(input).sign({ key: createPrivateKey(readFileSync(new URL(`${key}.key`, PKI))), dsaEncoding: 'ieee-p1363' });
  return `${input}.${bytes.base64UrlEncode(new Uint8Array(sig))}`;
}

const metadata = { credential_issuer: ISSUER, credential_endpoint: `${ISSUER}/credential`, credential_configurations_supported: { pid: { format: 'dc+sd-jwt' } } };
const signedMd = (over: { typ?: string; sub?: string; signer?: string; x5c?: string[]; exp?: number } = {}) =>
  sign({ alg: 'ES256', typ: over.typ ?? 'openidvci-issuer-metadata+jwt', x5c: over.x5c ?? [b64(over.signer ?? 'rp')] },
    { ...metadata, sub: over.sub ?? ISSUER, iat: Math.floor(Date.now() / 1000), ...(over.exp ? { exp: over.exp } : {}) }, over.signer ?? 'rp');

function client(serve: { jwt?: string }, signed: 'off' | 'verify' | 'require') {
  const accepts: string[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    const accept = new Headers(init?.headers).get('Accept') ?? '';
    if (u === `${ISSUER}/.well-known/openid-credential-issuer`) {
      accepts.push(accept);
      if (serve.jwt && accept.includes('application/jwt')) return new Response(serve.jwt, { headers: { 'Content-Type': 'application/jwt' } });
      return Response.json(metadata);
    }
    if (u === `${ISSUER}/.well-known/oauth-authorization-server`) return Response.json({ issuer: ISSUER, token_endpoint: `${ISSUER}/token` });
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
  const trust = createTrustClient({ fetch: f, issuerMetadata: { signed }, fallback: { localAnchors: [{ domain: 'credential-issuer', certificate: pem('rp-ca') }] } });
  return { trust, accepts };
}

describe('signed issuer metadata', () => {
  it('is not asked for by default', async () => {
    const { trust, accepts } = client({ jwt: signedMd() }, 'off');
    const md = await trust.getIssuerMetadata(ISSUER);
    expect(md.signedMetadata).toBeNull();
    expect(accepts).toEqual(['application/json']);
  });

  it('verifies a JWT signed by a certificate under a credential-issuer anchor and uses its claims', async () => {
    const { trust, accepts } = client({ jwt: signedMd() }, 'verify');
    const md = await trust.getIssuerMetadata(ISSUER);
    expect(accepts[0]).toBe('application/jwt, application/json;q=0.9');
    expect(md.signedMetadataVerified).toBe(true);
    expect(md.credentialIssuerMetadata).toEqual(metadata);
    expect(md.warnings.join()).toMatch(/Signed metadata verified \(signer .*\)/);
  });

  it('accepts unsigned metadata under verify, refuses it under require', async () => {
    expect((await client({}, 'verify').trust.getIssuerMetadata(ISSUER)).signedMetadata).toBeNull();
    await expect(client({}, 'require').trust.getIssuerMetadata(ISSUER)).rejects.toThrow(/no signed metadata/);
  });

  it('rejects untrusted or self-signed signers, wrong typ, sub and expiry', async () => {
    const fails = async (jwt: string, re: RegExp) => expect(client({ jwt }, 'verify').trust.getIssuerMetadata(ISSUER)).rejects.toThrow(re);
    await fails(signedMd({ signer: 'rogue-ds' }), /signer is not trusted/);
    await fails(signedMd({ signer: 'rp-ca' }), /self-signed/);
    await fails(signedMd({ typ: 'JWT' }), /typ must be openidvci-issuer-metadata\+jwt/);
    await fails(signedMd({ sub: 'https://other.example' }), /sub .* is not/);
    await fails(signedMd({ exp: 1000 }), /expired/);
    await fails(signedMd({ x5c: [b64('ds')] }), /signature does not verify/);
  });
});
