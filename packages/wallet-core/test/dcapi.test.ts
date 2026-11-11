/**
 * OpenID4VP 1.0 over the Digital Credentials API (Appendix A): unsigned and signed requests, expected_origins, the
 * origin-bound audience, the OpenID4VPDCAPIHandover session transcript and dc_api / dc_api.jwt response data.
 */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createPublicKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { bytes, cbor, decodeJws, jwkThumbprintBytes, parseCertificate, publicKeyFromJwk, verifyJws, verifySignature } from '@vctrust/trust-client/primitives';
import { buildVpToken, dcApiError, decryptJwe, disclosureDigest, evaluateDcql, openId4VpHandover, pickDcApiRequest, PresentationRequestError,
  resolveDcApiRequest, sigStructure, SoftwareKey, submitResponse, type AuthorizationRequest, type KeyStore, type StoredCredential } from '../src/index.js';
import { buildMdoc } from './mdoc-builder.js';
import { b64, enc, es256, pem, pinnedTrust, PKI } from './support.js';

const ORIGIN = 'https://verifier.example';
const offline = pinnedTrust([]);
const trusted = pinnedTrust([{ domain: 'verifier-access', certificate: pem('rp-ca') }]);
const cid = `x509_hash:${parseCertificate(pem('rp')).sha256}`;
const dcql = { credentials: [
  { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claims: [{ path: ['given_name'] }] },
  { id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' }, claims: [{ path: ['org.iso.18013.5.1', 'given_name'] }] },
] };
const unsigned = { response_type: 'vp_token', response_mode: 'dc_api', nonce: 'n-1', dcql_query: dcql };
const signed = (claims: Record<string, unknown>) => ({ request: es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] },
  { client_id: cid, expected_origins: [ORIGIN], ...unsigned, ...claims }, 'rp') });
/** A JWS JSON Serialization with one signature per [protected header, key] (A.3.2.2); client_id only in the headers. */
function multiSigned(signers: [Record<string, unknown>, string][], claims: Record<string, unknown> = {}) {
  const payload = enc({ expected_origins: [ORIGIN], ...unsigned, ...claims });
  return { payload, signatures: signers.map(([header, key]) => {
    const prot = enc(header);
    const sig = createSign('SHA256').update(`${prot}.${payload}`).sign({ key: createPrivateKey(readFileSync(new URL(`${key}.key`, PKI))), dsaEncoding: 'ieee-p1363' });
    return { protected: prot, signature: bytes.base64UrlEncode(new Uint8Array(sig)) };
  }) };
}
const fail = (p: Promise<unknown>) => p.then(() => { throw new Error('expected a failure'); }, (e: unknown) => e as PresentationRequestError);

const holder = SoftwareKey.generate();
const keys = { get: async () => holder } as unknown as KeyStore;
function sdJwt(): string {
  const disclosures = [['s1', 'given_name', 'Erika'], ['s2', 'family_name', 'Mustermann']].map((d) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(d))));
  const payload = { iss: 'https://issuer.example', vct: 'urn:eudi:pid:1', iat: Math.floor(Date.now() / 1000), _sd_alg: 'sha-256',
    _sd: disclosures.map(disclosureDigest), cnf: { jwk: holder.publicJwk } };
  return `${es256({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [b64(pem('rp'))] }, payload, 'rp')}~${disclosures.join('~')}~`;
}
const sd: StoredCredential = { id: 'c1', format: 'dc+sd-jwt', configurationId: 'pid', credential: sdJwt(), credentialIssuer: 'https://issuer.example',
  holderKeyId: holder.id, holderJwk: holder.publicJwk, issuedAt: new Date().toISOString(), report: { credentialType: 'urn:eudi:pid:1' } as never };
const mdl: StoredCredential = { id: 'c2', format: 'mso_mdoc', configurationId: 'mdl', credential: buildMdoc(holder),
  credentialIssuer: 'https://mdl.example', holderKeyId: holder.id, holderJwk: holder.publicJwk, issuedAt: new Date().toISOString(),
  report: { credentialType: 'org.iso.18013.5.1.mDL' } as never };

/** Presents both credentials for a resolved request the way PresentationSession.respond does. */
async function present(request: AuthorizationRequest) {
  const r = await evaluateDcql(request.dcqlQuery, [sd, mdl]);
  expect(r.satisfied).toBe(true);
  const selection = Object.fromEntries(r.selected.map((id) => {
    const m = r.matches.find((x) => x.query.id === id)!;
    return [id, { credential: m.candidates[0]!, claims: m.claims }];
  }));
  return submitResponse(request, { vp_token: await buildVpToken(request, selection, keys, trusted) }, fetch);
}

describe('OpenID4VP over the DC API', () => {
  it('OpenID4VP 1.0 B.2.6.2 test vector: OpenID4VPDCAPIHandover', () => {
    const req = { origin: 'https://example.com', nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA' } as AuthorizationRequest;
    const jwk = { kty: 'EC', crv: 'P-256', x: 'DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0', y: 'XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc', use: 'enc', alg: 'ECDH-ES', kid: '1' };
    expect(bytes.toHex(cbor.encode(openId4VpHandover(req, jwk))))
      .toBe('82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a');
  });

  it('picks the request it supports, signed before unsigned, from the current and the older request shapes', () => {
    const json = { requests: [{ protocol: 'org-iso-mdoc', data: {} }, { protocol: 'openid4vp-v1-unsigned', data: unsigned }, { protocol: 'openid4vp-v1-signed', data: { request: 'x' } }] };
    expect(pickDcApiRequest(JSON.stringify(json), ORIGIN)).toEqual({ protocol: 'openid4vp-v1-signed', data: { request: 'x' }, origin: ORIGIN });
    expect(pickDcApiRequest({ providers: [{ protocol: 'openid4vp-v1-unsigned', request: unsigned }] }, ORIGIN)?.data).toEqual(unsigned);
    expect(pickDcApiRequest({ requests: [{ protocol: 'openid4vp', data: {} }] }, ORIGIN)).toBeUndefined();
    expect(pickDcApiRequest(json, ORIGIN, 1)?.protocol).toBe('openid4vp-v1-unsigned');           // the matcher's choice wins
    expect(pickDcApiRequest(json, ORIGIN, 0)?.protocol).toBe('openid4vp-v1-signed');             // unless it is not OpenID4VP
  });

  it('answers an unsigned request with the response bound to the origin, ignoring any client_id', async () => {
    const { request, verifier } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data: { ...unsigned, client_id: 'x509_san_dns:bank.example' }, origin: ORIGIN }, offline);
    expect(request).toMatchObject({ clientId: `origin:${ORIGIN}`, prefix: 'origin', origin: ORIGIN, signed: false, responseMode: 'dc_api' });
    expect(verifier.refusal).toBeUndefined();                        // UNKNOWN: left to the user
    expect(verifier.checks.find((c) => c.label === 'Verifier origin')?.detail).toContain(ORIGIN);
    const r = await present(request);
    expect(r.status).toBe(0);
    const vpToken = r.dcApi!.vp_token as Record<string, string[]>;
    const kb = decodeJws(vpToken.pid![0]!.split('~').at(-1)!);
    expect(kb.payload).toMatchObject({ aud: `origin:${ORIGIN}`, nonce: 'n-1' });
    expect(verifyJws(kb, holder.publicJwk)).toBe(true);
    expect(r.dcApi).not.toHaveProperty('state');
    // the verifier is judged by origin:<origin>, which the evaluators map to the registry's URL identifiers
    const asked: unknown[] = [];
    const spy = { ...offline, evaluateVerifier: async (q: unknown) => { asked.push(q); return offline.evaluateVerifier(q as never); } } as typeof offline;
    await resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data: unsigned, origin: ORIGIN }, spy);
    expect(asked).toEqual([expect.objectContaining({ clientId: `origin:${ORIGIN}`, x5c: undefined, kid: undefined })]);
  });

  it('authenticates a signed request, requires the origin in expected_origins and still uses the origin as audience', async () => {
    const { request, verifier } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: signed({}), origin: ORIGIN }, trusted);
    expect(request).toMatchObject({ clientId: cid, prefix: 'x509_hash', signed: true, origin: ORIGIN });
    expect(verifier.trust.decision).toBe('TRUSTED');
    expect(verifier.checks.map((c) => c.label)).toEqual(expect.arrayContaining(['Request signature', 'x509_hash binding', 'Expected origins']));
    const kb = decodeJws(((await present(request)).dcApi!.vp_token as Record<string, string[]>).pid![0]!.split('~').at(-1)!);
    expect(kb.payload.aud).toBe(`origin:${ORIGIN}`);                  // A.4: even for signed requests

    const replayed = await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: signed({}), origin: 'https://evil.example' }, trusted));
    expect(replayed.message).toMatch(/made for https:\/\/verifier.example/);
    expect(dcApiError(replayed)).toEqual({ error: 'invalid_request' });
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: signed({ expected_origins: [] }), origin: ORIGIN }, trusted))).message)
      .toMatch(/expected_origins/);
  });

  it('refuses client identifiers that cannot be authenticated over the DC API', async () => {
    const redirect = signed({ client_id: `redirect_uri:${ORIGIN}/cb` });
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: redirect, origin: ORIGIN }, trusted))).message).toMatch(/redirect_uri over the DC API/);
    const origin = signed({ client_id: `origin:${ORIGIN}` });         // §5.9.3: never accepted in a request
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: origin, origin: ORIGIN }, trusted))).code).toBe('invalid_client');
    const untrustedCa = await resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: signed({}), origin: ORIGIN }, offline);
    expect(untrustedCa.verifier.refusal).toMatch(/trusted verifier CA/);
    const err = await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-signed', data: signed({ transaction_data: ['x'] }), origin: ORIGIN }, offline));
    expect(err.reportTo).toBeUndefined();                             // no error goes to a refused verifier
    expect(() => dcApiError(err)).toThrow();
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp', data: {}, origin: ORIGIN }, trusted))).message).toMatch(/Unsupported DC API protocol/);
  });

  it('answers a multi-signed request as the first client it can authenticate and does not refuse', async () => {
    const rp = { alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] };
    const forged = { ...rp, client_id: 'x509_hash:AAAA' };              // hash of no certificate: cannot be authenticated
    const good = { ...rp, client_id: cid };
    const data = { request: multiSigned([[forged, 'rp'], [good, 'rp']]) };
    const { request, verifier } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data, origin: ORIGIN }, trusted);
    expect(request).toMatchObject({ clientId: cid, prefix: 'x509_hash', signed: true, origin: ORIGIN });
    expect(verifier.checks.find((c) => c.label === 'Multi-signed request')?.detail).toContain(cid);
    expect(verifier.refusal).toBeUndefined();
    // as a JSON string too; every signature's protected header carries the request object typ (§5)
    const asString = { request: JSON.stringify(multiSigned([[good, 'rp']])) };
    expect((await resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data: asString, origin: ORIGIN }, trusted)).request.clientId).toBe(cid);
    for (const typ of ['JWT', undefined]) {
      const bad = { request: multiSigned([[{ ...good, typ }, 'rp']]) };
      expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data: bad, origin: ORIGIN }, trusted))).message).toMatch(/typ/);
    }
    // client_id belongs in each protected header; one in the payload does not count
    const noClient = { request: multiSigned([[rp, 'rp']], { client_id: cid }) };
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data: noClient, origin: ORIGIN }, trusted))).code).toBe('invalid_client');
    // every signer refused (no trusted CA): the user sees the refusal; expected_origins still applies
    expect((await resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data, origin: ORIGIN }, offline)).verifier.refusal).toMatch(/trusted verifier CA/);
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data, origin: 'https://evil.example' }, trusted))).message).toMatch(/made for/);
    expect((await fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data: { request: 'x.y.z' }, origin: ORIGIN }, trusted))).message).toMatch(/JWS JSON/);
  });

  it('answers a multi-signed request as its best signer: TRUSTED before UNKNOWN, whatever the order', async () => {
    const jwk = createPublicKey(pem('rp')).export({ format: 'jwk' });
    const did = `did:jwk:${bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })))}`;
    const byDid = { alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: `${did}#0`, client_id: `decentralized_identifier:${did}` };
    const byCert = { alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))], client_id: cid };
    const data = { request: multiSigned([[byDid, 'rp'], [byCert, 'rp']]) };
    const { request, verifier } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data, origin: ORIGIN }, trusted);
    expect(request.clientId).toBe(cid);
    expect(verifier.trust.decision).toBe('TRUSTED');
    // without a trusted CA the certificate signer is refused; the DID signer (UNKNOWN, left to the user) answers
    const alone = await resolveDcApiRequest({ protocol: 'openid4vp-v1-multisigned', data, origin: ORIGIN }, offline);
    expect(alone.request.prefix).toBe('decentralized_identifier');
    expect(alone.verifier.refusal).toBeUndefined();
  });

  it('names the verifier by the registry, and marks a name it gives itself', async () => {
    const data = { ...unsigned, client_metadata: { client_name: 'Your Bank', logo_uri: 'https://evil.example/bank.png' } };
    const { verifier } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data, origin: ORIGIN }, offline);
    expect(verifier).toMatchObject({ name: 'Your Bank', nameSelfDeclared: true, origin: ORIGIN });
  });

  it('checks the request itself: response mode, nonce and an encryption key for dc_api.jwt', async () => {
    const bad = (data: Record<string, unknown>) => fail(resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data: { ...unsigned, ...data }, origin: ORIGIN }, offline));
    expect((await bad({ response_mode: 'direct_post' })).message).toMatch(/response_mode direct_post over the DC API/);
    expect((await bad({ nonce: '' })).message).toMatch(/nonce/);
    expect((await bad({ response_mode: 'dc_api.jwt' })).message).toMatch(/ECDH-ES for dc_api.jwt/);
    const key = { ...SoftwareKey.generate().publicJwk, alg: 'ECDH-ES', kid: 'e' };
    expect((await bad({ response_mode: 'dc_api.jwt', client_metadata: { jwks: { keys: [key] }, encrypted_response_enc_values_supported: ['A192GCM'] } })).message)
      .toMatch(/none of the response encryption algorithms/);
    expect((await bad({ transaction_data: ['x'] })).reportTo).toEqual({ dcApi: true });     // the user may send it after seeing it
    await expect(resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data: unsigned, origin: '' }, offline)).rejects.toThrow(/origin/);
  });

  it('encrypts dc_api.jwt responses and binds the mdoc to the origin, nonce and encryption key', async () => {
    const verifierKey = p256.utils.randomSecretKey();
    const pub = p256.getPublicKey(verifierKey, false);
    const jwk = { kty: 'EC', crv: 'P-256', x: bytes.base64UrlEncode(pub.subarray(1, 33)), y: bytes.base64UrlEncode(pub.subarray(33)), use: 'enc', alg: 'ECDH-ES', kid: 'e1' };
    const data = { ...unsigned, response_mode: 'dc_api.jwt', client_metadata: { jwks: { keys: [jwk] }, encrypted_response_enc_values_supported: ['A256GCM'] } };
    const { request } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data, origin: ORIGIN }, offline);
    const r = await present(request);
    expect(Object.keys(r.dcApi!)).toEqual(['response']);
    const { header, plaintext } = decryptJwe(r.dcApi!.response as string, (peer) => p256.getSharedSecret(verifierKey, peer).subarray(1));
    expect(header).toMatchObject({ alg: 'ECDH-ES', enc: 'A256GCM', kid: 'e1' });
    const vpToken = JSON.parse(bytes.utf8Decode(plaintext)).vp_token as Record<string, string[]>;
    const doc = ((cbor.decode(bytes.base64UrlDecode(vpToken.mdl![0]!)) as Map<string, unknown>).get('documents') as Map<string, unknown>[])[0]!;
    const sig = (doc.get('deviceSigned') as Map<string, Map<string, unknown[]>>).get('deviceAuth')!.get('deviceSignature') as unknown[];
    const handover = ['OpenID4VPDCAPIHandover', (await import('@noble/hashes/sha2.js')).sha256(cbor.encode([ORIGIN, 'n-1', jwkThumbprintBytes(jwk)]))];
    const da = ['DeviceAuthentication', [null, null, handover], 'org.iso.18013.5.1.mDL', new cbor.Tagged(24, cbor.encode(new Map()))];
    const payload = cbor.encode(new cbor.Tagged(24, cbor.encode(da)));
    expect(verifySignature('ES256', publicKeyFromJwk(holder.publicJwk), sigStructure(sig[0] as Uint8Array, payload), sig[3] as Uint8Array)).toBe(true);
  });

  it('returns a single error member, never the state or a description', async () => {
    const { request } = await resolveDcApiRequest({ protocol: 'openid4vp-v1-unsigned', data: unsigned, origin: ORIGIN }, offline);
    expect((await submitResponse(request, { error: 'access_denied', error_description: 'User declined' }, fetch)).dcApi).toEqual({ error: 'access_denied' });
  });
});
