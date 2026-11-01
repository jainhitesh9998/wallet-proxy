/** Offline flow tests: offers, SD-JWT VC verification, OpenID4VP request validation, DCQL and presentations. */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createTrustClient, bytes, cbor, decodeJws, verifyJws, parseCertificate } from '@vctrust/trust-client';
import { resolveCredentialOffer, verifySdJwtVc, resolveAuthorizationRequest, evaluateDcql, presentSdJwt, presentMdoc, SoftwareKey,
  disclosureDigest, sigStructure, type StoredCredential, type DcqlQuery } from '../src/index.js';

const PKI = new URL('../../trust-client/test/fixtures/pki/', import.meta.url);
const pem = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8');
const b64 = (p: string) => p.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const keyOf = (n: string) => createPrivateKey(readFileSync(new URL(`${n}.key`, PKI)));
const enc = (o: unknown) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(o)));

function es256(header: object, payload: object, keyName: string): string {
  const input = `${enc(header)}.${enc(payload)}`;
  const sig = createSign('SHA256').update(input).sign({ key: keyOf(keyName), dsaEncoding: 'ieee-p1363' });
  return `${input}.${bytes.base64UrlEncode(new Uint8Array(sig))}`;
}

const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json' } });
const offline = (anchors: { domain: string; certificate: string }[]) => createTrustClient({ fetch: (async () => { throw new TypeError('offline'); }) as typeof fetch,
  fallback: { localAnchors: anchors } });

describe('credential offers', () => {
  it('parses by value and by reference', async () => {
    const offer = { credential_issuer: 'https://issuer.example', credential_configuration_ids: ['mdl'], grants: { authorization_code: {} } };
    expect((await resolveCredentialOffer(`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`, fetch)).credential_issuer).toBe('https://issuer.example');
    const f = (async () => json(offer)) as typeof fetch;
    expect((await resolveCredentialOffer('haip-vci://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fo%2F1', f)).credential_configuration_ids).toEqual(['mdl']);
    await expect(resolveCredentialOffer('openid-credential-offer://?credential_offer_uri=1234', f)).rejects.toThrow(/not a URL/);
    await expect(resolveCredentialOffer('{"credential_issuer":"x"}', f)).rejects.toThrow(/Invalid credential offer/);
  });
});

// An SD-JWT VC signed by the fixture "rsa-leaf"? No: ES256 issuer leaf "ds" isn't for SD-JWT; use rp (EC leaf) under rp-ca as issuer CA.
function makeSdJwt(holder: SoftwareKey, tamper = false) {
  const disclosures = [['s1', 'given_name', 'Erika'], ['s2', 'family_name', 'Mustermann'], ['s3', 'birthdate', '1984-01-26']]
    .map((d) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(d))));
  const payload = { iss: 'https://issuer.example', vct: 'urn:eudi:pid:1', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600,
    _sd_alg: 'sha-256', _sd: disclosures.map(disclosureDigest), cnf: { jwk: holder.publicJwk } };
  const jwt = es256({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [b64(pem('rp'))] }, payload, 'rp');
  const extra = tamper ? [bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(['s9', 'admin', true])))] : [];
  return `${jwt}~${[...disclosures, ...extra].join('~')}~`;
}

describe('SD-JWT VC verification', () => {
  it('verifies signature, disclosures, holder binding and issuer trust (credential-issuer domain)', async () => {
    const holder = SoftwareKey.generate();
    const trust = offline([{ domain: 'credential-issuer', certificate: pem('rp-ca') }]);
    const r = await verifySdJwtVc(makeSdJwt(holder), { trust, holderJwk: holder.publicJwk });
    expect(r.valid).toBe(true);
    expect(r.claims).toMatchObject({ given_name: 'Erika', family_name: 'Mustermann', vct: 'urn:eudi:pid:1' });
    expect(r.trust?.decision).toBe('TRUSTED');
    expect(r.trust?.source).toBe('fallback');
  });

  it('rejects unreferenced disclosures and foreign holder keys', async () => {
    const holder = SoftwareKey.generate();
    const r = await verifySdJwtVc(makeSdJwt(holder, true), { holderJwk: SoftwareKey.generate().publicJwk });
    expect(r.valid).toBe(false);
    expect(r.checks.find((c) => c.id === 'sdjwt.disclosures')?.status).toBe('fail');
    expect(r.checks.find((c) => c.id === 'sdjwt.holder')?.status).toBe('fail');
  });
});

describe('OpenID4VP request validation', () => {
  const rpHash = parseCertificate(pem('rp')).sha256;
  const base = (clientId: string) => ({ client_id: clientId, response_type: 'vp_token', response_mode: 'direct_post', nonce: 'n-0S6_WzA2Mj',
    response_uri: 'https://verifier.example/post', dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] } }] } });
  const serve = (jwt: string) => (async () => new Response(jwt, { headers: { 'Content-Type': 'application/oauth-authz-req+jwt' } })) as typeof fetch;
  const uri = (clientId: string) => `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent('https://verifier.example/req/1')}`;
  const trust = offline([{ domain: 'verifier-access', certificate: pem('rp-ca') }]);

  it('accepts x509_hash and x509_san_dns requests and evaluates verifier trust', async () => {
    for (const cid of [`x509_hash:${rpHash}`, 'x509_san_dns:verifier.example']) {
      const jwt = es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, base(cid), 'rp');
      const { request, verifier } = await resolveAuthorizationRequest(uri(cid), trust, serve(jwt));
      expect(request.nonce).toBe('n-0S6_WzA2Mj');
      expect(verifier.trust.decision).toBe('TRUSTED');
    }
  });

  it('rejects hash mismatch, wrong typ, client_id mismatch, unsigned x509 requests and presentation_definition', async () => {
    const bad = es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, base('x509_hash:AAAA'), 'rp');
    await expect(resolveAuthorizationRequest(uri('x509_hash:AAAA'), trust, serve(bad))).rejects.toThrow(/x509_hash/);
    const typ = es256({ alg: 'ES256', typ: 'JWT', x5c: [b64(pem('rp'))] }, base(`x509_hash:${rpHash}`), 'rp');
    await expect(resolveAuthorizationRequest(uri(`x509_hash:${rpHash}`), trust, serve(typ))).rejects.toThrow(/typ/);
    const other = es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, base(`x509_hash:${rpHash}`), 'rp');
    await expect(resolveAuthorizationRequest(uri('x509_san_dns:verifier.example'), trust, serve(other))).rejects.toThrow(/client_id/);
    const pd = es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, { ...base(`x509_hash:${rpHash}`), presentation_definition: {} }, 'rp');
    await expect(resolveAuthorizationRequest(uri(`x509_hash:${rpHash}`), trust, serve(pd))).rejects.toThrow(/presentation_definition/);
    const forged = es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, base('x509_san_dns:verifier.example'), 'ds');
    await expect(resolveAuthorizationRequest(uri('x509_san_dns:verifier.example'), trust, serve(forged))).rejects.toThrow(/signature/);
  });
});

describe('DCQL and presentations', () => {
  const holder = SoftwareKey.generate();
  const sd: StoredCredential = { id: 'c1', format: 'dc+sd-jwt', configurationId: 'pid', credential: makeSdJwt(holder), credentialIssuer: 'https://issuer.example',
    holderKeyId: holder.id, holderJwk: holder.publicJwk, issuedAt: new Date().toISOString(), report: { credentialType: 'urn:eudi:pid:1' } as never };
  const mosip = JSON.parse(readFileSync(new URL('../../trust-client/test/fixtures/MockMdl-DrivingLicenseCredential.json', import.meta.url), 'utf8'));
  const mdl: StoredCredential = { id: 'c2', format: 'mso_mdoc', configurationId: 'mdl', credential: mosip.credentials?.[0]?.credential ?? mosip.credential,
    credentialIssuer: 'https://mdl.example', holderKeyId: holder.id, holderJwk: holder.publicJwk, issuedAt: new Date().toISOString(),
    report: { credentialType: 'org.iso.18013.5.1.mDL' } as never };

  const query: DcqlQuery = { credentials: [
    { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claims: [{ path: ['given_name'] }] },
    { id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' }, claims: [{ path: ['org.iso.18013.5.1', 'given_name'] }] },
    { id: 'none', format: 'mso_mdoc', meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' } },
  ], credential_sets: [{ options: [['pid'], ['none']] }, { options: [['mdl']] }, { options: [['none']], required: false }] };

  it('selects satisfiable options across credential sets', async () => {
    const r = await evaluateDcql(query, [sd, mdl]);
    expect(r.satisfied).toBe(true);
    expect(r.selected).toEqual(['pid', 'mdl']);
    const missing = await evaluateDcql({ credentials: [{ id: 'x', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
      claims: [{ path: ['org.iso.18013.5.1', 'not_there'] }] }] }, [mdl]);
    expect(missing.satisfied).toBe(false);
  });

  const req = { clientId: 'x509_san_dns:verifier.example', nonce: 'nonce-1', responseUri: 'https://verifier.example/post', responseMode: 'direct_post',
    clientMetadata: {} } as never;

  it('builds an SD-JWT presentation with selective disclosure and a valid KB-JWT', async () => {
    const vp = await presentSdJwt(sd, [{ path: ['given_name'] }], req, holder);
    const parts = vp.split('~');
    expect(parts).toHaveLength(3);
    const kb = decodeJws(parts[2]!);
    expect(kb.header.typ).toBe('kb+jwt');
    expect(kb.payload).toMatchObject({ aud: 'x509_san_dns:verifier.example', nonce: 'nonce-1' });
    expect(verifyJws(kb, holder.publicJwk)).toBe(true);
  });

  it('builds an mdoc DeviceResponse whose device signature covers the OpenID4VP session transcript', async () => {
    const dr = cbor.decode(bytes.base64UrlDecode(await presentMdoc(mdl, [{ path: ['org.iso.18013.5.1', 'given_name'] }], req, holder))) as Map<string, unknown>;
    const doc = (dr.get('documents') as Map<string, unknown>[])[0]!;
    const ns = (doc.get('issuerSigned') as Map<string, Map<string, unknown[]>>).get('nameSpaces')!;
    expect([...ns.values()][0]).toHaveLength(1);
    const sig = (doc.get('deviceSigned') as Map<string, Map<string, unknown[]>>).get('deviceAuth')!.get('deviceSignature') as unknown[];
    expect(sig[2]).toBeNull();
    const { openId4VpHandover } = await import('../src/index.js');
    const da = ['DeviceAuthentication', [null, null, openId4VpHandover(req)], 'org.iso.18013.5.1.mDL', new cbor.Tagged(24, cbor.encode(new Map()))];
    const payload = cbor.encode(new cbor.Tagged(24, cbor.encode(da)));
    const { verifySignature, publicKeyFromJwk } = await import('@vctrust/trust-client');
    expect(verifySignature('ES256', publicKeyFromJwk(holder.publicJwk), sigStructure(sig[0] as Uint8Array, payload), sig[3] as Uint8Array)).toBe(true);
  });
});
