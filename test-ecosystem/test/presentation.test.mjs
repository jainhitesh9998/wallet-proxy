/**
 * The reference verifier, answered by the protocol library's own wallet client over loopback HTTP. The presentations
 * are made with the holder side of the reference implementations: @digitalbazaar/vc (a did:key holder),
 * @sd-jwt/sd-jwt-vc (key binding) and @owf/mdoc (DeviceResponse over the OpenID4VP session transcript).
 */
import { createHash } from 'node:crypto';
import * as vc from '@digitalbazaar/vc';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import { cryptosuite as ecdsaRdfc2019 } from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import { CoseKey, DeviceRequest, DocRequest, Holder, IssuerSigned, ItemsRequest, SessionTranscript } from '@owf/mdoc';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { serve } from '../src/http.mjs';
import { IDENTITY_VCT } from '../src/issuer.mjs';
import { generateEcJwk, thumbprint } from '../src/keys.mjs';
import { documentLoader } from '../src/ldp.mjs';
import { MDL_DOCTYPE, MDL_NAMESPACE, mdocContext } from '../src/mdoc.mjs';
import { b64Der, derOf, isRevoked } from '../src/pki.mjs';
import { es256Signer } from '../src/sdjwt.mjs';
import { startEcosystem } from '../src/serve.mjs';
import { createVerifier } from '../src/verifier.mjs';
import { createWallet } from './wallet.mjs';

const DEGREE_TYPE = 'https://reference.example/vocab#UniversityDegreeCredential';
const degreeQuery = { credentials: [{ id: 'degree', format: 'ldp_vc', type: [DEGREE_TYPE], claims: [['credentialSubject', 'givenName'], ['credentialSubject', 'degree', 'name']] }] };
const identityQuery = { credentials: [{ id: 'identity', format: 'dc+sd-jwt', vct: IDENTITY_VCT, claims: [['given_name']] }], responseMode: 'direct_post' };
const mdlQuery = { credentials: [{ id: 'mdl', format: 'mso_mdoc', doctype: MDL_DOCTYPE, claims: [[MDL_NAMESPACE, 'family_name'], [MDL_NAMESPACE, 'age_over_18']] }] };

describe('reference verifier', () => {
  let eco;
  let wallet;
  let loader;
  let degree;
  let identity;
  let mdl;

  /** A W3C Verifiable Presentation by the did:key of a P-256 key, signed with @digitalbazaar/vc (ecdsa-rdfc-2019). */
  async function degreePresentation(credential, holderKey, { nonce, client_id: domain }) {
    const key = await EcdsaMultikey.fromJwk({ jwk: holderKey, secretKey: true });
    key.controller = `did:key:${key.publicKeyMultibase}`;
    key.id = `${key.controller}#${key.publicKeyMultibase}`;
    return vc.signPresentation({ presentation: vc.createPresentation({ verifiableCredential: [credential], holder: key.controller }),
      suite: new DataIntegrityProof({ signer: key.signer(), cryptosuite: ecdsaRdfc2019 }), challenge: nonce, domain, documentLoader: loader });
  }

  /** An SD-JWT VC presentation disclosing the given claims, with a Key Binding JWT, made with @sd-jwt/sd-jwt-vc. */
  function identityPresentation(credential, holderKey, { nonce, client_id: aud }, disclosed = ['given_name']) {
    const hasher = (data, alg) => new Uint8Array(createHash(alg.replace('-', '')).update(data).digest());
    const holder = new SDJwtVcInstance({ hasher, kbSigner: es256Signer(holderKey), kbSignAlg: 'ES256' });
    return holder.present(credential, Object.fromEntries(disclosed.map((name) => [name, true])), { kb: { payload: { iat: Math.floor(Date.now() / 1000), aud, nonce } } });
  }

  /** A DeviceResponse disclosing the given mDL data elements, device-signed over the OpenID4VP handover, made with @owf/mdoc. */
  async function mdlPresentation(credential, holderKey, { nonce, client_id: clientId, response_uri: responseUri, client_metadata: metadata }, elements = ['family_name', 'age_over_18']) {
    const encryptionKey = metadata.jwks?.keys[0];
    const sessionTranscript = await SessionTranscript.forOid4Vp({ clientId, nonce, responseUri,
      jwkThumbprint: encryptionKey && new Uint8Array(Buffer.from(await thumbprint(encryptionKey), 'base64url')) }, mdocContext);
    const itemsRequest = ItemsRequest.create({ docType: MDL_DOCTYPE, namespaces: { [MDL_NAMESPACE]: Object.fromEntries(elements.map((name) => [name, false])) } });
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest({ deviceRequest: DeviceRequest.create({ docRequests: [DocRequest.create({ itemsRequest })] }), sessionTranscript,
      documents: [{ issuerSigned: IssuerSigned.fromEncodedForOid4Vci(credential), docRequestIndex: 0, signature: { signingKey: CoseKey.fromJwk({ ...holderKey, alg: 'ES256' }) } }] }, mdocContext);
    return deviceResponse.encodedForOid4Vp;
  }

  /** Creates a request on a verifier, lets the wallet answer it, and returns the HTTP outcome with the request state. */
  async function exchange(options, makeVpToken, verifier = eco.verifier) {
    const { id, authorizationRequestUri } = await verifier.createRequest(options);
    const { status, body } = await wallet.present(authorizationRequestUri, makeVpToken);
    return { status, body, state: verifier.requestState(id) };
  }

  beforeAll(async () => {
    eco = await startEcosystem({ issuerPort: 0, verifierPort: 0 });
    wallet = createWallet();
    loader = documentLoader({ fetch });
    const obtain = async (configurationId) => wallet.receive((await eco.issuer.createOffer({ configurationIds: [configurationId] })).credentialOfferUri, configurationId);
    degree = await obtain('UniversityDegree_ldp_vc_ecdsa-rdfc-2019');
    identity = await obtain('Identity_dc_sd_jwt');
    mdl = await obtain('mDL_mso_mdoc');
  });
  afterAll(() => eco.stop());

  it('passes a request object by reference, signed with the relying-party certificate its x509_hash client_id names', async () => {
    const created = await (await fetch(`${eco.verifierUrl}/api/requests`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(degreeQuery) })).json();
    const uri = new URL(created.authorizationRequestUri);
    expect(uri.protocol).toBe('openid4vp:');
    expect([...uri.searchParams.keys()].sort()).toEqual(['client_id', 'request_uri']);
    const certificate = b64Der(eco.pki.verifier.pem);
    // Section 5.9.3: the base64url SHA-256 hash of the DER leaf certificate.
    expect(uri.searchParams.get('client_id')).toBe(`x509_hash:${createHash('sha256').update(derOf(eco.pki.verifier.pem)).digest('base64url')}`);

    const served = await fetch(uri.searchParams.get('request_uri'));
    expect(served.headers.get('content-type')).toBe('application/oauth-authz-req+jwt');
    const jwt = await served.text();
    expect(decodeProtectedHeader(jwt)).toEqual({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [certificate] });
    const request = decodeJwt(jwt);
    expect(request).toMatchObject({ aud: 'https://self-issued.me/v2', response_type: 'vp_token', response_mode: 'direct_post.jwt', client_id: eco.verifier.clientId,
      response_uri: `${eco.verifierUrl}/response/${created.id}`, nonce: expect.any(String),
      dcql_query: { credentials: [{ id: 'degree', format: 'ldp_vc', meta: { type_values: [[DEGREE_TYPE]] }, claims: [{ path: ['credentialSubject', 'givenName'] }, { path: ['credentialSubject', 'degree', 'name'] }] }] } });
    // Section 8.3: the encryption key carries `kid` and `alg`; section 11.1: the formats the verifier takes.
    expect(request.client_metadata.jwks.keys).toEqual([expect.objectContaining({ kty: 'EC', crv: 'P-256', alg: 'ECDH-ES', kid: expect.any(String) })]);
    expect(request.client_metadata.jwks.keys[0]).not.toHaveProperty('d');
    expect(request.client_metadata).toMatchObject({ encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
      vp_formats_supported: { ldp_vc: { cryptosuite_values: ['ecdsa-rdfc-2019', 'eddsa-rdfc-2022'] }, mso_mdoc: {}, 'dc+sd-jwt': {} } });
    expect(await (await fetch(`${eco.verifierUrl}/api/requests/${created.id}`)).json()).toEqual({ id: created.id, status: 'pending' });
  });

  it('accepts a W3C presentation that a did:key holder made with the Digital Bazaar library', async () => {
    const { status, body, state } = await exchange(degreeQuery, async (request) => ({ degree: [await degreePresentation(degree.credential, degree.holderKey, request)] }));
    expect(state.error).toBeUndefined();
    expect([status, body]).toEqual([200, {}]);
    expect(state).toMatchObject({ status: 'verified', credentials: { degree: [{ format: 'ldp_vc', issuer: eco.issuer.did,
      type: ['https://www.w3.org/2018/credentials#VerifiableCredential', DEGREE_TYPE], claims: { credentialSubject: { givenName: 'Erika', degree: { name: 'Bachelor of Science' } } } }] } });
  });

  it('refuses a W3C presentation that was tampered with, replayed, or made by someone other than the subject', async () => {
    const tampered = await exchange(degreeQuery, async (request) => {
      const presentation = await degreePresentation(degree.credential, degree.holderKey, request);
      presentation.verifiableCredential[0] = { ...degree.credential, credentialSubject: { ...degree.credential.credentialSubject, givenName: 'Mallory' } };
      return { degree: [presentation] };
    });
    expect(tampered.status).toBe(400);
    expect(tampered.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/does not verify/) });

    // A presentation made for another request: the challenge is not this request's nonce.
    const replayed = await exchange(degreeQuery, async (request) => ({ degree: [await degreePresentation(degree.credential, degree.holderKey, { ...request, nonce: 'the-nonce-of-another-request' })] }));
    expect(replayed.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/does not verify/) });

    const stolen = await exchange(degreeQuery, async (request) => ({ degree: [await degreePresentation(degree.credential, await generateEcJwk(), request)] }));
    expect(stolen.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/not signed with a key of the credential subject/) });

    // The right credential, but not the type that was asked for: the DCQL query is not satisfied.
    const mismatched = await exchange({ credentials: [{ id: 'degree', format: 'ldp_vc', type: ['https://reference.example/vocab#Diploma'] }] },
      async (request) => ({ degree: [await degreePresentation(degree.credential, degree.holderKey, request)] }));
    expect(mismatched.state.status).toBe('failed');
  });

  it('accepts an SD-JWT VC with key binding, and sees only what was disclosed', async () => {
    const { status, state } = await exchange(identityQuery, async (request) => ({ identity: [await identityPresentation(identity.credential, identity.holderKey, request)] }));
    expect(state.error).toBeUndefined();
    expect(status).toBe(200);
    expect(state.credentials.identity[0]).toMatchObject({ format: 'dc+sd-jwt', issuer: eco.issuerUrl, type: IDENTITY_VCT, claims: { given_name: 'Erika' } });
    expect(state.credentials.identity[0].claims).not.toHaveProperty('family_name');

    const wrongAudience = await exchange(identityQuery, async (request) => ({ identity: [await identityPresentation(identity.credential, identity.holderKey, { ...request, client_id: 'x509_hash:another-verifier' })] }));
    expect(wrongAudience.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/audience/i) });
    const notTheHolder = await exchange(identityQuery, async (request) => ({ identity: [await identityPresentation(identity.credential, await generateEcJwk(), request)] }));
    expect(notTheHolder.state.status).toBe('failed');
    // The query asks for given_name; a presentation that withholds it does not satisfy it.
    const withheld = await exchange(identityQuery, async (request) => ({ identity: [await identityPresentation(identity.credential, identity.holderKey, request, ['family_name'])] }));
    expect(withheld.state.status).toBe('failed');
  });

  it.each(['direct_post.jwt', 'direct_post'])('accepts an mdoc DeviceResponse over the OpenID4VP session transcript (%s)', async (responseMode) => {
    const query = { ...mdlQuery, responseMode };
    const { status, state } = await exchange(query, async (request) => ({ mdl: [await mdlPresentation(mdl.credential, mdl.holderKey, request)] }));
    expect(state.error).toBeUndefined();
    expect(status).toBe(200);
    expect(state.credentials.mdl[0]).toMatchObject({ format: 'mso_mdoc', type: MDL_DOCTYPE });
    expect(state.credentials.mdl[0].claims).toEqual({ [MDL_NAMESPACE]: { family_name: 'Mustermann', age_over_18: true } });

    // Device authentication covers the nonce, the client_id, the response_uri and the encryption key of this request.
    const replayed = await exchange(query, async (request) => ({ mdl: [await mdlPresentation(mdl.credential, mdl.holderKey, { ...request, nonce: 'the-nonce-of-another-request' })] }));
    expect(replayed.status).toBe(400);
    expect(replayed.state.status).toBe('failed');
    const notTheDevice = await exchange(query, async (request) => ({ mdl: [await mdlPresentation(mdl.credential, await generateEcJwk(), request)] }));
    expect(notTheDevice.state.status).toBe('failed');
  });

  it('derives the session transcript of the example in OpenID4VP 1.0 appendix B.2.6.1', async () => {
    const encryptionKey = { kty: 'EC', crv: 'P-256', x: 'DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0', y: 'XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc', use: 'enc', alg: 'ECDH-ES', kid: '1' };
    const jwkThumbprint = Buffer.from(await thumbprint(encryptionKey), 'base64url');
    expect(jwkThumbprint.toString('hex')).toBe('4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047');
    const transcript = await SessionTranscript.forOid4Vp({ clientId: 'x509_san_dns:example.com', nonce: 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA',
      responseUri: 'https://example.com/response', jwkThumbprint: new Uint8Array(jwkThumbprint) }, mdocContext);
    expect(Buffer.from(transcript.encode()).toString('hex')).toBe('83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac');
  });

  it('leaves the decision which issuers to accept to the injected function', async () => {
    let handle;
    const server = await serve((request, body) => handle(request, body), 0);
    try {
      const asked = [];
      const strict = await createVerifier({ baseUrl: `http://localhost:${server.port}`, pki: eco.pki, isTrustedIssuer: async (info) => { asked.push(info); return false; } });
      handle = strict.handle;
      const sdJwt = await exchange(identityQuery, async (request) => ({ identity: [await identityPresentation(identity.credential, identity.holderKey, request)] }), strict);
      const mdoc = await exchange(mdlQuery, async (request) => ({ mdl: [await mdlPresentation(mdl.credential, mdl.holderKey, request)] }), strict);
      const ldp = await exchange(degreeQuery, async (request) => ({ degree: [await degreePresentation(degree.credential, degree.holderKey, request)] }), strict);
      for (const { status, state } of [sdJwt, mdoc, ldp]) {
        expect(status).toBe(400);
        expect(state).toMatchObject({ status: 'failed', error: expect.stringMatching(/not trusted/) });
      }
      expect(asked).toEqual([
        { format: 'dc+sd-jwt', issuer: eco.issuerUrl, x5c: [b64Der(eco.pki.issuerSigner.pem)], type: IDENTITY_VCT },
        { format: 'mso_mdoc', x5c: [b64Der(eco.pki.ds.pem)], type: MDL_DOCTYPE },
        { format: 'ldp_vc', issuer: eco.issuer.did, type: ['https://www.w3.org/2018/credentials#VerifiableCredential', DEGREE_TYPE] },
      ]);
    } finally {
      await server.close();
    }
  });

  it('refuses revoked credentials, and mdocs once the Document Signer is on the CRL', async () => {
    eco.issuer.revokeCredential(degree.credential.credentialStatus.id);
    const { uri, idx } = decodeJwt(identity.credential.split('~')[0]).status.status_list;
    eco.issuer.revokeCredential(`${uri}#${idx}`);
    const revokedDegree = await exchange(degreeQuery, async (request) => ({ degree: [await degreePresentation(degree.credential, degree.holderKey, request)] }));
    expect(revokedDegree.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/revocation status is set/) });
    const revokedIdentity = await exchange(identityQuery, async (request) => ({ identity: [await identityPresentation(identity.credential, identity.holderKey, request)] }));
    expect(revokedIdentity.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/status/i) });

    const signer = [derOf(eco.pki.ds.pem), derOf(eco.pki.iaca.pem)];
    expect(await isRevoked(...signer)).toBe(false);
    const revoked = await fetch(`${eco.issuerUrl}/api/revoke-document-signer`, { method: 'POST' });
    expect(await revoked.json()).toEqual({ serialNumber: eco.pki.ds.serialNumber, revoked: true });
    expect((await fetch(eco.pki.crlUrl)).headers.get('content-type')).toBe('application/pkix-crl');
    expect(await isRevoked(...signer)).toBe(true);
    const revokedSigner = await exchange(mdlQuery, async (request) => ({ mdl: [await mdlPresentation(mdl.credential, mdl.holderKey, request)] }));
    expect(revokedSigner.state).toMatchObject({ status: 'failed', error: expect.stringMatching(/not trusted/) });
  });
});
