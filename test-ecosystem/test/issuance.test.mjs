/**
 * The reference issuer, driven by the protocol library's own wallet client over loopback HTTP. Every credential is
 * verified by the reference implementation of its format: @digitalbazaar/vc (with the Digital Bazaar status check),
 * @owf/mdoc against the IACA, and @sd-jwt/sd-jwt-vc.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as vc from '@digitalbazaar/vc';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import { cryptosuite as ecdsaRdfc2019 } from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import { cryptosuite as eddsaRdfc2022 } from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import { checkStatus as referenceStatus, decodeList } from '@digitalbazaar/vc-bitstring-status-list';
import { getListFromStatusListJWT } from '@sd-jwt/jwt-status-list';
import { decodeJwt, decodeProtectedHeader, importJWK, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIssuer, IDENTITY_VCT } from '../src/issuer.mjs';
import { generateEcJwk, publicOf } from '../src/keys.mjs';
import { documentLoader, verifyCredential } from '../src/ldp.mjs';
import { MDL_DOCTYPE, MDL_NAMESPACE, mdocClaims, verifyIssuerSigned } from '../src/mdoc.mjs';
import { b64Der, derOf, generatePki } from '../src/pki.mjs';
import { verifySdJwtVc } from '../src/sdjwt.mjs';
import { startEcosystem } from '../src/serve.mjs';
import { createWallet, didJwk } from './wallet.mjs';

const LDP = { 'ecdsa-rdfc-2019': 'UniversityDegree_ldp_vc_ecdsa-rdfc-2019', 'eddsa-rdfc-2022': 'UniversityDegree_ldp_vc_eddsa-rdfc-2022' };
const MDL = 'mDL_mso_mdoc';
const IDENTITY = 'Identity_dc_sd_jwt';
const suites = () => [ecdsaRdfc2019, eddsaRdfc2022].map((cryptosuite) => new DataIntegrityProof({ cryptosuite }));
/** The OAuth or credential error code a wallet library call fails with. */
const errorOf = (promise) => promise.then(() => undefined, (e) => e.errorResponse?.error ?? /error\\?":\s*\\?"(\w+)/.exec(e.message)?.[1] ?? e.message);
const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': body instanceof URLSearchParams ? 'application/x-www-form-urlencoded' : 'application/json', ...headers },
  body: body instanceof URLSearchParams ? body : JSON.stringify(body) });

describe('reference issuer', () => {
  let eco;
  let wallet;
  let loader;
  /** Offers a credential and takes it through the pre-authorized code flow. */
  const obtain = async (configurationId, offer = {}) => wallet.receive((await eco.issuer.createOffer({ configurationIds: [configurationId], ...offer })).credentialOfferUri, configurationId);
  /** @digitalbazaar/vc with the status check of @digitalbazaar/vc-bitstring-status-list, as they come. */
  const referenceVerify = (credential) => vc.verifyCredential({ credential, suite: suites(), documentLoader: loader, checkStatus: referenceStatus });

  beforeAll(async () => {
    eco = await startEcosystem({ issuerPort: 0, verifierPort: 0 });
    wallet = createWallet();
    loader = documentLoader({ fetch });
  });
  afterAll(() => eco.stop());

  it('publishes metadata the wallet library resolves, and a did:web document with Multikey assertion methods', async () => {
    const { credentialOffer, issuerMetadata } = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [MDL] })).credentialOfferUri);
    expect(credentialOffer.credential_configuration_ids).toEqual([MDL]);
    expect(issuerMetadata.credentialIssuer).toMatchObject({ credential_issuer: eco.issuerUrl, nonce_endpoint: `${eco.issuerUrl}/nonce`, batch_credential_issuance: { batch_size: 5 } });
    expect(Object.keys(issuerMetadata.credentialIssuer.credential_configurations_supported)).toEqual(eco.issuer.configurationIds);
    expect(issuerMetadata.authorizationServers[0]).toMatchObject({ issuer: eco.issuerUrl, code_challenge_methods_supported: ['S256'],
      pushed_authorization_request_endpoint: `${eco.issuerUrl}/par`, dpop_signing_alg_values_supported: ['ES256'] });

    const did = await (await fetch(`${eco.issuerUrl}/.well-known/did.json`)).json();
    expect(did.id).toBe(`did:web:localhost%3A${new URL(eco.issuerUrl).port}`);
    expect(did.verificationMethod.map((m) => m.type)).toEqual(['Multikey', 'Multikey']);
    expect(did.verificationMethod.every((m) => m.controller === did.id && m.publicKeyMultibase.startsWith('z'))).toBe(true);
    expect(did.assertionMethod).toEqual(did.verificationMethod.map((m) => m.id));
  });

  it.each(Object.entries(LDP))('issues a VCDM 2.0 credential with an %s proof that @digitalbazaar/vc verifies', async (suite, configurationId) => {
    const { credential, holderKey } = await obtain(configurationId);
    expect(credential).toMatchObject({ '@context': ['https://www.w3.org/ns/credentials/v2', eco.issuer.contextUrl], type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      issuer: eco.issuer.did, credentialSubject: { id: didJwk(holderKey), givenName: 'Erika' },
      proof: { type: 'DataIntegrityProof', cryptosuite: suite, proofPurpose: 'assertionMethod' } });
    expect(credential.proof.verificationMethod.startsWith(`${eco.issuer.did}#`)).toBe(true);

    const result = await referenceVerify(credential);
    expect(result.error).toBeUndefined();
    expect(result.verified).toBe(true);
    expect(result.statusResult).toMatchObject({ verified: true, results: [{ status: false }] });
    // Every term is defined by a served context, so a changed claim breaks the proof rather than slipping past it.
    const tampered = await referenceVerify({ ...credential, credentialSubject: { ...credential.credentialSubject, givenName: 'Mallory' } });
    expect(tampered.verified).toBe(false);

    // Bitstring Status List v1.0: sections 2.1 (entry), 2.2 (list credential, at least 131,072 entries) and 3.2 (matching purposes).
    const entry = credential.credentialStatus;
    expect(entry).toMatchObject({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListCredential: `${eco.issuerUrl}/status/bitstring` });
    expect(entry.statusListIndex).toMatch(/^\d+$/);
    const served = await fetch(entry.statusListCredential);
    expect(served.headers.get('content-type')).toBe('application/vc');
    const list = await served.json();
    expect(list).toMatchObject({ '@context': ['https://www.w3.org/ns/credentials/v2'], id: entry.statusListCredential, issuer: eco.issuer.did,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'], credentialSubject: { type: 'BitstringStatusList', statusPurpose: entry.statusPurpose },
      proof: { type: 'DataIntegrityProof' } });
    expect((await decodeList({ encodedList: list.credentialSubject.encodedList })).length).toBeGreaterThanOrEqual(131_072);
  });

  it('issues an mDL that @owf/mdoc verifies against the IACA, with only the Document Signer in the x5chain', async () => {
    const { credential, holderKey } = await obtain(MDL, { claims: { given_name: 'Max', birth_date: '1985-07-01' } });
    const issuerSigned = await verifyIssuerSigned(credential, [eco.pki.iaca.pem]);
    await expect(verifyIssuerSigned(credential, [eco.pki.issuerCa.pem])).rejects.toThrow();

    const chain = issuerSigned.issuerAuth.certificateChain;
    expect(chain.map((c) => Buffer.from(c).toString('base64'))).toEqual([b64Der(eco.pki.ds.pem)]);
    expect(Buffer.from(chain[0]).equals(Buffer.from(derOf(eco.pki.iaca.pem)))).toBe(false);
    const mso = issuerSigned.issuerAuth.mobileSecurityObject;
    expect(mso.docType).toBe(MDL_DOCTYPE);
    expect(mso.deviceKeyInfo.deviceKey.jwk).toMatchObject({ kty: 'EC', crv: 'P-256', x: holderKey.x, y: holderKey.y });
    const elements = mdocClaims(issuerSigned)[MDL_NAMESPACE];
    expect(elements).toMatchObject({ given_name: 'Max', family_name: 'Mustermann', birth_date: '1985-07-01', issuing_country: 'UT', age_over_18: true });
    // ISO/IEC 18013-5 clause 7.2.1: the mandatory data elements.
    for (const mandatory of ['family_name', 'given_name', 'birth_date', 'issue_date', 'expiry_date', 'issuing_country', 'issuing_authority', 'document_number', 'portrait', 'driving_privileges', 'un_distinguishing_sign']) {
      expect(elements, mandatory).toHaveProperty(mandatory);
    }
  });

  it('issues an SD-JWT VC that @sd-jwt/sd-jwt-vc verifies, with the signer certificate in x5c and a Token Status List entry', async () => {
    const { credential, holderKey } = await obtain(IDENTITY, { claims: { given_name: 'Max' } });
    const [issuerSigned, ...disclosures] = credential.split('~').filter(Boolean);
    expect(decodeProtectedHeader(issuerSigned)).toEqual({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [b64Der(eco.pki.issuerSigner.pem)] });
    const signed = decodeJwt(issuerSigned);
    expect(signed).toMatchObject({ iss: eco.issuerUrl, vct: IDENTITY_VCT, cnf: { jwk: publicOf(holderKey) }, _sd_alg: 'sha-256', status: { status_list: { uri: `${eco.issuerUrl}/status/token` } } });
    expect(signed.exp).toBeGreaterThan(signed.iat);
    // The subject claims are selectively disclosable: digests in the signed payload, one disclosure each.
    expect(signed).not.toHaveProperty('given_name');
    expect(signed._sd).toHaveLength(3);
    expect(disclosures).toHaveLength(3);

    const verified = await verifySdJwtVc(credential);
    expect(verified.payload).toMatchObject({ given_name: 'Max', family_name: 'Mustermann', birthdate: '1990-03-14' });
    await expect(verifySdJwtVc(credential.replace(disclosures[0], disclosures[0].slice(0, -2)))).rejects.toThrow();

    // draft-ietf-oauth-status-list sections 5.1 and 8.1: the Status List Token, signed with the same certificate.
    const served = await fetch(signed.status.status_list.uri, { headers: { Accept: 'application/statuslist+jwt' } });
    expect(served.headers.get('content-type')).toBe('application/statuslist+jwt');
    const token = await served.text();
    expect(decodeProtectedHeader(token)).toEqual({ alg: 'ES256', typ: 'statuslist+jwt', x5c: [b64Der(eco.pki.issuerSigner.pem)] });
    expect(decodeJwt(token)).toMatchObject({ sub: signed.status.status_list.uri, status_list: { bits: 1 } });
    expect(getListFromStatusListJWT(token).getStatus(signed.status.status_list.idx)).toBe(0);
  });

  it('asks for the transaction code of the offer', async () => {
    const offer = await eco.issuer.createOffer({ configurationIds: [IDENTITY], txCode: true });
    expect(offer.txCode).toMatch(/^\d{6}$/);
    const session = await wallet.resolve(offer.credentialOfferUri);
    expect(session.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].tx_code).toEqual({ input_mode: 'numeric', length: 6 });
    // Section 6.3: a missing transaction code is invalid_request, a wrong one invalid_grant.
    const grant = session.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    const missing = await post(`${eco.issuerUrl}/token`, new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': grant['pre-authorized_code'] }));
    expect([missing.status, (await missing.json()).error]).toEqual([400, 'invalid_request']);
    expect(await errorOf(wallet.preAuthorizedToken(session, { txCode: offer.txCode === '000000' ? '000001' : '000000' }))).toBe('invalid_grant');
    const token = await wallet.preAuthorizedToken(session, { txCode: offer.txCode });
    expect(token.accessTokenResponse.token_type).toBe('Bearer');
    // A pre-authorized code is single use (section 4.1.1).
    expect(await errorOf(wallet.preAuthorizedToken(session, { txCode: offer.txCode }))).toBe('invalid_grant');
  });

  it('issues through the authorization code flow, with a pushed request and PKCE', async () => {
    const configurationId = LDP['ecdsa-rdfc-2019'];
    const session = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [configurationId], grant: 'authorization_code' })).credentialOfferUri);
    expect(session.credentialOffer.grants.authorization_code.issuer_state).toEqual(expect.any(String));
    const authorization = await wallet.authorizationCodeToken(session);
    expect(new URL(authorization.authorizationRequestUrl).searchParams.get('request_uri')).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    expect(Object.fromEntries(new URL(authorization.redirectUrl).searchParams)).toMatchObject({ code: expect.any(String), iss: eco.issuerUrl });
    const token = await authorization.redeem();
    const { response } = await wallet.requestCredentials({ ...session, configurationId, token });
    expect((await referenceVerify(response.credentials[0].credential)).verified).toBe(true);
    // An authorization code is good once.
    expect(await errorOf(authorization.redeem())).toBe('invalid_grant');

    // Without a code challenge the authorization endpoint redirects back with an error instead of a code.
    const plain = new URL(`${eco.issuerUrl}/authorize`);
    plain.search = new URLSearchParams({ response_type: 'code', client_id: 'reference-test-wallet', redirect_uri: 'http://localhost/wallet/callback', scope: 'university_degree', state: 'abc' });
    const refused = new URL((await fetch(plain, { redirect: 'manual' })).headers.get('location'));
    expect(Object.fromEntries(refused.searchParams)).toMatchObject({ error: 'invalid_request', state: 'abc', iss: eco.issuerUrl });
    expect(refused.searchParams.has('code')).toBe(false);
  });

  it('binds the access token to the DPoP key of the token request', async () => {
    const session = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [IDENTITY] })).credentialOfferUri);
    const token = await wallet.preAuthorizedToken(session, { dpop: true });
    expect(token.accessTokenResponse.token_type).toBe('DPoP');
    const { response } = await wallet.requestCredentials({ ...session, configurationId: IDENTITY, token });
    expect(response.credentials).toHaveLength(1);
    // The same token without a proof of the key is refused (RFC 9449 section 7).
    for (const scheme of ['Bearer', 'DPoP']) {
      const bare = await post(`${eco.issuerUrl}/credential`, { credential_configuration_id: IDENTITY }, { Authorization: `${scheme} ${token.accessTokenResponse.access_token}` });
      expect(bare.status).toBe(401);
    }

    // A pushed authorization request with a DPoP proof binds the code to that key: no token without it, a bound token with it.
    const offer = await eco.issuer.createOffer({ configurationIds: [IDENTITY], grant: 'authorization_code' });
    const unproven = await wallet.authorizationCodeToken(await wallet.resolve(offer.credentialOfferUri), { dpop: true });
    expect(await errorOf(unproven.redeem(null))).toBe('invalid_dpop_proof');
    const proven = await wallet.authorizationCodeToken(await wallet.resolve(offer.credentialOfferUri), { dpop: true });
    expect((await proven.redeem()).accessTokenResponse.token_type).toBe('DPoP');
  });

  it('issues one credential per key proof, up to the batch size', async () => {
    const configurationId = LDP['eddsa-rdfc-2022'];
    const session = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [configurationId] })).credentialOfferUri);
    const token = await wallet.preAuthorizedToken(session);
    const tooMany = await post(`${eco.issuerUrl}/credential`, { credential_configuration_id: configurationId, proofs: { jwt: (await wallet.createProofs({ ...session, configurationId, count: 6 })).proofs } },
      { Authorization: `Bearer ${token.accessTokenResponse.access_token}` });
    expect([tooMany.status, (await tooMany.json()).error]).toEqual([400, 'invalid_credential_request']);
    const { response, holderKeys } = await wallet.requestCredentials({ ...session, configurationId, token, count: 3 });
    expect(response.credentials.map((c) => c.credential.credentialSubject.id)).toEqual(holderKeys.map(didJwk));
    expect(new Set(response.credentials.map((c) => c.credential.credentialStatus.statusListIndex)).size).toBe(3);
    // The token covers the offered configuration only.
    expect(await errorOf(wallet.requestCredentials({ ...session, configurationId: MDL, token }))).toBe('credential_request_denied');
  });

  it('names the credential by identifier when the wallet asked with authorization details', async () => {
    const session = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [IDENTITY, MDL] })).credentialOfferUri);
    const token = await wallet.client.retrievePreAuthorizedCodeAccessTokenFromOffer({ ...session,
      additionalRequestPayload: { authorization_details: JSON.stringify([{ type: 'openid_credential', credential_configuration_id: IDENTITY }]) } });
    // Section 6.2: the token response then lists credential identifiers, and section 8.2 makes the request use one.
    const details = token.accessTokenResponse.authorization_details;
    expect(details).toEqual([{ type: 'openid_credential', credential_configuration_id: IDENTITY, credential_identifiers: [expect.any(String)] }]);
    const request = async (naming) => {
      const { proofs } = await wallet.createProofs({ ...session, configurationId: IDENTITY });
      const response = await post(`${eco.issuerUrl}/credential`, { ...naming, proofs: { jwt: proofs } }, { Authorization: `Bearer ${token.accessTokenResponse.access_token}` });
      return [response.status, (await response.json()).error];
    };
    expect(await request({ credential_identifier: details[0].credential_identifiers[0] })).toEqual([200, undefined]);
    expect(await request({ credential_configuration_id: IDENTITY })).toEqual([400, 'invalid_credential_request']);
    expect(await request({ credential_identifier: 'another' })).toEqual([400, 'unknown_credential_identifier']);
  });

  it('takes a key proof once, and only one that is addressed to it', async () => {
    const session = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [IDENTITY] })).credentialOfferUri);
    const token = await wallet.preAuthorizedToken(session);
    const request = async (proof) => {
      const response = await post(`${eco.issuerUrl}/credential`, { credential_configuration_id: IDENTITY, proofs: { jwt: [proof] } }, { Authorization: `Bearer ${token.accessTokenResponse.access_token}` });
      return [response.status, response.headers.get('cache-control'), (await response.json()).error];
    };
    const { proofs: [proof] } = await wallet.createProofs({ ...session, configurationId: IDENTITY });
    expect(await request(proof)).toEqual([200, 'no-store', undefined]);
    // The nonce of the nonce endpoint is spent with the request that carried it.
    expect(await request(proof)).toEqual([400, 'no-store', 'invalid_nonce']);

    const nonce = await post(`${eco.issuerUrl}/nonce`, {});
    expect(nonce.headers.get('cache-control')).toBe('no-store');
    const key = await generateEcJwk();
    const elsewhere = await new SignJWT({ aud: 'https://another-issuer.example', nonce: (await nonce.json()).c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicOf(key) }).setIssuedAt().sign(await importJWK(key, 'ES256'));
    expect(await request(elsewhere)).toEqual([400, 'no-store', 'invalid_proof']);
  });

  it('defers issuance when the offer says so, and records what the wallet notifies', async () => {
    const session = await wallet.resolve((await eco.issuer.createOffer({ configurationIds: [IDENTITY], deferSeconds: 1 })).credentialOfferUri);
    const token = await wallet.preAuthorizedToken(session);
    const { response } = await wallet.requestCredentials({ ...session, configurationId: IDENTITY, token });
    expect(response).toEqual({ transaction_id: expect.any(String), interval: expect.any(Number) });
    const deferred = () => wallet.client.retrieveDeferredCredentials({ issuerMetadata: session.issuerMetadata, accessToken: token.accessTokenResponse.access_token, transactionId: response.transaction_id });
    const pending = await deferred();
    expect(pending.response.status).toBe(202);
    expect(pending.deferredCredentialResponse).toEqual({ transaction_id: response.transaction_id, interval: expect.any(Number) });
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const ready = await deferred();
    expect(ready.response.status).toBe(200);
    expect((await verifySdJwtVc(ready.deferredCredentialResponse.credentials[0].credential)).payload.vct).toBe(IDENTITY_VCT);
    expect(await errorOf(deferred())).toBe('invalid_transaction_id');

    const notificationId = ready.deferredCredentialResponse.notification_id;
    await wallet.client.sendNotification({ issuerMetadata: session.issuerMetadata, accessToken: token.accessTokenResponse.access_token, notification: { notificationId, event: 'credential_accepted' } });
    expect(eco.issuer.notifications()).toContainEqual(expect.objectContaining({ notificationId, event: 'credential_accepted' }));
    expect(await (await fetch(`${eco.issuerUrl}/api/notifications`)).json()).toEqual(eco.issuer.notifications());
  });

  it('revokes a credential: the reference status checks then report it', async () => {
    const degree = await obtain(LDP['ecdsa-rdfc-2019']);
    const other = await obtain(LDP['ecdsa-rdfc-2019']);
    const identity = await obtain(IDENTITY);
    const { uri, idx } = decodeJwt(identity.credential.split('~')[0]).status.status_list;
    expect(eco.issuer.credentials()).toContainEqual(expect.objectContaining({ id: degree.credential.credentialStatus.id, format: 'ldp_vc', revoked: false }));
    expect((await verifyCredential(degree.credential, loader)).verified).toBe(true);
    await verifySdJwtVc(identity.credential);

    eco.issuer.revokeCredential(degree.credential.credentialStatus.id);
    const revoke = await post(`${eco.issuerUrl}/api/revoke`, { id: `${uri}#${idx}` });
    expect(revoke.status).toBe(200);

    // @digitalbazaar/vc-bitstring-status-list reads the bit; the verifier's status check turns a set bit into a failure.
    expect((await referenceVerify(degree.credential)).statusResult).toMatchObject({ verified: true, results: [{ status: true }] });
    const result = await verifyCredential(degree.credential, loader);
    expect(result.verified).toBe(false);
    expect(result.statusResult.error.message).toMatch(/revocation status is set/);
    expect((await verifyCredential(other.credential, loader)).verified).toBe(true);
    // @sd-jwt/sd-jwt-vc checks the Token Status List itself.
    await expect(verifySdJwtVc(identity.credential)).rejects.toMatchObject({ code: 'STATUS_INVALID' });
    expect(eco.issuer.credentials().filter((c) => c.revoked).map((c) => c.id).sort()).toEqual([degree.credential.credentialStatus.id, `${uri}#${idx}`].sort());
    expect(() => eco.issuer.revokeCredential('urn:unknown')).toThrow(/No credential/);
  });

  it('keeps its keys and status lists in the data directory', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'reference-issuer-'));
    try {
      const baseUrl = 'http://localhost:8791';
      const pki = await generatePki({ issuerUrl: baseUrl, verifierHost: 'localhost' });
      const get = async (issuer, path) => (await issuer.handle({ method: 'GET', url: `${baseUrl}${path}`, headers: new Headers() })).body;
      const first = await createIssuer({ baseUrl, pki, dataDir: dir });
      first.revokeDocumentSigner();
      const second = await createIssuer({ baseUrl, pki, dataDir: dir });
      expect(await get(second, '/.well-known/did.json')).toEqual(await get(first, '/.well-known/did.json'));
      expect(await get(second, '/jwks')).toEqual(await get(first, '/jwks'));
      const { X509Crl } = await import('@peculiar/x509');
      expect(new X509Crl(await get(second, '/pki/iaca.crl')).entries.map((e) => e.serialNumber)).toEqual([pki.ds.serialNumber]);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
