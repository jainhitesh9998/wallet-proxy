/**
 * Reference credential issuer: OpenID4VCI 1.0 on the protocol library behind Animo's playground (@openid4vc/*), with the
 * credentials themselves made by reference implementations. Credential endpoint (section 8), nonce endpoint (7),
 * deferred issuance (9), notifications (11), jwt key proofs (appendix F.1), batch issuance, and the formats of
 * appendix A: ldp_vc (A.1.2), mso_mdoc (A.2) and dc+sd-jwt (A.3). The authorization server is in
 * authorization-server.mjs. A test issuer: offers are created by whoever can reach `/api`.
 */
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Openid4vciIssuer, Openid4vciVersion } from '@openid4vc/openid4vci';
import { authorizationCodeGrantIdentifier, decodeJwt, Oauth2ResourceUnauthorizedError, Oauth2ServerErrorResponseError, preAuthorizedCodeGrantIdentifier, setGlobalConfig } from '@openid4vc/oauth2';
import { ValidationError } from '@openid4vc/utils';
import { createAuthorizationServer, oauthError } from './authorization-server.mjs';
import { generateEcJwk, joseCallbacks } from './keys.mjs';
import { createAssertionKeys, didDocument, didWeb, documentLoader, exportAssertionKeys, signCredential } from './ldp.mjs';
import { issueMdl, MDL_DOCTYPE, MDL_NAMESPACE } from './mdoc.mjs';
import { createCrl, loadCa } from './pki.mjs';
import { issueSdJwtVc, signStatusListToken } from './sdjwt.mjs';
import { createStatusLists } from './status.mjs';

const OFFER_TTL_S = 600;
const NONCE_TTL_S = 300;
const BATCH_SIZE = 5;
const DEFERRED_INTERVAL_S = 2;
const PROOF_ALGORITHMS = ['ES256'];
export const IDENTITY_VCT = 'urn:reference:identity:1';
/** The ldp_vc credential configurations and the cryptosuite each one signs with. */
const LDP_SUITES = { 'UniversityDegree_ldp_vc_ecdsa-rdfc-2019': 'ecdsa-rdfc-2019', 'UniversityDegree_ldp_vc_eddsa-rdfc-2022': 'eddsa-rdfc-2022' };

const VOCAB = 'https://reference.example/vocab#';
/** The vocabulary of the reference ldp_vc credentials: every term is defined, so nothing escapes the signature. */
const REFERENCE_CONTEXT = { '@context': { '@protected': true,
  UniversityDegreeCredential: `${VOCAB}UniversityDegreeCredential`, BachelorDegree: `${VOCAB}BachelorDegree`, MasterDegree: `${VOCAB}MasterDegree`,
  givenName: 'https://schema.org/givenName', familyName: 'https://schema.org/familyName',
  degree: { '@id': `${VOCAB}degree`, '@context': { '@protected': true, name: 'https://schema.org/name' } } } };

const label = (name) => [{ name, locale: 'en' }];
const claim = (path, name) => ({ path, display: label(name) });
const timestamp = (date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');

/** The credential configurations (section 12.2.4): two ldp_vc, one per cryptosuite, an mDL and an SD-JWT VC. */
function credentialConfigurations(contextUrl) {
  const proof_types_supported = { jwt: { proof_signing_alg_values_supported: PROOF_ALGORITHMS } };
  const ldp = (suite) => ({
    format: 'ldp_vc', scope: 'university_degree', cryptographic_binding_methods_supported: ['did:jwk'],
    credential_signing_alg_values_supported: ['DataIntegrityProof'], proof_types_supported,
    credential_definition: { '@context': ['https://www.w3.org/ns/credentials/v2', contextUrl], type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
    credential_metadata: { display: label(`University degree (${suite})`), claims: [claim(['credentialSubject', 'givenName'], 'Given name'),
      claim(['credentialSubject', 'familyName'], 'Family name'), claim(['credentialSubject', 'degree', 'name'], 'Degree')] },
  });
  return {
    ...Object.fromEntries(Object.entries(LDP_SUITES).map(([id, suite]) => [id, ldp(suite)])),
    mDL_mso_mdoc: {
      format: 'mso_mdoc', doctype: MDL_DOCTYPE, scope: 'mdl', cryptographic_binding_methods_supported: ['cose_key'],
      credential_signing_alg_values_supported: [-7], proof_types_supported,
      credential_metadata: { display: label('Mobile driving licence'), claims: [claim([MDL_NAMESPACE, 'given_name'], 'Given name'),
        claim([MDL_NAMESPACE, 'family_name'], 'Family name'), claim([MDL_NAMESPACE, 'birth_date'], 'Date of birth'), claim([MDL_NAMESPACE, 'age_over_18'], 'Over 18')] },
    },
    Identity_dc_sd_jwt: {
      format: 'dc+sd-jwt', vct: IDENTITY_VCT, scope: 'identity', cryptographic_binding_methods_supported: ['jwk'],
      credential_signing_alg_values_supported: ['ES256'], proof_types_supported,
      credential_metadata: { display: label('Identity'), claims: [claim(['given_name'], 'Given name'), claim(['family_name'], 'Family name'), claim(['birthdate'], 'Date of birth')] },
    },
  };
}

/**
 * @typedef {{ configurationIds: string[], grant?: 'pre-authorized_code' | 'authorization_code', txCode?: string | true,
 *   claims?: Record<string, unknown>, deferSeconds?: number }} OfferOptions `txCode: true` picks a 6 digit code;
 *   `claims` replace or add subject claims (ldp_vc: terms of the reference context; mso_mdoc: mDL data elements;
 *   dc+sd-jwt: top-level claims); `deferSeconds` makes the credential endpoint defer issuance by that long
 * @typedef {{ offerId: string, credentialOfferUri: string, credentialOffer: object, txCode?: string }} Offer
 * @typedef {{ id?: string, offerId?: string, configurationId: string, format: string, issuedAt: string, revoked: boolean }} IssuedCredential
 *   `id` names the status entry of a credential that has one: `credentialStatus.id` of an ldp_vc, and
 *   `status.status_list.uri + '#' + idx` of an SD-JWT VC
 */

/**
 * @param {{ baseUrl: string, pki: import('./pki.mjs').Pki, dataDir?: string }} opts with `dataDir`, the issuer's keys,
 *   status lists and revocations are kept in `issuer.json` there; offers, grants and nonces live in memory
 */
export async function createIssuer({ baseUrl, pki, dataDir }) {
  // The reference ecosystem runs on loopback http; behind TLS this switch is not needed.
  if (baseUrl.startsWith('http://')) setGlobalConfig({ allowInsecureUrls: true });
  const did = didWeb(baseUrl);
  const contextUrl = `${baseUrl}/contexts/reference/v1`;
  const statusUrls = { bitstring: `${baseUrl}/status/bitstring`, token: `${baseUrl}/status/token` };
  const stateFile = dataDir && join(dataDir, 'issuer.json');
  const saved = stateFile && existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : {};

  const tokenKey = saved.tokenKey ?? await generateEcJwk();
  const assertionKeys = await createAssertionKeys(did, saved.assertionKeys);
  const lists = createStatusLists(saved.status);
  /** @type {Array<IssuedCredential & { list?: 'bitstring' | 'token', index?: number }>} */
  const issued = saved.issued ?? [];
  let documentSignerRevoked = saved.documentSignerRevoked ?? false;
  const iaca = await loadCa(pki.iaca);
  const exportedKeys = await exportAssertionKeys(assertionKeys);
  function save() {
    if (!stateFile) return;
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(stateFile, JSON.stringify({ tokenKey, assertionKeys: exportedKeys, status: lists.toJSON(), issued, documentSignerRevoked }, null, 2), { mode: 0o600 });
  }
  save();

  const callbacks = joseCallbacks([tokenKey]);
  const issuer = new Openid4vciIssuer({ callbacks });
  const configurations = credentialConfigurations(contextUrl);
  /** offer id → offer; nonce → expiry; transaction id → deferred issuance; notification id → the grant and credentials */
  const offers = new Map();
  const nonces = new Map();
  const transactions = new Map();
  const notifiable = new Map();
  const notifications = [];
  const authorizationServer = createAuthorizationServer({ baseUrl, callbacks, tokenKey, configurations, offers });

  const credentialIssuer = issuer.createCredentialIssuerMetadata({
    credential_issuer: baseUrl, credential_endpoint: `${baseUrl}/credential`, nonce_endpoint: `${baseUrl}/nonce`,
    deferred_credential_endpoint: `${baseUrl}/deferred_credential`, notification_endpoint: `${baseUrl}/notification`,
    batch_credential_issuance: { batch_size: BATCH_SIZE }, display: label('Reference Issuer'),
    credential_configurations_supported: configurations,
  });
  const issuerMetadata = { credentialIssuer, authorizationServers: [authorizationServer.metadata], originalDraftVersion: Openid4vciVersion.V1,
    knownCredentialConfigurations: issuer.getKnownCredentialConfigurationsSupported(credentialIssuer) };
  const didDoc = await didDocument(did, assertionKeys);
  const loader = documentLoader({ statics: { [contextUrl]: REFERENCE_CONTEXT, [did]: didDoc } });

  // RFC 6749 section 5.1, and the same for nonces and credentials.
  const noStore = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };
  /** @returns {IssuedCredential[]} */
  const credentials = () => issued.map(({ list, index, ...record }) => record);

  /** @param {OfferOptions} opts @returns {Promise<Offer>} */
  async function createOffer({ configurationIds, grant = 'pre-authorized_code', txCode, claims = {}, deferSeconds = 0 }) {
    const unknown = configurationIds.find((id) => !configurations[id]);
    if (configurationIds.length === 0 || unknown !== undefined) throw new Error(unknown === undefined ? 'An offer names at least one credential configuration' : `Unknown credential configuration ${unknown}`);
    if (!['pre-authorized_code', 'authorization_code'].includes(grant)) throw new Error(`Unknown grant ${grant}`);
    if (txCode && grant !== 'pre-authorized_code') throw new Error('A transaction code goes with the pre-authorized code grant only');
    const offer = { id: randomUUID(), configurationIds, claims, deferSeconds, expiresAt: Date.now() + OFFER_TTL_S * 1000, redeemed: false };
    let grants;
    if (grant === 'pre-authorized_code') {
      offer.preAuthorizedCode = randomBytes(24).toString('base64url');
      if (txCode) offer.txCode = txCode === true ? String(randomInt(1_000_000)).padStart(6, '0') : txCode;
      grants = { [preAuthorizedCodeGrantIdentifier]: { 'pre-authorized_code': offer.preAuthorizedCode,
        ...(offer.txCode ? { tx_code: { input_mode: /^\d+$/.test(offer.txCode) ? 'numeric' : 'text', length: offer.txCode.length } } : {}) } };
    } else {
      offer.issuerState = randomBytes(24).toString('base64url');
      grants = { [authorizationCodeGrantIdentifier]: { issuer_state: offer.issuerState } };
    }
    offers.set(offer.id, offer);
    const { credentialOffer, credentialOfferObject } = await issuer.createCredentialOffer({ issuerMetadata, credentialConfigurationIds: configurationIds, grants });
    return { offerId: offer.id, credentialOfferUri: credentialOffer, credentialOffer: credentialOfferObject, ...(offer.txCode ? { txCode: offer.txCode } : {}) };
  }

  /** Section 7.2. */
  function nonce() {
    const value = randomBytes(24).toString('base64url');
    nonces.set(value, Date.now() + NONCE_TTL_S * 1000);
    return issuer.createNonceResponse({ cNonce: value, cNonceExpiresIn: NONCE_TTL_S });
  }

  /** The credential configuration a request asks for, by identifier or by configuration id as the token response dictates (8.2). */
  function requestedConfiguration(parsed, grant) {
    if (grant.identifiers) {
      if (!parsed.credentialIdentifier) throw oauthError('invalid_credential_request', 'The token response carried credential_identifiers, so credential_identifier is required');
      const id = grant.identifiers[parsed.credentialIdentifier];
      if (!id) throw oauthError('unknown_credential_identifier', 'The credential_identifier is not one of the token response');
      return id;
    }
    if (!parsed.credentialConfigurationId) throw oauthError('invalid_credential_request', 'credential_configuration_id is required');
    if (!grant.configurationIds.includes(parsed.credentialConfigurationId)) throw oauthError('credential_request_denied', 'The access token does not cover this credential configuration');
    return parsed.credentialConfigurationId;
  }

  /**
   * Verifies the key proofs of a request (appendix F.4): one credential per proof, every proof carrying a nonce of the
   * nonce endpoint, which is spent by the request that presents it.
   */
  async function holderKeys(parsed, configurationId) {
    const proofs = parsed.proofs?.jwt ?? [];
    if (proofs.length === 0) throw oauthError('invalid_proof', 'A key proof of type jwt is required');
    if (proofs.length > BATCH_SIZE) throw oauthError('invalid_credential_request', `At most ${BATCH_SIZE} proofs per request`);
    const decoded = proofs.map((jwt) => {
      try { return { jwt, ...decodeJwt({ jwt }) }; } catch { throw oauthError('invalid_proof', 'A key proof is not a JWT'); }
    });
    const expiry = new Map(decoded.map(({ payload }) => [payload.nonce, nonces.get(payload.nonce)]));
    for (const value of expiry.keys()) nonces.delete(value);
    const signers = [];
    for (const { jwt, header, payload } of decoded) {
      if (!(expiry.get(payload.nonce) > Date.now())) throw oauthError('invalid_nonce', 'The proof carries no nonce of the nonce endpoint, or one that expired or was used already');
      if (!PROOF_ALGORITHMS.includes(header.alg)) throw oauthError('invalid_proof', `Proof algorithm ${header.alg} is not supported`);
      const proof = await issuer.verifyCredentialRequestJwtProof({ issuerMetadata, jwt, expectedNonce: payload.nonce })
        .catch((e) => { throw e instanceof Oauth2ServerErrorResponseError ? e : oauthError('invalid_proof', String(e.message)); });
      const wanted = configurations[configurationId].format === 'ldp_vc' ? 'did' : 'jwk';
      if (proof.signer.method !== wanted) {
        throw oauthError('invalid_proof', wanted === 'did' ? 'The proof must name the holder by a did:jwk URL in kid' : 'The proof must carry the holder key in the jwk header');
      }
      signers.push(proof.signer);
    }
    return signers;
  }

  /** Builds one credential for one holder key, and records it. */
  async function build(configurationId, grant, signer) {
    const { format, credential_definition: definition, vct } = configurations[configurationId];
    const claims = offers.get(grant.offerId)?.claims ?? {};
    const record = { offerId: grant.offerId, configurationId, format, issuedAt: timestamp(new Date()), revoked: false };
    let credential;
    if (format === 'ldp_vc') {
      record.list = 'bitstring';
      record.index = lists.allocate('bitstring');
      record.id = `${statusUrls.bitstring}#${record.index}`;
      const now = new Date();
      credential = await signCredential({
        '@context': definition['@context'], id: `urn:uuid:${randomUUID()}`, type: definition.type, issuer: did,
        validFrom: timestamp(now), validUntil: timestamp(new Date(now.getTime() + 365 * 86_400_000)),
        credentialStatus: { id: record.id, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(record.index), statusListCredential: statusUrls.bitstring },
        credentialSubject: { id: signer.didUrl.split('#')[0], givenName: 'Erika', familyName: 'Mustermann', degree: { type: 'BachelorDegree', name: 'Bachelor of Science' }, ...claims },
      }, assertionKeys[LDP_SUITES[configurationId]], LDP_SUITES[configurationId], loader);
    } else if (format === 'mso_mdoc') {
      credential = await issueMdl({ pki, deviceJwk: signer.publicJwk, claims });
    } else {
      record.list = 'token';
      record.index = lists.allocate('token');
      record.id = `${statusUrls.token}#${record.index}`;
      credential = await issueSdJwtVc({ pki, holderJwk: signer.publicJwk, vct, status: { uri: statusUrls.token, idx: record.index },
        claims: { given_name: 'Erika', family_name: 'Mustermann', birthdate: '1990-03-14', ...claims }, disclosable: ['given_name', 'family_name', 'birthdate', ...Object.keys(claims)] });
    }
    issued.push(record);
    return { credential, record };
  }

  /** Issues the credentials of a request and makes them notifiable (section 11). */
  async function issue(configurationId, grant, signers) {
    const built = [];
    for (const signer of signers) built.push(await build(configurationId, grant, signer));
    save();
    const notificationId = randomUUID();
    notifiable.set(notificationId, { grantId: grant.id, credentials: built.map(({ record }) => record) });
    return { credentials: built.map(({ credential }) => ({ credential })), notificationId };
  }

  /** Section 8: 200 with the credentials, or 202 with a transaction when the offer asked for deferred issuance. */
  async function credential(request, body) {
    const grant = await authorizationServer.authenticate(request);
    const parsed = await issuer.parseCredentialRequest({ credentialRequest: body, contentType: request.headers.get('content-type') ?? '', issuerMetadata });
    const configurationId = requestedConfiguration(parsed, grant);
    const signers = await holderKeys(parsed, configurationId);
    const deferSeconds = offers.get(grant.offerId)?.deferSeconds ?? 0;
    if (deferSeconds > 0) {
      const transactionId = randomUUID();
      transactions.set(transactionId, { grantId: grant.id, configurationId, signers, readyAt: Date.now() + deferSeconds * 1000 });
      const { credentialResponse } = await issuer.createCredentialResponse({ credentialRequest: parsed, transactionId, interval: DEFERRED_INTERVAL_S });
      return { status: 202, body: credentialResponse, headers: noStore };
    }
    const { credentialResponse } = await issuer.createCredentialResponse({ credentialRequest: parsed, ...(await issue(configurationId, grant, signers)) });
    return { status: 200, body: credentialResponse, headers: noStore };
  }

  /** Section 9: 202 with the same transaction while the issuance is pending, 200 with the credentials once it is due. */
  async function deferredCredential(request, body) {
    const grant = await authorizationServer.authenticate(request);
    const { deferredCredentialRequest } = await issuer.parseDeferredCredentialRequest({ deferredCredentialRequest: body, contentType: request.headers.get('content-type') ?? '', issuerMetadata });
    const transactionId = deferredCredentialRequest.transaction_id;
    const transaction = transactions.get(transactionId);
    if (!transaction || transaction.grantId !== grant.id) throw oauthError('invalid_transaction_id', 'Unknown or completed transaction');
    if (Date.now() < transaction.readyAt) {
      const { deferredCredentialResponse } = await issuer.createDeferredCredentialResponse({ transactionId, interval: DEFERRED_INTERVAL_S });
      return { status: 202, body: deferredCredentialResponse, headers: noStore };
    }
    transactions.delete(transactionId);
    const { deferredCredentialResponse } = await issuer.createDeferredCredentialResponse(await issue(transaction.configurationId, grant, transaction.signers));
    return { status: 200, body: deferredCredentialResponse, headers: noStore };
  }

  /** Section 11: records what the wallet reports about the credentials of an earlier response. */
  async function notification(request, body) {
    const grant = await authorizationServer.authenticate(request);
    const { notificationRequest } = issuer.parseNotificationRequest({ notificationRequest: body });
    const subject = notifiable.get(notificationRequest.notification_id);
    if (!subject || subject.grantId !== grant.id) throw oauthError('invalid_notification_id', 'Unknown notification_id');
    notifications.push({ notificationId: notificationRequest.notification_id, event: notificationRequest.event, eventDescription: notificationRequest.event_description,
      receivedAt: timestamp(new Date()), credentials: subject.credentials.map(({ id, configurationId }) => ({ id, configurationId })) });
    return { status: 204 };
  }

  /**
   * Sets the revocation status of an issued credential.
   * @param {string} id see IssuedCredential
   */
  function revokeCredential(id) {
    const record = issued.find((r) => r.id === id);
    if (!record) throw new Error(`No credential with status entry ${id} was issued`);
    lists.revoke(record.list, record.index);
    record.revoked = true;
    save();
  }

  /** Revokes the Document Signer certificate: from now on the IACA's CRL lists it. Mdocs keep being issued under it. */
  function revokeDocumentSigner() {
    documentSignerRevoked = true;
    save();
  }

  /** The W3C status list credential, signed like any credential of this issuer (Bitstring Status List section 2.2). */
  async function bitstringStatusList() {
    const credential = await lists.bitstringCredential(statusUrls.bitstring);
    return signCredential({ ...credential, issuer: did, validFrom: timestamp(new Date()) }, assertionKeys['ecdsa-rdfc-2019'], 'ecdsa-rdfc-2019', loader);
  }

  const ok = (body, headers) => ({ status: 200, body, headers });
  const routes = {
    'GET /.well-known/openid-credential-issuer': () => ok(credentialIssuer),
    'GET /.well-known/oauth-authorization-server': () => ok(authorizationServer.metadata),
    'GET /.well-known/did.json': () => ok(didDoc, { 'Content-Type': 'application/did+ld+json' }),
    'GET /jwks': () => ok(authorizationServer.jwks),
    'GET /contexts/reference/v1': () => ok(REFERENCE_CONTEXT, { 'Content-Type': 'application/ld+json' }),
    'GET /status/bitstring': async () => ok(await bitstringStatusList(), { 'Content-Type': 'application/vc' }),
    'GET /status/token': async () => ok(await signStatusListToken({ pki, list: lists.tokenStatusList(), uri: statusUrls.token }), { 'Content-Type': 'application/statuslist+jwt' }),
    'GET /pki/iaca.pem': () => ok(pki.iaca.pem, { 'Content-Type': 'application/x-pem-file' }),
    'GET /pki/issuer-ca.pem': () => ok(pki.issuerCa.pem, { 'Content-Type': 'application/x-pem-file' }),
    // A new CRL per request, numbered by the clock: later CRLs carry larger numbers, also across restarts.
    'GET /pki/iaca.crl': async () => ok(await createCrl(iaca, documentSignerRevoked ? [pki.ds.serialNumber] : [], { number: Date.now() }), { 'Content-Type': 'application/pkix-crl' }),
    'GET /authorize': (request) => authorizationServer.authorize(request),
    'POST /par': async (request, body) => ({ status: 201, body: (await authorizationServer.par(request, body)).pushedAuthorizationResponse, headers: noStore }),
    'POST /token': async (request, body) => ok(await authorizationServer.token(request, body), noStore),
    'POST /nonce': () => ok(nonce(), noStore),
    'POST /credential': credential,
    'POST /deferred_credential': deferredCredential,
    'POST /notification': notification,
    'POST /api/offers': async (request, body) => ok(await createOffer(body)),
    'POST /api/revoke': (request, body) => { revokeCredential(body.id); return ok({ id: body.id, revoked: true }); },
    'POST /api/revoke-document-signer': () => { revokeDocumentSigner(); return ok({ serialNumber: pki.ds.serialNumber, revoked: true }); },
    'GET /api/credentials': () => ok(credentials()),
    'GET /api/notifications': () => ok(notifications),
  };

  /**
   * @param {{ method: string, url: string, headers: Headers }} request
   * @param {unknown} body the parsed JSON or form body
   * @returns {Promise<{ status: number, body?: unknown, headers?: Record<string, string> }>}
   */
  async function handle(request, body) {
    const { pathname, search } = new URL(request.url);
    const route = routes[`${request.method} ${pathname}`];
    if (!route) return { status: 404, body: { error: 'not_found' } };
    try {
      // The public URL of the request, whatever host the connection named: it is what DPoP proofs sign (htu).
      return await route({ ...request, url: `${baseUrl}${pathname}${search}` }, body);
    } catch (e) {
      if (e instanceof Oauth2ServerErrorResponseError) return { status: e.status, body: e.errorResponse, headers: noStore };
      if (e instanceof Oauth2ResourceUnauthorizedError) {
        return { status: 401, body: { error: e.wwwAuthenticateHeaders.find((h) => h.error)?.error ?? 'invalid_token' }, headers: { 'WWW-Authenticate': e.toHeaderValue() } };
      }
      if (e instanceof ValidationError) return { status: 400, body: { error: 'invalid_request', error_description: e.message }, headers: noStore };
      if (pathname.startsWith('/api/')) return { status: 400, body: { error: 'invalid_request', error_description: String(e.message ?? e) } };
      console.error(e);
      return { status: 500, body: { error: 'server_error' } };
    }
  }

  return {
    baseUrl, did, contextUrl, statusUrls, configurationIds: Object.keys(configurations), issuerMetadata, handle, createOffer, revokeCredential, revokeDocumentSigner,
    credentials, notifications: () => [...notifications],
  };
}
