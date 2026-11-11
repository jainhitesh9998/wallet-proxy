/**
 * Reference verifier: OpenID4VP 1.0 on the protocol library behind Animo's playground (@openid4vc/openid4vp). A signed
 * request object passed by reference (section 5.10), the `x509_hash` client identifier prefix (5.9.3), a DCQL query
 * (section 6), and the response modes `direct_post` and `direct_post.jwt` (8.2, 8.3). The response is validated by the
 * library, each presentation is verified by the reference implementation of its format (8.6, appendix B), the DCQL
 * query is evaluated by the `dcql` library, and the issuer is put to the injected trust decision.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Oauth2ServerErrorResponseError, setGlobalConfig } from '@openid4vc/oauth2';
import { calculateX509HashClientIdPrefixValue, Openid4vpVerifier, zOpenid4vpAuthorizationErrorResponse } from '@openid4vc/openid4vp';
import { DcqlPresentationResult, DcqlQuery } from 'dcql';
import { generateEcJwk, joseCallbacks, publicOf, RESPONSE_ENCRYPTION, thumbprint } from './keys.mjs';
import { documentLoader, expandedTypes, failureReasons, isSubjectKey, SUITES, verifyPresentation } from './ldp.mjs';
import { mdocClaims, verifyDeviceResponse } from './mdoc.mjs';
import { b64Der } from './pki.mjs';
import { SIGNATURE_ALGORITHMS, verifySdJwtVc } from './sdjwt.mjs';
import { referenceTrust } from './trust.mjs';

const REQUEST_TTL_S = 300;
/** What the reference implementations verify (section 11.1, vp_formats_supported; COSE -7 is ES256, -9 ESP256). */
const VP_FORMATS = {
  ldp_vc: { proof_type_values: ['DataIntegrityProof'], cryptosuite_values: Object.keys(SUITES) },
  mso_mdoc: { issuerauth_alg_values: [-7, -9], deviceauth_alg_values: [-7, -9] },
  'dc+sd-jwt': { 'sd-jwt_alg_values': SIGNATURE_ALGORITHMS, 'kb-jwt_alg_values': SIGNATURE_ALGORITHMS },
};
const TYPE_PARAMETER = { ldp_vc: 'type', mso_mdoc: 'doctype', 'dc+sd-jwt': 'vct' };

/**
 * @typedef {{ id?: string, format: 'ldp_vc' | 'mso_mdoc' | 'dc+sd-jwt', type?: string | string[], doctype?: string, vct?: string,
 *   claims?: Array<Array<string | number | null>> }} CredentialOptions `type` (ldp_vc) holds expanded type IRIs that must all be
 *   present, `doctype` (mso_mdoc) and `vct` (dc+sd-jwt) name the credential type; `claims` are claims path pointers
 * @typedef {{ credentials: CredentialOptions[], responseMode?: 'direct_post.jwt' | 'direct_post' }} RequestOptions
 * @typedef {{ id: string, status: 'pending' | 'verified' | 'failed' | 'rejected' | 'expired', error?: string,
 *   credentials?: Record<string, Array<{ format: string, issuer?: string, type: string | string[], claims: object }>> }} RequestState
 *   `failed`: the response did not verify, `error` says why; `rejected`: the wallet answered with an error response
 */

/** The DCQL Credential Query (section 6.1 and the `meta` of appendix B) of simple options. */
function credentialQuery({ id, format, claims, ...options }, index) {
  if (!TYPE_PARAMETER[format]) throw new Error(`Unsupported credential format ${format}`);
  const value = options[TYPE_PARAMETER[format]];
  if (value === undefined) throw new Error(`A ${format} credential needs '${TYPE_PARAMETER[format]}'`);
  const meta = { ldp_vc: { type_values: [[value].flat()] }, mso_mdoc: { doctype_value: value }, 'dc+sd-jwt': { vct_values: [value] } }[format];
  return { id: id ?? `credential_${index}`, format, meta, ...(claims ? { claims: claims.map((path) => ({ path })) } : {}) };
}

/**
 * @param {{ baseUrl: string, pki: import('./pki.mjs').Pki, fetch?: typeof fetch,
 *   isTrustedIssuer?: (info: import('./trust.mjs').IssuerInfo) => Promise<boolean> }} opts `isTrustedIssuer` decides
 *   which issuers are accepted (default: the reference PKI and DID); `fetch` retrieves DID documents, JSON-LD
 *   contexts, status lists and CRLs
 */
export async function createVerifier({ baseUrl, pki, fetch: fetcher = fetch, isTrustedIssuer = referenceTrust(pki, fetcher) }) {
  if (baseUrl.startsWith('http://')) setGlobalConfig({ allowInsecureUrls: true });
  const signing = joseCallbacks([pki.verifier.privateJwk]);
  const openid4vp = new Openid4vpVerifier({ callbacks: signing });
  const certificate = b64Der(pki.verifier.pem);
  const clientId = `x509_hash:${await calculateX509HashClientIdPrefixValue({ x509Certificate: certificate, hash: signing.hash })}`;
  const loader = documentLoader({ fetch: fetcher });
  /** request id → { state, payload, jwt, encryptionKey, expiresAt, answered } */
  const requests = new Map();

  /** @param {RequestOptions} opts @returns {Promise<{ id: string, authorizationRequestUri: string }>} */
  async function createRequest({ credentials, responseMode = 'direct_post.jwt' }) {
    if (!['direct_post.jwt', 'direct_post'].includes(responseMode)) throw new Error(`Unsupported response mode ${responseMode}`);
    const query = DcqlQuery.parse({ credentials: credentials.map(credentialQuery) });
    DcqlQuery.validate(query);
    const id = randomUUID();
    // Section 8.3: the response is encrypted to a key of this request alone, named with `kid` and `alg` in client_metadata.
    const encryptionKey = responseMode === 'direct_post.jwt' ? { ...(await generateEcJwk()), kid: randomUUID(), use: 'enc', alg: RESPONSE_ENCRYPTION.alg } : undefined;
    const { authorizationRequest, authorizationRequestPayload, jar } = await openid4vp.createOpenId4vpAuthorizationRequest({
      authorizationRequestPayload: {
        response_type: 'vp_token', client_id: clientId, response_mode: responseMode, response_uri: `${baseUrl}/response/${id}`,
        nonce: randomBytes(24).toString('base64url'), dcql_query: query,
        client_metadata: { vp_formats_supported: VP_FORMATS,
          ...(encryptionKey ? { jwks: { keys: [publicOf(encryptionKey)] }, encrypted_response_enc_values_supported: RESPONSE_ENCRYPTION.enc } : {}) },
      },
      jar: { requestUri: `${baseUrl}/request/${id}`, jwtSigner: { method: 'x5c', x5c: [certificate], alg: 'ES256' }, expiresInSeconds: REQUEST_TTL_S },
    });
    requests.set(id, { state: { id, status: 'pending' }, payload: authorizationRequestPayload, jwt: jar.authorizationRequestJwt, encryptionKey, expiresAt: Date.now() + REQUEST_TTL_S * 1000 });
    return { id, authorizationRequestUri: authorizationRequest };
  }

  /** The request, with its state brought up to date: a pending request expires with its request object. */
  const requestOf = (id) => {
    const request = requests.get(id);
    if (request?.state.status === 'pending' && request.expiresAt < Date.now()) request.state = { id, status: 'expired' };
    return request;
  };

  /** @returns {RequestState | undefined} */
  const requestState = (id) => requestOf(id)?.state;

  /**
   * Verifies one presentation with the reference implementation of its format: integrity and authenticity, holder
   * binding to this request (nonce and client identifier), and status (section 8.6 step 2, a, c and d).
   * @returns {Promise<{ info: import('./trust.mjs').IssuerInfo, claims: object, dcql: object }>}
   */
  async function verifyOne(format, presentation, { payload, encryptionJwk }) {
    if (format === 'ldp_vc') {
      const credentials = [presentation?.verifiableCredential].flat();
      if (typeof presentation !== 'object' || credentials.length !== 1 || typeof credentials[0] !== 'object') throw new Error('An ldp_vc presentation is a Verifiable Presentation with one credential');
      const result = await verifyPresentation(presentation, { challenge: payload.nonce, domain: clientId }, loader);
      if (!result.verified) throw new Error(`The presentation does not verify: ${failureReasons(result)}`);
      const [credential] = credentials;
      if (!(await isSubjectKey(credential, result.presentationResult.results[0].verificationMethod, loader))) throw new Error('The presentation is not signed with a key of the credential subject');
      const type = await expandedTypes(credential, loader);
      return { info: { format, issuer: credential.issuer?.id ?? credential.issuer, type }, claims: credential,
        dcql: { credential_format: format, type, claims: credential, cryptographic_holder_binding: true } };
    }
    if (typeof presentation !== 'string') throw new Error(`A ${format} presentation is a string`);
    if (format === 'dc+sd-jwt') {
      const { payload: claims, x5c } = await verifySdJwtVc(presentation, { keyBinding: { nonce: payload.nonce, audience: clientId }, fetch: fetcher });
      return { info: { format, issuer: claims.iss, x5c, type: claims.vct }, claims,
        dcql: { credential_format: format, vct: claims.vct, claims, cryptographic_holder_binding: true } };
    }
    // Appendix B.2.6.1: the handover names the key the response was encrypted to, or null when it was not encrypted.
    const handover = { clientId, nonce: payload.nonce, responseUri: payload.response_uri,
      jwkThumbprint: encryptionJwk && new Uint8Array(Buffer.from(await thumbprint(encryptionJwk), 'base64url')) };
    let info;
    const documents = await verifyDeviceResponse(presentation, handover, async (x5c, type) => {
      info = { format, x5c, type };
      if (!(await isTrustedIssuer(info))) throw new Error('The issuer of the mdoc is not trusted');
      return [Buffer.from(x5c[0], 'base64')];
    });
    if (documents.length !== 1) throw new Error('An mso_mdoc presentation is a DeviceResponse with one document');
    const claims = mdocClaims(documents[0].issuerSigned);
    return { info, claims, dcql: { credential_format: format, doctype: documents[0].docType, namespaces: claims, cryptographic_holder_binding: true } };
  }

  /** Section 8.6: every presentation verifies, the issuers are trusted, and together they satisfy the DCQL query. */
  async function verifyResponse(request, body) {
    const { payload, encryptionKey } = request;
    const parsed = await openid4vp.parseOpenid4vpAuthorizationResponse({ authorizationResponse: body, authorizationRequestPayload: payload,
      callbacks: joseCallbacks(encryptionKey ? [encryptionKey] : []) });
    const formats = Object.fromEntries(payload.dcql_query.credentials.map((c) => [c.id, c.format]));
    const credentials = {};
    const presented = {};
    for (const [queryId, presentations] of Object.entries(parsed.dcql.presentations)) {
      if (!formats[queryId]) throw new Error(`The response answers a credential query '${queryId}' that was not asked`);
      credentials[queryId] = [];
      presented[queryId] = [];
      for (const presentation of presentations) {
        const { info, claims, dcql } = await verifyOne(formats[queryId], presentation, { payload, encryptionJwk: parsed.jarm?.decryptionJwk });
        if (info.format !== 'mso_mdoc' && !(await isTrustedIssuer(info))) throw new Error(`The issuer of the ${info.format} credential is not trusted`);
        credentials[queryId].push({ format: info.format, issuer: info.issuer, type: info.type, claims });
        presented[queryId].push(dcql);
      }
    }
    const match = DcqlPresentationResult.fromDcqlPresentation(presented, { dcqlQuery: payload.dcql_query });
    if (!match.can_be_satisfied) {
      const unmet = Object.values(match.credential_matches).filter((m) => !m.success || m.failed_credentials).map((m) => m.credential_query_id);
      throw new Error(`The presentations do not satisfy the DCQL query (${unmet.join(', ')})`);
    }
    return credentials;
  }

  /** The response endpoint (section 8.2). A request takes one response; what it led to is in the request state. */
  async function response(id, body) {
    const request = requestOf(id);
    if (request?.state.status !== 'pending' || request.answered) return { status: 400, body: { error: 'invalid_request', error_description: 'Unknown, answered or expired request' } };
    request.answered = true;
    const walletError = typeof body?.error === 'string' && zOpenid4vpAuthorizationErrorResponse.safeParse(body);
    if (walletError?.success) {
      request.state = { id, status: 'rejected', error: [walletError.data.error, walletError.data.error_description].filter(Boolean).join(': ') };
      return { status: 200, body: {} };
    }
    try {
      request.state = { id, status: 'verified', credentials: await verifyResponse(request, body) };
      return { status: 200, body: {} };
    } catch (e) {
      const reason = e instanceof Oauth2ServerErrorResponseError ? e.errorResponse.error_description ?? e.errorResponse.error : String(e.message ?? e);
      request.state = { id, status: 'failed', error: reason };
      return { status: 400, body: { error: 'invalid_request', error_description: reason } };
    }
  }

  /**
   * @param {{ method: string, url: string, headers: Headers }} request
   * @param {unknown} body the parsed JSON or form body
   * @returns {Promise<{ status: number, body?: unknown, headers?: Record<string, string> }>}
   */
  async function handle(request, body) {
    const { pathname } = new URL(request.url);
    const id = (method, pattern) => (request.method === method ? pattern.exec(pathname)?.[1] : undefined);
    const notFound = { status: 404, body: { error: 'not_found' } };
    let requestId;
    if ((requestId = id('GET', /^\/request\/([^/]+)$/))) {
      // Section 5.10.1: the request object, by reference.
      const request = requestOf(requestId);
      return request?.state.status === 'pending' ? { status: 200, body: request.jwt, headers: { 'Content-Type': 'application/oauth-authz-req+jwt', 'Cache-Control': 'no-store' } } : notFound;
    }
    if ((requestId = id('POST', /^\/response\/([^/]+)$/))) return response(requestId, body);
    if ((requestId = id('GET', /^\/api\/requests\/([^/]+)$/))) {
      const state = requestState(requestId);
      return state ? { status: 200, body: state } : notFound;
    }
    if (request.method === 'POST' && pathname === '/api/requests') {
      try {
        return { status: 200, body: await createRequest(body) };
      } catch (e) {
        return { status: 400, body: e instanceof Oauth2ServerErrorResponseError ? e.errorResponse : { error: 'invalid_request', error_description: String(e.message ?? e) } };
      }
    }
    if (request.method === 'GET' && pathname === '/pki/verifier-ca.pem') return { status: 200, body: pki.verifierCa.pem, headers: { 'Content-Type': 'application/x-pem-file' } };
    return notFound;
  }

  return { baseUrl, clientId, handle, createRequest, requestState };
}
