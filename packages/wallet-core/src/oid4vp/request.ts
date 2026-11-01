/**
 * OpenID4VP 1.0 authorization request handling: request_uri (GET / POST with wallet_metadata + wallet_nonce),
 * JAR verification per client_id prefix (x509_hash, x509_san_dns, decentralized_identifier, redirect_uri),
 * and verifier trust through the trust client.
 */
import { decodeJws, verifyJws, parseCertificate, findVerificationMethod, verificationMethodPublicKey, type TrustClient, type TrustDecision, type Jwk } from '@vctrust/trust-client';
import { randomId } from '../crypto/jwt.js';

export interface DcqlClaim { id?: string; path: (string | number | null)[]; values?: unknown[]; intent_to_retain?: boolean }
export interface DcqlCredentialQuery {
  id: string; format: string; multiple?: boolean; meta?: Record<string, unknown>; claims?: DcqlClaim[]; claim_sets?: string[][];
  trusted_authorities?: { type: string; values: string[] }[]; require_cryptographic_holder_binding?: boolean;
}
export interface DcqlQuery { credentials: DcqlCredentialQuery[]; credential_sets?: { options: string[][]; required?: boolean; purpose?: unknown }[] }

export interface AuthorizationRequest {
  clientId: string;
  prefix: string;
  responseType: string;
  responseMode: string;
  responseUri?: string;
  redirectUri?: string;
  nonce: string;
  state?: string;
  dcqlQuery: DcqlQuery;
  clientMetadata: Record<string, unknown>;
  signed: boolean;
  x5c?: string[];
  raw: Record<string, unknown>;
}

export interface VerifierView {
  clientId: string;
  prefix: string;
  name?: string;
  logoUri?: string;
  trust: TrustDecision;
  /** Checks done locally on the request object */
  checks: { label: string; ok: boolean; detail?: string }[];
  /** Why the wallet will not present to this verifier (shown to the user; only a decline can be sent) */
  refusal?: string;
}

/** Where an error response may go: the response_uri of an authenticated request (OpenID4VP §8.5). */
export interface ErrorResponseTarget {
  responseUri: string;
  state?: string;
}

export class PresentationRequestError extends Error {
  /**
   * @param reportTo set when the request was authenticated, so the error may be returned to the verifier — after the
   *   user has seen it (OpenID4VP §15.9.2): {@link reportPresentationError}
   */
  constructor(message: string, readonly code = 'invalid_request', readonly reportTo?: ErrorResponseTarget) {
    super(message);
    this.name = 'PresentationRequestError';
  }
}

/** Sends an error Authorization Response for a request that failed after it was authenticated (unencrypted, §8.3.1). */
export async function reportPresentationError(err: PresentationRequestError, f: typeof fetch = fetch): Promise<number> {
  if (!err.reportTo) throw new Error('This request cannot be answered with an error');
  const form = new URLSearchParams({ error: err.code, error_description: err.message, ...(err.reportTo.state ? { state: err.reportTo.state } : {}) });
  const r = await f(err.reportTo.responseUri, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form.toString() });
  return r.status;
}

const SKEW_S = 300;

const PREFIXES = new Set(['redirect_uri', 'x509_san_dns', 'x509_hash', 'decentralized_identifier', 'verifier_attestation', 'openid_federation', 'origin']);

export function clientIdPrefix(clientId: string): { prefix: string; value: string } {
  const i = clientId.indexOf(':');
  const p = i > 0 ? clientId.slice(0, i) : '';
  return PREFIXES.has(p) ? { prefix: p, value: clientId.slice(i + 1) } : { prefix: 'pre-registered', value: clientId };
}

export const WALLET_METADATA = {
  vp_formats_supported: {
    'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
    mso_mdoc: { issuerauth_alg_values: [-7, -9], deviceauth_alg_values: [-7, -9] },
    ldp_vc: { proof_type_values: ['DataIntegrityProof', 'Ed25519Signature2020'], cryptosuite_values: ['ecdsa-rdfc-2019', 'eddsa-rdfc-2022'] },
  },
  client_id_prefixes_supported: ['x509_hash', 'x509_san_dns', 'decentralized_identifier', 'redirect_uri'],
  request_object_signing_alg_values_supported: ['ES256', 'ES384', 'ES512', 'EdDSA', 'RS256', 'PS256'],
  response_modes_supported: ['direct_post', 'direct_post.jwt'],
  authorization_encryption_alg_values_supported: ['ECDH-ES'],
  authorization_encryption_enc_values_supported: ['A128GCM', 'A256GCM'],
};

export async function resolveAuthorizationRequest(uri: string, trust: TrustClient, f: typeof fetch): Promise<{ request: AuthorizationRequest; verifier: VerifierView }> {
  const q = new URLSearchParams(uri.includes('?') ? uri.slice(uri.indexOf('?') + 1) : uri);
  const queryClientId = q.get('client_id') ?? '';
  let raw: Record<string, unknown>;
  let header: Record<string, unknown> | undefined;
  let jws: ReturnType<typeof decodeJws> | undefined;
  const checks: VerifierView['checks'] = [];
  const requestUri = q.get('request_uri');
  let walletNonce: string | undefined;
  if (requestUri || q.get('request')) {
    // JAR (RFC 9101 §5): client_id accompanies request / request_uri; it must equal the request object's (§5.10.1).
    if (!queryClientId) throw new PresentationRequestError('client_id is required alongside request_uri / request', 'invalid_request');
    let jwt = q.get('request') ?? '';
    if (requestUri) {
      const method = (q.get('request_uri_method') ?? 'get').toLowerCase();
      if (method !== 'get' && method !== 'post') throw new PresentationRequestError(`Unsupported request_uri_method ${method}`, 'invalid_request_uri_method');
      const r = method === 'post'
        ? await f(requestUri, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/oauth-authz-req+jwt' },
          body: new URLSearchParams({ wallet_metadata: JSON.stringify(WALLET_METADATA), wallet_nonce: (walletNonce = randomId()) }).toString() })
        : await f(requestUri, { headers: { Accept: 'application/oauth-authz-req+jwt' } });
      if (!r.ok) throw new PresentationRequestError(`Fetching request_uri failed: HTTP ${r.status}`);
      jwt = (await r.text()).trim();
    }
    jws = decodeJws(jwt);
    header = jws.header;
    raw = jws.payload as Record<string, unknown>;
    if (header.typ !== 'oauth-authz-req+jwt') throw new PresentationRequestError(`Request object typ must be oauth-authz-req+jwt (got ${String(header.typ)})`);
    checks.push({ label: 'Request object type', ok: true, detail: 'oauth-authz-req+jwt' });
    if (walletNonce && raw.wallet_nonce !== walletNonce) throw new PresentationRequestError('wallet_nonce mismatch');
    const now = Math.floor(Date.now() / 1000);
    if (typeof raw.exp === 'number' && raw.exp < now - SKEW_S) throw new PresentationRequestError(`Request object expired at ${new Date(raw.exp * 1000).toISOString()}`);
    if (typeof raw.nbf === 'number' && raw.nbf > now + SKEW_S) throw new PresentationRequestError('Request object is not yet valid');
  } else {
    raw = Object.fromEntries(q.entries());
    for (const k of ['dcql_query', 'client_metadata']) if (typeof raw[k] === 'string') raw[k] = JSON.parse(raw[k] as string);
  }
  const clientId = String(raw.client_id ?? '');
  if (!clientId || (queryClientId && queryClientId !== clientId)) throw new PresentationRequestError('client_id in request object does not match the query parameter', 'invalid_client');
  const { prefix, value } = clientIdPrefix(clientId);
  const x5c = Array.isArray(header?.x5c) ? (header!.x5c as string[]) : undefined;
  const responseMode = String(raw.response_mode ?? 'fragment');
  const responseUri = raw.response_uri as string | undefined;

  // Signature and prefix rules (OID4VP §5.9.3)
  if (prefix === 'x509_san_dns' || prefix === 'x509_hash') {
    if (!jws || !x5c?.length) throw new PresentationRequestError(`${prefix} requires a signed request object with x5c`, 'invalid_client');
    const leaf = parseCertificate(x5c[0]!);
    if (!leaf.publicKey || !verifyJws(jws, leaf.publicKey)) throw new PresentationRequestError('Request object signature is invalid', 'invalid_client');
    checks.push({ label: 'Request signature', ok: true, detail: `signed by ${leaf.subject}` });
    if (prefix === 'x509_hash') {
      if (leaf.sha256 !== value) throw new PresentationRequestError('x509_hash does not match the signing certificate', 'invalid_client');
      checks.push({ label: 'x509_hash binding', ok: true, detail: 'client_id is the SHA-256 of the signing certificate' });
    } else {
      if (!leaf.dnsNames.includes(value)) throw new PresentationRequestError(`Signing certificate has no SAN dNSName ${value}`, 'invalid_client');
      checks.push({ label: 'x509_san_dns binding', ok: true, detail: `SAN ${value}` });
    }
  } else if (prefix === 'decentralized_identifier') {
    // The kid's DID must be the client_id's DID exactly (a prefix match would let did:web:bank.com.evil.net pass).
    if (!jws || typeof header?.kid !== 'string' || header.kid.split('#')[0] !== value) {
      throw new PresentationRequestError('decentralized_identifier requires a request signed with a key of that DID', 'invalid_client');
    }
    const resolved = await trust.resolveDid(header.kid);
    const vm = resolved.didDocument ? findVerificationMethod(resolved.didDocument, header.kid) : undefined;
    if (!vm || !verifyJws(jws, verificationMethodPublicKey(vm))) throw new PresentationRequestError('Request object signature is invalid', 'invalid_client');
    checks.push({ label: 'Request signature', ok: true, detail: `signed by ${header.kid}` });
  } else if (prefix === 'redirect_uri') {
    if (jws) throw new PresentationRequestError('redirect_uri client identifiers must not use signed requests');
    if (value !== (responseUri ?? raw.redirect_uri)) throw new PresentationRequestError('redirect_uri client_id does not match the response URI', 'invalid_client');
    checks.push({ label: 'Request signature', ok: false, detail: 'Unsigned request (redirect_uri client identifier)' });
  } else {
    throw new PresentationRequestError(`Unsupported client identifier prefix ${prefix}`, 'invalid_client');
  }
  // Verifier trust. Errors may go back only to a verifier that signed the request and is not refused.
  const trustDecision = await trust.evaluateVerifier({ clientId, x5c, kid: header?.kid as string | undefined, responseUri });
  const refusal = verifierRefusal(prefix, trustDecision);
  const reportTo = jws && !refusal && responseUri && responseMode.startsWith('direct_post') ? { responseUri, state: raw.state as string | undefined } : undefined;
  // Request well-formedness.
  const fail = (message: string, code = 'invalid_request') => new PresentationRequestError(message, code, reportTo);
  if (raw.response_type !== 'vp_token') throw fail(`Unsupported response_type ${String(raw.response_type)}`, 'unsupported_response_type');
  if (typeof raw.nonce !== 'string' || !raw.nonce) throw fail('nonce is required');
  if (raw.presentation_definition) throw fail('presentation_definition is not part of OpenID4VP 1.0; use dcql_query');
  if (!raw.dcql_query) throw fail('dcql_query is required');
  if (raw.dcql_query && raw.scope) throw fail('dcql_query and scope must not both be present');
  if (responseMode.startsWith('direct_post') && !responseUri) throw new PresentationRequestError('response_uri is required for direct_post');
  // §8.2: redirect_uri with direct_post MUST be answered with invalid_request.
  if (responseUri && raw.redirect_uri) throw fail('redirect_uri must not be present with response_uri');
  // §8.4: a wallet that does not support transaction_data MUST return an error.
  if (raw.transaction_data) throw fail('transaction_data is not supported by this wallet', 'invalid_transaction_data');
  if (!['direct_post', 'direct_post.jwt'].includes(responseMode)) throw new PresentationRequestError(`Unsupported response_mode ${responseMode}`);
  if (responseMode === 'direct_post.jwt' && !encryptionKey((raw.client_metadata ?? {}) as Record<string, unknown>)) {
    throw fail('client_metadata.jwks has no P-256 key with alg ECDH-ES for direct_post.jwt');
  }

  const md = (raw.client_metadata ?? {}) as Record<string, unknown>;
  const request: AuthorizationRequest = {
    clientId, prefix, responseType: 'vp_token', responseMode, responseUri, redirectUri: raw.redirect_uri as string | undefined,
    nonce: String(raw.nonce), state: raw.state as string | undefined, dcqlQuery: raw.dcql_query as DcqlQuery, clientMetadata: md,
    signed: !!jws, x5c, raw,
  };
  return { request, verifier: { clientId, prefix, trust: trustDecision, checks, refusal,
    name: (md.client_name as string | undefined) ?? trustDecision.entity?.display?.[0]?.name, logoUri: md.logo_uri as string | undefined } };
}

/**
 * x509_hash / x509_san_dns: the wallet MUST validate the certificate's trust chain (OpenID4VP §5.9.3), so anything but
 * TRUSTED is refused. Other prefixes: a verifier the trust service says NOT_TRUSTED is refused; UNKNOWN is left to the user.
 */
export function verifierRefusal(prefix: string, d: TrustDecision): string | undefined {
  if (d.decision === 'NOT_TRUSTED') return `The verifier is not trusted: ${d.summary}`;
  if ((prefix === 'x509_hash' || prefix === 'x509_san_dns') && d.decision !== 'TRUSTED') {
    return `The verifier's certificate does not chain to a trusted verifier CA: ${d.summary}`;
  }
  return undefined;
}

/** The verifier's response encryption key: every JWK carries alg (§8.3); this wallet does ECDH-ES on P-256. */
export function encryptionKey(md: Record<string, unknown>): Jwk | undefined {
  const keys = ((md.jwks as { keys?: Jwk[] } | undefined)?.keys ?? []) as Jwk[];
  return keys.find((k) => k.kty === 'EC' && k.crv === 'P-256' && (!k.use || k.use === 'enc') && k.alg === 'ECDH-ES');
}
