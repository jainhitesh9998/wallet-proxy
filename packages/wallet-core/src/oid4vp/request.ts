/**
 * OpenID4VP 1.0 authorization request handling: request_uri (GET / POST with wallet_metadata + wallet_nonce),
 * JAR verification per client_id prefix (x509_hash, x509_san_dns, decentralized_identifier, redirect_uri),
 * and verifier trust through the trust client.
 */
import type { Jwk, TrustClient, TrustDecision } from '@vctrust/trust-client';
import { decodeJws, verifyJws, parseCertificate, findVerificationMethod, verificationMethodPublicKey } from '@vctrust/trust-client/primitives';
import { randomId } from '../crypto/jwt.js';
import { requireHttps } from '../net.js';
import { CLOCK_SKEW_MS } from '../verify/report.js';
import { dcqlProblem } from './dcql.js';

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
  /** DC API: the verifier's Origin as the platform reported it; the response is bound to it, not to client_id (A.4) */
  origin?: string;
  raw: Record<string, unknown>;
}

export interface VerifierView {
  clientId: string;
  prefix: string;
  /** DC API: the origin the request came from */
  origin?: string;
  /** the trust registry's name for the verifier, or else the request's client_name ({@link nameSelfDeclared}) */
  name?: string;
  /** the name is the verifier's own claim (client_name), not the registry's */
  nameSelfDeclared?: boolean;
  /** a logo to show: only for a verifier the trust layer knows (an image URL from an unknown party is not fetched) */
  logoUri?: string;
  trust: TrustDecision;
  /** Checks done locally on the request object */
  checks: { label: string; ok: boolean; detail?: string }[];
  /** Why the wallet will not present to this verifier (shown to the user; only a decline can be sent) */
  refusal?: string;
}

/**
 * Where an error response may go (OpenID4VP §8.5): the response_uri of an authenticated request, or, over the DC API,
 * back through the platform as {@code {error}} ({@link dcApiError}).
 */
export interface ErrorResponseTarget {
  responseUri?: string;
  state?: string;
  dcApi?: boolean;
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
  if (!err.reportTo?.responseUri) throw new Error('This request cannot be answered with an error over HTTP');
  const form = new URLSearchParams({ error: err.code, error_description: err.message, ...(err.reportTo.state ? { state: err.reportTo.state } : {}) });
  const r = await f(err.reportTo.responseUri, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form.toString() });
  return r.status;
}

/** The DC API response data for an error: a single error member (A.4), returned only after the user saw it (§15.9.2). */
export function dcApiError(err: PresentationRequestError): { error: string } {
  if (!err.reportTo?.dcApi) throw new Error('This request cannot be answered with an error');
  return { error: err.code };
}

const SKEW_S = CLOCK_SKEW_MS / 1000;

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

export async function resolveAuthorizationRequest(uri: string, trust: TrustClient, f: typeof fetch, insecureHosts: readonly string[] = []): Promise<{ request: AuthorizationRequest; verifier: VerifierView }> {
  const q = new URLSearchParams(uri.includes('?') ? uri.slice(uri.indexOf('?') + 1) : uri);
  const queryClientId = q.get('client_id') ?? '';
  let raw: Record<string, unknown>;
  let jws: Jws | undefined;
  const checks: VerifierView['checks'] = [];
  const requestUri = q.get('request_uri');
  if (requestUri || q.get('request')) {
    // JAR (RFC 9101 §5): client_id accompanies request / request_uri; it must equal the request object's (§5.10.1).
    if (!queryClientId) throw new PresentationRequestError('client_id is required alongside request_uri / request', 'invalid_request');
    let jwt = q.get('request') ?? '';
    let walletNonce: string | undefined;
    if (requestUri) {
      const method = (q.get('request_uri_method') ?? 'get').toLowerCase();
      if (method !== 'get' && method !== 'post') throw new PresentationRequestError(`Unsupported request_uri_method ${method}`, 'invalid_request_uri_method');
      requireHttps(requestUri, 'request_uri', insecureHosts);
      const r = method === 'post'
        ? await f(requestUri, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/oauth-authz-req+jwt' },
          body: new URLSearchParams({ wallet_metadata: JSON.stringify(WALLET_METADATA), wallet_nonce: (walletNonce = randomId()) }).toString() })
        : await f(requestUri, { headers: { Accept: 'application/oauth-authz-req+jwt' } });
      if (!r.ok) throw new PresentationRequestError(`Fetching request_uri failed: HTTP ${r.status}`);
      jwt = (await r.text()).trim();
    }
    jws = readRequestObject(jwt, checks);
    raw = jws.payload as Record<string, unknown>;
    if (walletNonce && raw.wallet_nonce !== walletNonce) throw new PresentationRequestError('wallet_nonce mismatch');
  } else {
    raw = Object.fromEntries(q.entries());
    for (const k of ['dcql_query', 'client_metadata']) if (typeof raw[k] === 'string') raw[k] = JSON.parse(raw[k] as string);
  }
  const clientId = String(raw.client_id ?? '');
  if (!clientId || (queryClientId && queryClientId !== clientId)) throw new PresentationRequestError('client_id in request object does not match the query parameter', 'invalid_client');
  return authenticate(raw, jws, clientId, trust, checks, undefined, insecureHosts);
}

/** The protocol identifiers of OpenID4VP over the Digital Credentials API (Appendix A.1) this wallet answers. */
export const DC_API_PROTOCOLS = ['openid4vp-v1-signed', 'openid4vp-v1-multisigned', 'openid4vp-v1-unsigned'] as const;

/** One request of a DC API call, with the verifier's Origin as the platform (browser / OS) reported it. */
export interface DcApiRequest {
  protocol: string;
  data: unknown;
  origin: string;
}

/**
 * The OpenID4VP request this wallet answers out of a DC API request JSON ({@code {requests: [{protocol, data}]}}, or the
 * older {@code {providers: [{protocol, request}]}}): the one the platform's matcher chose ({@code index}), else the first
 * whose protocol it supports, signed before unsigned.
 */
export function pickDcApiRequest(requestJson: string | Record<string, unknown>, origin: string, index?: number): DcApiRequest | undefined {
  const o = (typeof requestJson === 'string' ? JSON.parse(requestJson) : requestJson) as Record<string, unknown>;
  const list = ((o.requests ?? o.providers ?? (o.digital as Record<string, unknown> | undefined)?.requests ?? []) as Record<string, unknown>[])
    .map((r) => ({ protocol: String(r.protocol ?? ''), data: r.data ?? r.request, origin }));
  const chosen = index === undefined ? undefined : list[index];
  if (chosen && (DC_API_PROTOCOLS as readonly string[]).includes(chosen.protocol)) return chosen;
  for (const p of DC_API_PROTOCOLS) {
    const hit = list.find((r) => r.protocol === p);
    if (hit) return hit;
  }
  return undefined;
}

/**
 * OpenID4VP over the Digital Credentials API (Appendix A). The response is bound to {@code origin}, which the platform
 * authenticated; an unsigned request has no client_id (any is ignored, A.2), a signed one is authenticated like any
 * request object and MUST list the origin in expected_origins.
 */
export async function resolveDcApiRequest(input: DcApiRequest, trust: TrustClient): Promise<{ request: AuthorizationRequest; verifier: VerifierView }> {
  const { protocol, origin } = input;
  if (!origin) throw new PresentationRequestError('The platform did not report the verifier origin');
  const data = (typeof input.data === 'string' ? JSON.parse(input.data) : input.data) as Record<string, unknown> | undefined;
  if (!data || typeof data !== 'object') throw new PresentationRequestError('The DC API request has no data');
  const checks: VerifierView['checks'] = [{ label: 'Verifier origin', ok: true, detail: `${origin} (reported by the platform)` }];
  if (protocol === 'openid4vp-v1-unsigned') {
    const { client_id: _ignored, expected_origins: _alsoIgnored, ...raw } = data;
    return authenticate(raw, undefined, `origin:${origin}`, trust, checks, origin);
  }
  if (protocol === 'openid4vp-v1-multisigned') return resolveMultiSigned(data.request, origin, trust, checks);
  if (protocol !== 'openid4vp-v1-signed') throw new PresentationRequestError(`Unsupported DC API protocol ${protocol}`);
  if (typeof data.request !== 'string') throw new PresentationRequestError('A signed DC API request carries the request object in data.request');
  const jws = readRequestObject(data.request, checks);
  const raw = jws.payload as Record<string, unknown>;
  const clientId = String(raw.client_id ?? '');
  if (!clientId) throw new PresentationRequestError('A signed request must name its client_id', 'invalid_client');
  return authenticate(raw, jws, clientId, trust, checks, origin);
}

/**
 * A request signed for several client identifiers (A.3.2.2, JWS JSON Serialization): each signature's protected header
 * names its client_id. Every signature is checked and the wallet answers as the best client it can authenticate and does
 * not refuse: a TRUSTED one before an UNKNOWN one, and x509_hash (HAIP §5) before other prefixes. When it refuses every
 * one, the user sees the first refusal; when none can be answered, preferably an authenticated signer's error.
 */
async function resolveMultiSigned(request: unknown, origin: string, trust: TrustClient, checks: VerifierView['checks']): Promise<{ request: AuthorizationRequest; verifier: VerifierView }> {
  let json: { payload?: unknown; signatures?: { protected?: unknown; signature?: unknown }[] } | undefined;
  try { json = (typeof request === 'string' ? JSON.parse(request) : request) as typeof json; } catch { json = undefined; }
  if (typeof json?.payload !== 'string' || !Array.isArray(json.signatures) || !json.signatures.length) {
    throw new PresentationRequestError('A multi-signed DC API request carries a JWS JSON Serialization in data.request');
  }
  type Resolved = { request: AuthorizationRequest; verifier: VerifierView };
  const rank = (r: Resolved) => (r.verifier.trust.decision === 'TRUSTED' ? 2 : 0) + (r.request.prefix === 'x509_hash' ? 1 : 0);
  let best: Resolved | undefined;
  let refused: Resolved | undefined;
  let failure: unknown;
  for (const sig of json.signatures) {
    try {
      if (typeof sig.protected !== 'string' || typeof sig.signature !== 'string') throw new PresentationRequestError('A signature has no protected header');
      const own = [...checks];
      const jws = readRequestObject(`${sig.protected}.${json.payload}.${sig.signature}`, own);
      const clientId = String(jws.header.client_id ?? '');
      if (!clientId) throw new PresentationRequestError('Each signature of a multi-signed request names its client_id', 'invalid_client');
      own.push({ label: 'Multi-signed request', ok: true, detail: `answered as ${clientId} (${json.signatures.length} signatures)` });
      const r = await authenticate(jws.payload as Record<string, unknown>, jws, clientId, trust, own, origin);
      if (r.verifier.refusal) refused ??= r;
      else if (!best || rank(r) > rank(best)) best = r;
    } catch (e) {
      // An error from a signer that was authenticated (it may be reported) says more than another signer's bad signature.
      const reportable = (x: unknown) => x instanceof PresentationRequestError && !!x.reportTo;
      if (failure === undefined || (reportable(e) && !reportable(failure))) failure = e;
    }
  }
  if (best) return best;
  if (refused) return refused;
  throw failure;
}

type Jws = ReturnType<typeof decodeJws>;

/**
 * Decodes a request object and checks what does not depend on its signer: typ (§5: never processed without it, also
 * per signature of a multi-signed request), exp, nbf.
 */
function readRequestObject(jwt: string, checks: VerifierView['checks']): Jws {
  const jws = decodeJws(jwt);
  const raw = jws.payload as Record<string, unknown>;
  if (jws.header.typ !== 'oauth-authz-req+jwt') throw new PresentationRequestError(`Request object typ must be oauth-authz-req+jwt (got ${String(jws.header.typ)})`);
  checks.push({ label: 'Request object type', ok: true, detail: 'oauth-authz-req+jwt' });
  const now = Math.floor(Date.now() / 1000);
  if (typeof raw.exp === 'number' && raw.exp < now - SKEW_S) throw new PresentationRequestError(`Request object expired at ${new Date(raw.exp * 1000).toISOString()}`);
  if (typeof raw.nbf === 'number' && raw.nbf > now + SKEW_S) throw new PresentationRequestError('Request object is not yet valid');
  return jws;
}

/**
 * Authenticates the verifier per client identifier prefix, evaluates its trust and checks the request is well formed.
 * {@code origin} is set for the DC API, where the response goes back through the platform instead of to a URL.
 */
async function authenticate(raw: Record<string, unknown>, jws: Jws | undefined, clientId: string, trust: TrustClient, checks: VerifierView['checks'],
                            origin?: string, insecureHosts: readonly string[] = []): Promise<{ request: AuthorizationRequest; verifier: VerifierView }> {
  const dcApi = origin !== undefined;
  const header = jws?.header;
  const { prefix, value } = dcApi && !jws ? { prefix: 'origin', value: origin } : clientIdPrefix(clientId);
  const x5c = Array.isArray(header?.x5c) ? (header!.x5c as string[]) : undefined;
  const responseMode = String(raw.response_mode ?? (dcApi ? 'dc_api' : 'fragment'));
  // Over the DC API the response goes back through the platform: response_uri / redirect_uri mean nothing (A.2).
  const responseUri = dcApi ? undefined : raw.response_uri as string | undefined;
  // The presentation is posted there: never over plain http, whoever asks.
  if (responseUri !== undefined) {
    try { requireHttps(responseUri, 'response_uri', insecureHosts); } catch (e) { throw new PresentationRequestError((e as Error).message); }
  }

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
  } else if (prefix === 'redirect_uri' && !dcApi) {
    if (jws) throw new PresentationRequestError('redirect_uri client identifiers must not use signed requests');
    if (value !== (responseUri ?? raw.redirect_uri)) throw new PresentationRequestError('redirect_uri client_id does not match the response URI', 'invalid_client');
    checks.push({ label: 'Request signature', ok: false, detail: 'Unsigned request (redirect_uri client identifier)' });
  } else if (prefix === 'origin' && dcApi && !jws) {
    checks.push({ label: 'Request signature', ok: false, detail: 'Unsigned request: the verifier is known only by its origin' });
  } else {
    throw new PresentationRequestError(`Unsupported client identifier prefix ${prefix}${dcApi ? ' over the DC API' : ''}`, 'invalid_client');
  }
  // Verifier trust. Errors may go back only to a verifier that signed the request and is not refused.
  // Only the key the request signature was verified with: the x5c leaf for x509_*, the DID key for decentralized_identifier.
  // An unsigned DC API request is judged by its origin (origin:<origin>, matched against the registry's URL
  // identifiers), which the platform authenticated (Web PKI / app signature).
  const x509 = prefix === 'x509_san_dns' || prefix === 'x509_hash';
  const trustDecision = await trust.evaluateVerifier({ clientId, x5c: x509 ? x5c : undefined,
    kid: prefix === 'decentralized_identifier' ? header?.kid as string | undefined : undefined, responseUri });
  const refusal = verifierRefusal(prefix, trustDecision);
  // DC API: errors go back through the platform, only after the user saw them (§15.9.2), to an origin the platform vouched for.
  const reportTo = refusal ? undefined
    : dcApi ? { dcApi: true }
      : jws && responseUri && responseMode.startsWith('direct_post') ? { responseUri, state: raw.state as string | undefined } : undefined;
  // Request well-formedness.
  const fail = (message: string, code = 'invalid_request') => new PresentationRequestError(message, code, reportTo);
  if (dcApi && jws) {
    // A.2: a signed request lists the origins it was made for, so it cannot be replayed from another site.
    const expected = raw.expected_origins;
    if (!Array.isArray(expected) || !expected.length) throw fail('A signed DC API request must list expected_origins');
    if (!expected.includes(origin)) throw fail(`This request was made for ${expected.join(', ')}, not ${origin}`);
    checks.push({ label: 'Expected origins', ok: true, detail: `${origin} is listed` });
  }
  if (raw.response_type !== 'vp_token') throw fail(`Unsupported response_type ${String(raw.response_type)}`, 'unsupported_response_type');
  if (typeof raw.nonce !== 'string' || !raw.nonce) throw fail('nonce is required');
  if (raw.presentation_definition) throw fail('presentation_definition is not part of OpenID4VP 1.0; use dcql_query');
  if (!raw.dcql_query) throw fail('dcql_query is required');
  const malformed = dcqlProblem(raw.dcql_query);
  if (malformed) throw fail(`dcql_query is not valid: ${malformed}`);
  if (raw.dcql_query && raw.scope) throw fail('dcql_query and scope must not both be present');
  const modes = dcApi ? ['dc_api', 'dc_api.jwt'] : ['direct_post', 'direct_post.jwt'];
  if (!modes.includes(responseMode)) throw fail(`Unsupported response_mode ${responseMode}${dcApi ? ' over the DC API' : ''}`);
  if (responseMode.startsWith('direct_post') && !responseUri) throw new PresentationRequestError('response_uri is required for direct_post');
  // §8.2: redirect_uri with direct_post MUST be answered with invalid_request.
  if (responseUri && raw.redirect_uri) throw fail('redirect_uri must not be present with response_uri');
  // §8.4: a wallet that does not support transaction_data MUST return an error.
  if (raw.transaction_data) throw fail('transaction_data is not supported by this wallet', 'invalid_transaction_data');
  if (responseMode.endsWith('.jwt') && !encryptionKey((raw.client_metadata ?? {}) as Record<string, unknown>)) {
    throw fail(`client_metadata.jwks has no P-256 key with alg ECDH-ES for ${responseMode}`);
  }
  const encs = ((raw.client_metadata ?? {}) as Record<string, unknown>).encrypted_response_enc_values_supported;
  if (responseMode.endsWith('.jwt') && Array.isArray(encs) && !encs.some((e) => e === 'A128GCM' || e === 'A256GCM')) {
    throw fail(`The verifier accepts none of the response encryption algorithms this wallet supports (A128GCM, A256GCM): ${encs.join(', ')}`);
  }

  const md = (raw.client_metadata ?? {}) as Record<string, unknown>;
  const request: AuthorizationRequest = {
    clientId, prefix, responseType: 'vp_token', responseMode, responseUri, redirectUri: dcApi ? undefined : raw.redirect_uri as string | undefined,
    nonce: String(raw.nonce), state: dcApi ? undefined : raw.state as string | undefined, dcqlQuery: raw.dcql_query as DcqlQuery, clientMetadata: md,
    signed: !!jws, x5c, origin, raw,
  };
  return { request, verifier: { clientId, prefix, origin, trust: trustDecision, checks, refusal,
    // The registry's name for a recognised verifier; otherwise the request's own client_name, marked as self-declared.
    ...verifierName(trustDecision.entity?.display?.[0]?.name, md.client_name),
    ...(trustDecision.decision === 'TRUSTED' ? { logoUri: trustDecision.entity?.display?.[0]?.logoUri ?? (typeof md.logo_uri === 'string' ? md.logo_uri : undefined) } : {}) } };
}

function verifierName(registered: string | undefined, declared: unknown): Pick<VerifierView, 'name' | 'nameSelfDeclared'> {
  if (registered) return { name: registered };
  return typeof declared === 'string' && declared ? { name: declared, nameSelfDeclared: true } : {};
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
