/**
 * OpenID4VCI 1.0 wallet client with the HAIP 1.0 feature set:
 *  - pre-authorized code (+ tx_code) and authorization code flows; PKCE S256; PAR when offered; RFC 9207 iss check
 *  - DPoP-bound tokens with nonce handling at AS and credential issuer
 *  - wallet attestation (attest_jwt_client_auth) and key attestation in jwt proofs
 *  - nonce endpoint, credential_identifier vs credential_configuration_id, deferred issuance, notification
 * Issuer metadata and trust come from the TrustClient (trust service, with standards-based fallback).
 */
import { bytes, base58Encode, writeVarint, MULTICODEC, type IssuerMetadataResult, type Jwk, type TrustClient, type TrustDecision } from '@vctrust/trust-client';
import { p256 } from '@noble/curves/nist.js';
import { nowSeconds, randomId, signJwt } from '../crypto/jwt.js';
import type { KeyStore, SigningKey } from '../crypto/keys.js';
import { Dpop } from '../oauth/dpop.js';
import { createPkce, type Pkce } from '../oauth/pkce.js';
import type { WalletAttester } from '../oauth/attestation.js';
import { PRE_AUTH, resolveCredentialOffer, type CredentialOffer, type TxCode } from './offer.js';
import { verifyCredential, type VerificationReport } from '../verify/index.js';

export interface IssuerClientRegistration {
  /** Pre-registered client_id at this issuer's AS (when not using wallet attestation). */
  clientId: string;
  redirectUri?: string;
  /** Token endpoint override, e.g. a wallet-backend token proxy holding the client's credentials. */
  tokenEndpoint?: string;
  extraAuthorizeParams?: Record<string, string>;
  /** Defaults to true when the AS offers PAR. */
  usePar?: boolean;
}

export interface Oid4vciOptions {
  trust: TrustClient;
  keyStore: KeyStore;
  fetch?: typeof fetch;
  attester?: WalletAttester;
  redirectUri: string;
  /** client_id of a public client when no attestation / registration applies. */
  clientId?: string;
  registrations?: Record<string, IssuerClientRegistration>;
  dpop?: 'auto' | 'never';
  /** Send wallet attestation: when the AS asks for it ('auto'), always, or never. */
  walletAttestation?: 'auto' | 'always' | 'never';
  keyAttestation?: 'auto' | 'always' | 'never';
  /** Max seconds to wait for deferred credentials before returning them as pending. */
  deferredWaitSeconds?: number;
  verify?: boolean;
}

export interface IssuedCredential {
  id: string;
  format: string;
  configurationId: string;
  credential: unknown;
  credentialIssuer: string;
  holderKeyId: string;
  holderJwk: Jwk;
  holderDid?: string;
  issuedAt: string;
  display?: Record<string, unknown>;
  claimMetadata?: unknown[];
  report?: VerificationReport;
  pending?: { transactionId: string; interval: number };
}

export class IssuanceError extends Error {
  constructor(message: string, readonly code?: string, readonly status?: number) {
    super(message);
    this.name = 'IssuanceError';
  }
}

type TokenResponse = { access_token: string; token_type: string; c_nonce?: string; refresh_token?: string;
  authorization_details?: Array<{ type: string; credential_configuration_id?: string; credential_identifiers?: string[] }> };

export class Oid4vciClient {
  private readonly f: typeof fetch;

  constructor(readonly opts: Oid4vciOptions) {
    this.f = opts.fetch ?? fetch;
  }

  /** Resolves an offer, fetches issuer metadata (through the trust service) and returns a session. */
  async startFromOffer(offerInput: string): Promise<IssuanceSession> {
    const offer = await resolveCredentialOffer(offerInput, this.f);
    const metadata = await this.opts.trust.getIssuerMetadata(offer.credential_issuer);
    return new IssuanceSession(this, offer, metadata);
  }

  /** Wallet-initiated issuance (no offer): authorization code flow for the given configurations. */
  async startWalletInitiated(credentialIssuer: string, configurationIds: string[]): Promise<IssuanceSession> {
    const metadata = await this.opts.trust.getIssuerMetadata(credentialIssuer);
    return new IssuanceSession(this, { credential_issuer: metadata.credentialIssuer, credential_configuration_ids: configurationIds,
      grants: { authorization_code: {} } }, metadata);
  }

  get fetchFn(): typeof fetch {
    return this.f;
  }
}

export class IssuanceSession {
  readonly configurations: Array<{ id: string; config: Record<string, unknown> }>;
  readonly grant: 'pre-authorized_code' | 'authorization_code';
  readonly txCode?: TxCode;
  private readonly as: string;
  private readonly asMd: Record<string, unknown>;
  private readonly im: Record<string, unknown>;
  private readonly reg?: IssuerClientRegistration;
  private dpop?: Dpop;
  private pkce?: Pkce;
  private state?: string;
  private redirectUri: string;

  constructor(private readonly client: Oid4vciClient, readonly offer: CredentialOffer, readonly metadata: IssuerMetadataResult) {
    this.im = metadata.credentialIssuerMetadata;
    const supported = (this.im.credential_configurations_supported ?? {}) as Record<string, Record<string, unknown>>;
    this.configurations = offer.credential_configuration_ids.map((id) => {
      const config = supported[id];
      if (!config) throw new IssuanceError(`Offered configuration ${id} is not in the issuer metadata`, 'unknown_credential_configuration');
      return { id, config };
    });
    const pre = offer.grants?.[PRE_AUTH];
    this.grant = pre ? 'pre-authorized_code' : 'authorization_code';
    this.txCode = pre?.tx_code;
    const servers = Object.keys(metadata.authorizationServers);
    const wanted = pre?.authorization_server ?? offer.grants?.authorization_code?.authorization_server;
    this.as = wanted && metadata.authorizationServers[wanted] ? wanted : servers[0] ?? metadata.credentialIssuer;
    this.asMd = metadata.authorizationServers[this.as] ?? {};
    this.reg = client.opts.registrations?.[metadata.credentialIssuer];
    this.redirectUri = this.reg?.redirectUri ?? client.opts.redirectUri;
  }

  get credentialIssuer(): string {
    return this.metadata.credentialIssuer;
  }

  get issuerTrust(): TrustDecision {
    return this.metadata.trust;
  }

  /** Issuer display (OpenID4VCI §12.2.4 display) */
  get issuerDisplay(): Record<string, unknown> | undefined {
    return (this.im.display as Record<string, unknown>[] | undefined)?.[0];
  }

  private get usesDpop(): boolean {
    return this.client.opts.dpop !== 'never' && Array.isArray(this.asMd.dpop_signing_alg_values_supported)
      && (this.asMd.dpop_signing_alg_values_supported as string[]).includes('ES256');
  }

  private get clientId(): string | undefined {
    return this.reg?.clientId ?? this.client.opts.attester?.clientId ?? this.client.opts.clientId;
  }

  private attestationWanted(): boolean {
    const mode = this.client.opts.walletAttestation ?? 'auto';
    if (!this.client.opts.attester || mode === 'never' || this.reg) return false;
    if (mode === 'always') return true;
    const methods = (this.asMd.token_endpoint_auth_methods_supported as string[] | undefined) ?? [];
    return methods.includes('attest_jwt_client_auth') || this.grant === 'authorization_code';
  }

  private async ensureDpop(): Promise<Dpop | undefined> {
    if (!this.usesDpop) return undefined;
    if (!this.dpop) this.dpop = new Dpop(await this.client.opts.keyStore.create());
    return this.dpop;
  }

  private async attestationHeaders(): Promise<Record<string, string>> {
    const attester = this.client.opts.attester!;
    let challenge: string | undefined;
    const ce = this.asMd.challenge_endpoint as string | undefined;
    if (ce) {
      const r = await this.client.fetchFn(ce, { method: 'POST' });
      if (r.ok) challenge = ((await r.json()) as { attestation_challenge?: string }).attestation_challenge;
    }
    return attester.headers(String(this.asMd.issuer ?? this.as), challenge);
  }

  /** POST form to an AS endpoint with optional attestation and DPoP; retries once with attestation on invalid_client. */
  private async asPost(url: string, form: Record<string, string>, attest: boolean): Promise<Response> {
    const send = async (withAttestation: boolean) => {
      const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
      const body = { ...form };
      if (withAttestation) {
        Object.assign(headers, await this.attestationHeaders());
        body.client_id = this.client.opts.attester!.clientId;
      }
      const init = { method: 'POST', headers, body: new URLSearchParams(body).toString() };
      const dpop = await this.ensureDpop();
      return dpop ? dpop.fetch(this.client.fetchFn, url, init) : this.client.fetchFn(url, init);
    };
    const r = await send(attest);
    // Servers signal missing client authentication with invalid_client as 400 or 401.
    if (!attest && (r.status === 401 || r.status === 400) && this.client.opts.attester && this.client.opts.walletAttestation !== 'never') {
      const err = (await r.clone().json().catch(() => ({}))) as { error?: string };
      if (err.error === 'invalid_client') return send(true);
    }
    return r;
  }

  // ---- pre-authorized code -------------------------------------------------------------------------

  async acceptPreAuthorized(txCode?: string): Promise<IssuedCredential[]> {
    const pre = this.offer.grants?.[PRE_AUTH];
    if (!pre) throw new IssuanceError('Offer has no pre-authorized code grant');
    if (this.txCode && !txCode) throw new IssuanceError('This offer requires a transaction code', 'tx_code_required');
    const form: Record<string, string> = { grant_type: PRE_AUTH, 'pre-authorized_code': pre['pre-authorized_code'] };
    if (this.txCode) form.tx_code = txCode!;
    const anonymousAllowed = this.asMd['pre-authorized_grant_anonymous_access_supported'] === true;
    const attest = this.attestationWanted() && (!anonymousAllowed || this.client.opts.walletAttestation === 'always');
    if (!anonymousAllowed && this.clientId && !attest) form.client_id = this.clientId;
    const token = await this.token(form, attest);
    return this.issueAll(token, !attest && anonymousAllowed);
  }

  // ---- authorization code -------------------------------------------------------------------------

  /** Builds the authorization request (via PAR when available). Open the returned URL in a browser. */
  async beginAuthorization(): Promise<{ authorizationUrl: string; state: string; redirectUri: string }> {
    const authEndpoint = this.asMd.authorization_endpoint as string | undefined;
    if (!authEndpoint) throw new IssuanceError('Authorization server has no authorization_endpoint');
    const clientId = this.attestationWanted() ? this.client.opts.attester!.clientId : this.clientId;
    if (!clientId) throw new IssuanceError('No client_id: configure wallet attestation, a registration or clientId');
    this.pkce = createPkce();
    this.state = randomId();
    const scopes = this.configurations.map((c) => c.config.scope).filter((s): s is string => typeof s === 'string');
    const params: Record<string, string> = {
      response_type: 'code', client_id: clientId, redirect_uri: this.redirectUri, state: this.state,
      code_challenge: this.pkce.challenge, code_challenge_method: 'S256', ...(this.reg?.extraAuthorizeParams ?? {}),
    };
    if (scopes.length === this.configurations.length) params.scope = [...new Set(scopes)].join(' ');
    else params.authorization_details = JSON.stringify(this.configurations.map((c) => ({ type: 'openid_credential', credential_configuration_id: c.id })));
    const issuerState = this.offer.grants?.authorization_code?.issuer_state;
    if (issuerState) params.issuer_state = issuerState;
    const par = this.asMd.pushed_authorization_request_endpoint as string | undefined;
    if (par && this.reg?.usePar !== false) {
      const r = await this.asPost(par, params, this.attestationWanted());
      if (!r.ok) {
        const err = await this.error('PAR', r);
        // Some issuers (e.g. Credo-based playgrounds) only authorize sessions they started with an offer.
        if (err.code === 'access_denied' && !issuerState) {
          throw new IssuanceError(`${err.message}. The issuer refused wallet-initiated issuance; start from a credential offer issued by it instead.`, err.code, err.status);
        }
        throw err;
      }
      const { request_uri: requestUri } = (await r.json()) as { request_uri: string };
      return { authorizationUrl: `${authEndpoint}?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`, state: this.state, redirectUri: this.redirectUri };
    }
    if (this.asMd.require_pushed_authorization_requests === true) throw new IssuanceError('AS requires PAR but advertises no endpoint');
    return { authorizationUrl: `${authEndpoint}?${new URLSearchParams(params)}`, state: this.state, redirectUri: this.redirectUri };
  }

  /** Completes the flow with the redirect URL the browser landed on. */
  async completeAuthorization(callbackUrl: string): Promise<IssuedCredential[]> {
    const q = new URLSearchParams(callbackUrl.includes('?') ? callbackUrl.slice(callbackUrl.indexOf('?') + 1).split('#')[0] : '');
    if (q.get('error')) throw new IssuanceError(`Authorization failed: ${q.get('error')} ${q.get('error_description') ?? ''}`, q.get('error')!);
    if (!this.state || q.get('state') !== this.state) throw new IssuanceError('state mismatch in authorization response', 'invalid_state');
    const iss = q.get('iss');
    if (iss && iss !== this.asMd.issuer) throw new IssuanceError(`iss ${iss} does not match the authorization server`, 'invalid_iss');
    if (!iss && this.asMd.authorization_response_iss_parameter_supported === true) throw new IssuanceError('Missing iss in authorization response (RFC 9207)', 'invalid_iss');
    const code = q.get('code');
    if (!code) throw new IssuanceError('No authorization code in callback');
    const form: Record<string, string> = { grant_type: 'authorization_code', code, code_verifier: this.pkce!.verifier, redirect_uri: this.redirectUri };
    if (!this.attestationWanted() && this.clientId) form.client_id = this.clientId;
    return this.issueAll(await this.token(form, this.attestationWanted()), false);
  }

  // ---- token & credential --------------------------------------------------------------------------

  private async token(form: Record<string, string>, attest: boolean): Promise<TokenResponse> {
    const endpoint = this.reg?.tokenEndpoint ?? (this.asMd.token_endpoint as string | undefined);
    if (!endpoint) throw new IssuanceError('Authorization server has no token_endpoint');
    const r = await this.asPost(endpoint, form, attest);
    if (!r.ok) throw await this.error('Token request', r);
    const t = (await r.json()) as TokenResponse;
    if (this.usesDpop && t.token_type?.toLowerCase() !== 'dpop') throw new IssuanceError(`Expected a DPoP-bound token, got ${t.token_type}`);
    return t;
  }

  private async nonce(token: TokenResponse): Promise<string | undefined> {
    const ne = this.im.nonce_endpoint as string | undefined;
    if (!ne) return token.c_nonce;
    const r = await this.client.fetchFn(ne, { method: 'POST', headers: { Accept: 'application/json' } });
    if (!r.ok) throw await this.error('Nonce request', r);
    const dpopNonce = r.headers.get('DPoP-Nonce');
    if (dpopNonce && this.dpop) this.dpop.setNonce(String(this.im.credential_endpoint), dpopNonce);
    return ((await r.json()) as { c_nonce: string }).c_nonce;
  }

  private async issueAll(token: TokenResponse, anonymous: boolean): Promise<IssuedCredential[]> {
    const out: IssuedCredential[] = [];
    for (const c of this.configurations) out.push(await this.issueOne(c.id, c.config, token, anonymous));
    return out;
  }

  private async issueOne(configId: string, config: Record<string, unknown>, token: TokenResponse, anonymous: boolean): Promise<IssuedCredential> {
    const opts = this.client.opts;
    const holder = await opts.keyStore.create();
    const binding = (config.cryptographic_binding_methods_supported as string[] | undefined) ?? ['jwk'];
    const holderDid = bindingDid(holder.publicJwk, binding);
    const identifiers = token.authorization_details?.find((d) => d.credential_configuration_id === configId)?.credential_identifiers;
    let nonce = await this.nonce(token);
    let response: Response | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      const proof = await this.proof(holder, config, nonce, anonymous, holderDid);
      const body: Record<string, unknown> = identifiers?.length
        ? { credential_identifier: identifiers[0], proofs: { jwt: [proof] } }
        : { credential_configuration_id: configId, proofs: { jwt: [proof] } };
      response = await this.credentialPost(String(this.im.credential_endpoint), body, token);
      if (response.status === 400 && attempt === 0) {
        const err = (await response.clone().json().catch(() => ({}))) as { error?: string };
        if (err.error === 'invalid_nonce') { nonce = await this.nonce(token); continue; }
      }
      break;
    }
    if (!response!.ok) throw await this.error(`Credential request (${configId})`, response!);
    let payload = (await response!.json()) as { credentials?: Array<{ credential: unknown }>; credential?: unknown; transaction_id?: string;
      interval?: number; notification_id?: string };
    if (response!.status === 202 || (payload.transaction_id && !payload.credentials)) {
      payload = await this.waitDeferred(payload.transaction_id!, payload.interval ?? 5, token) ?? payload;
    }
    const meta = (config.credential_metadata ?? {}) as Record<string, unknown>;
    const issued: IssuedCredential = {
      id: randomId(), format: String(config.format), configurationId: configId, credential: payload.credentials?.[0]?.credential ?? payload.credential,
      credentialIssuer: this.metadata.credentialIssuer, holderKeyId: holder.id, holderJwk: holder.publicJwk, holderDid, issuedAt: new Date().toISOString(),
      display: ((meta.display ?? config.display) as Record<string, unknown>[] | undefined)?.[0],
      claimMetadata: (meta.claims ?? config.claims) as unknown[] | undefined,
    };
    if (!issued.credential && payload.transaction_id) {
      issued.pending = { transactionId: payload.transaction_id, interval: payload.interval ?? 5 };
      return issued;
    }
    if (opts.verify !== false) {
      issued.report = await verifyCredential(issued.format, issued.credential, { trust: opts.trust, fetch: this.client.fetchFn,
        holderJwk: holder.publicJwk, holderDid, credentialIssuer: issued.credentialIssuer });
      if (!payload.credentials && payload.credential) issued.report.checks.unshift({ id: 'oid4vci.response', label: 'Credential response',
        status: 'warn', detail: 'Pre-1.0 response shape (credential instead of credentials[])' });
    }
    const notify = this.im.notification_endpoint as string | undefined;
    if (notify && payload.notification_id) {
      await this.credentialPost(notify, { notification_id: payload.notification_id,
        event: issued.report && !issued.report.valid ? 'credential_failure' : 'credential_accepted' }, token).catch(() => undefined);
    }
    return issued;
  }

  private async proof(holder: SigningKey, config: Record<string, unknown>, nonce: string | undefined, anonymous: boolean, holderDid?: string): Promise<string> {
    const header: Record<string, unknown> = { typ: 'openid4vci-proof+jwt' };
    if (holderDid) header.kid = holderDid.startsWith('did:jwk:') ? `${holderDid}#0` : `${holderDid}#${holderDid.slice('did:key:'.length)}`;
    else header.jwk = holder.publicJwk;
    const jwtProof = (config.proof_types_supported as Record<string, Record<string, unknown>> | undefined)?.jwt;
    const ka = this.client.opts.keyAttestation ?? 'auto';
    const required = jwtProof?.key_attestations_required as { key_storage?: string[]; user_authentication?: string[] } | undefined;
    if (required && !this.client.opts.attester) throw new IssuanceError('Issuer requires a key attestation but no wallet provider is configured', 'key_attestation_required');
    if (required && this.client.opts.attester) {
      const caps = this.client.opts.attester.capabilities;
      const missing = (want: string[] | undefined, have: string[]) => want?.length && !want.some((w) => have.includes(w));
      if (missing(required.key_storage, caps.keyStorage) || missing(required.user_authentication, caps.userAuthentication)) {
        throw new IssuanceError(`Issuer requires key storage ${JSON.stringify(required.key_storage ?? [])} / user authentication `
          + `${JSON.stringify(required.user_authentication ?? [])}; this wallet attests ${JSON.stringify(caps)}`, 'insufficient_key_protection');
      }
    }
    if (this.client.opts.attester && ka !== 'never' && (ka === 'always' || required)) {
      header.key_attestation = await this.client.opts.attester.keyAttestation([holder.publicJwk], nonce);
    }
    const payload: Record<string, unknown> = { aud: this.metadata.credentialIssuer, iat: nowSeconds() };
    if (nonce) payload.nonce = nonce;
    const clientId = this.attestationWanted() ? this.client.opts.attester!.clientId : this.clientId;
    if (!anonymous && clientId) payload.iss = clientId;
    return signJwt(header, payload, holder);
  }

  private async credentialPost(url: string, body: unknown, token: TokenResponse): Promise<Response> {
    const init = { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) };
    if (token.token_type?.toLowerCase() === 'dpop' && this.dpop) return this.dpop.fetch(this.client.fetchFn, url, init, token.access_token);
    return this.client.fetchFn(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token.access_token}` } });
  }

  private async waitDeferred(transactionId: string, interval: number, token: TokenResponse) {
    const endpoint = this.im.deferred_credential_endpoint as string | undefined;
    if (!endpoint) return undefined;
    const deadline = Date.now() + (this.client.opts.deferredWaitSeconds ?? 30) * 1000;
    let wait = Math.max(1, interval);
    while (Date.now() + wait * 1000 <= deadline) {
      await new Promise((r) => setTimeout(r, wait * 1000));
      const r = await this.credentialPost(endpoint, { transaction_id: transactionId }, token);
      if (r.status === 200) return (await r.json()) as { credentials?: Array<{ credential: unknown }>; notification_id?: string };
      if (r.status === 202) { wait = ((await r.json()) as { interval?: number }).interval ?? wait; continue; }
      throw await this.error('Deferred credential request', r);
    }
    return undefined;
  }

  private async error(what: string, r: Response): Promise<IssuanceError> {
    const text = await r.text().catch(() => '');
    let code: string | undefined;
    let detail = text.slice(0, 300);
    try {
      const j = JSON.parse(text) as { error?: string; error_description?: string };
      code = j.error;
      detail = `${j.error ?? ''} ${j.error_description ?? ''}`.trim() || detail;
    } catch { /* not JSON */ }
    return new IssuanceError(`${what} failed (HTTP ${r.status}): ${detail}`, code, r.status);
  }
}

/** DID for binding methods that need one (did:jwk preferred, then did:key); undefined means use a jwk header. */
export function bindingDid(jwk: Jwk, methods: string[]): string | undefined {
  if (methods.includes('jwk') || methods.includes('cose_key')) return undefined;
  if (methods.includes('did:jwk')) {
    const { kty, crv, x, y } = jwk;
    return `did:jwk:${bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify({ crv, kty, x, y })))}`;
  }
  if (methods.includes('did:key')) {
    const point = bytes.concatBytes(Uint8Array.of(4), bytes.base64UrlDecode(jwk.x!), bytes.base64UrlDecode(jwk.y!));
    const compressed = p256.Point.fromBytes(point).toBytes(true);
    return `did:key:z${base58Encode(writeVarint(MULTICODEC.p256, compressed))}`;
  }
  return undefined;
}
