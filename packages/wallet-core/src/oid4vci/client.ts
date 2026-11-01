/**
 * OpenID4VCI 1.0 wallet client with the HAIP 1.0 feature set:
 *  - pre-authorized code (+ tx_code) and authorization code flows; PKCE S256; PAR when offered; RFC 9207 iss check
 *  - DPoP-bound tokens with nonce handling at AS and credential issuer
 *  - wallet attestation (attest_jwt_client_auth) and key attestation in jwt proofs
 *  - nonce endpoint, credential_identifier vs credential_configuration_id, deferred issuance, notification
 *  - credential request / response encryption (ECDH-ES P-256, A128GCM / A256GCM) when the issuer requires or offers it
 *  - credentials that fail verification are refused (credential_failure); credential_accepted only once stored
 * Issuer metadata and trust come from the TrustClient (trust service, with standards-based fallback).
 */
import { bytes, base58Encode, writeVarint, MULTICODEC, type IssuerMetadataResult, type Jwk, type TrustClient, type TrustDecision } from '@vctrust/trust-client';
import { p256 } from '@noble/curves/nist.js';
import { nowSeconds, randomId, signJwt } from '../crypto/jwt.js';
import { decryptJwe, encryptJwe, type JweEnc } from '../crypto/jwe.js';
import { SoftwareKey, type KeyStore, type SigningKey } from '../crypto/keys.js';
import { Dpop } from '../oauth/dpop.js';
import { createPkce, type Pkce } from '../oauth/pkce.js';
import type { WalletAttester } from '../oauth/attestation.js';
import { PRE_AUTH, resolveCredentialOffer, type CredentialOffer, type TxCode } from './offer.js';
import { holderBinding, verifyCredential, type VerificationReport } from '../verify/index.js';
import { didPublicKey } from '../verify/sdjwt.js';

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
  /**
   * Refuse a credential that fails verification, or an SD-JWT VC whose x5c issuer certificate does not chain to a
   * trusted anchor (SD-JWT VC §3.5: the credential MUST be rejected). Default true.
   */
  rejectInvalid?: boolean;
  /** Credential request / response encryption: only when the issuer requires it (default) or whenever it offers it. */
  encryption?: 'required' | 'preferred';
  /**
   * Instances to request of each credential when the issuer supports batch issuance (OID4VCI §8.2,
   * batch_credential_issuance; HAIP §4: in one request, not consecutive ones). Each is bound to its own key, so
   * presenting a different instance to every verifier keeps them from linking the presentations (OID4VCI §15.4).
   * Capped at the issuer's batch_size. Default 1.
   */
  batchSize?: number;
}

/** OID4VCI §11 notification events. */
export type NotificationEvent = 'credential_accepted' | 'credential_failure' | 'credential_deleted';

/** One copy of a credential and the holder key it is bound to. */
export interface CredentialInstance {
  credential: unknown;
  holderKeyId: string;
  holderJwk: Jwk;
  holderDid?: string;
  report?: VerificationReport;
  /** times this instance has been presented */
  presentations?: number;
}

/** A credential; with batch issuance, the first of its instances (the others are in {@link instances}). */
export interface IssuedCredential extends CredentialInstance {
  id: string;
  format: string;
  configurationId: string;
  credentialIssuer: string;
  issuedAt: string;
  display?: Record<string, unknown>;
  claimMetadata?: unknown[];
  /**
   * Deferred issuance still running (OID4VCI §9), with what {@link Oid4vciClient.retrieveDeferred} needs to ask again:
   * the access token (DPoP-bound when dpopKeyId is set) and the holder keys of the requested instances.
   */
  pending?: { transactionId: string; interval: number; accessToken?: string; tokenType?: string; refreshToken?: string; dpopKeyId?: string;
    holderKeyIds?: string[];
    /** how the token request authenticated, repeated for the refresh: wallet attestation, a client_id, or anonymously */
    tokenAuth?: { attested: boolean; clientId?: string } };
  /** Further instances of the same credential from a batch, each bound to its own key. */
  instances?: CredentialInstance[];
  /**
   * Notifies the issuer (OID4VCI §11) — {@link Wallet.store} sends credential_accepted, {@link Wallet.discard}
   * credential_deleted. Not enumerable, so it is never persisted.
   */
  notify?: (event: NotificationEvent, description?: string) => Promise<void>;
}

/** A freshly created holder key and the DID it is bound with, if the configuration binds to a DID. */
interface Holder {
  key: SigningKey;
  did?: string;
}

export class IssuanceError extends Error {
  /** credentials of the same offer issued before this failure; store or discard them */
  issued: IssuedCredential[] = [];
  /** a pending credential whose tokens were refreshed before this failure; store it so the new refresh token is kept */
  updatedPending?: IssuedCredential;

  constructor(message: string, readonly code?: string, readonly status?: number, readonly report?: VerificationReport) {
    super(message);
    this.name = 'IssuanceError';
  }
}

interface EncryptionPlan {
  request?: { jwk: Jwk; enc: JweEnc };
  response?: { enc: JweEnc };
}

/** A credential (or deferred) request body, sealed for the issuer when encryption applies. */
interface SealedRequest {
  body: string;
  contentType: string;
  responseKey?: SoftwareKey;
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

  /**
   * Asks the deferred credential endpoint again for a credential stored as pending (OID4VCI §9). Returns it still
   * pending while the issuer is not done; the issued credential keeps the pending one's id.
   */
  async retrieveDeferred(pending: IssuedCredential): Promise<IssuedCredential> {
    const metadata = await this.opts.trust.getIssuerMetadata(pending.credentialIssuer);
    return new IssuanceSession(this, { credential_issuer: metadata.credentialIssuer, credential_configuration_ids: [pending.configurationId],
      grants: { authorization_code: {} } }, metadata).retrieveDeferred(pending);
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
  /** OAuth-Client-Attestation-Challenge from the last AS response, for the next attestation PoP */
  private attestationChallenge?: string;
  /** how the last token request authenticated (a refresh repeats it) */
  private tokenAuth?: { attested: boolean; clientId?: string };

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

  /**
   * Attestation headers. The PoP carries a challenge when the AS issues them: the one it last returned in
   * OAuth-Client-Attestation-Challenge, else a fresh one from its challenge endpoint (which must then succeed).
   */
  private async attestationHeaders(): Promise<Record<string, string>> {
    const attester = this.client.opts.attester!;
    let challenge = this.attestationChallenge;
    this.attestationChallenge = undefined;
    const ce = this.asMd.challenge_endpoint as string | undefined;
    if (!challenge && ce) {
      const r = await this.client.fetchFn(ce, { method: 'POST', headers: { Accept: 'application/json' } });
      if (!r.ok) throw await this.error('Attestation challenge request', r);
      challenge = ((await r.json()) as { attestation_challenge?: string }).attestation_challenge;
      if (!challenge) throw new IssuanceError('The challenge endpoint returned no attestation_challenge', 'invalid_challenge');
    }
    return attester.headers(String(this.asMd.issuer ?? this.as), challenge);
  }

  /**
   * POST form to an AS endpoint with optional attestation and DPoP. Retries once: with attestation on invalid_client,
   * with the AS's new challenge on use_attestation_challenge, with a fresh attestation on use_fresh_attestation.
   */
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
      const r = dpop ? await dpop.fetch(this.client.fetchFn, url, init) : await this.client.fetchFn(url, init);
      const challenge = r.headers.get('OAuth-Client-Attestation-Challenge');
      if (challenge) this.attestationChallenge = challenge;
      return r;
    };
    const r = await send(attest);
    if (r.status !== 400 && r.status !== 401) return r;
    const err = (await r.clone().json().catch(() => ({}))) as { error?: string };
    // Servers signal missing client authentication with invalid_client as 400 or 401.
    if (!attest && err.error === 'invalid_client' && this.client.opts.attester && this.client.opts.walletAttestation !== 'never') return send(true);
    if (attest && (err.error === 'use_attestation_challenge' || err.error === 'use_fresh_attestation')) return send(true);
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
    // HAIP 4.4.1: authenticate with the wallet attestation wherever the AS supports it, even if anonymous access is allowed.
    const supportsAttestation = ((this.asMd.token_endpoint_auth_methods_supported as string[] | undefined) ?? []).includes('attest_jwt_client_auth');
    const attest = this.attestationWanted() && (!anonymousAllowed || supportsAttestation || this.client.opts.walletAttestation === 'always');
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
    else {
      // OID4VCI §5.1.1: with a separate authorization server, locations names the Credential Issuer.
      const locations = Array.isArray(this.im.authorization_servers) ? { locations: [this.metadata.credentialIssuer] } : {};
      params.authorization_details = JSON.stringify(this.configurations.map((c) => ({ type: 'openid_credential', credential_configuration_id: c.id, ...locations })));
    }
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
    if (form.grant_type !== 'refresh_token') this.tokenAuth = { attested: attest, ...(form.client_id ? { clientId: form.client_id } : {}) };
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
    for (const c of this.configurations) {
      try {
        out.push(await this.issueOne(c.id, c.config, token, anonymous));
      } catch (e) {
        // Credentials already issued for this offer travel with the error, so the caller can still store or discard them.
        if (e instanceof IssuanceError) e.issued = out;
        throw e;
      }
    }
    return out;
  }

  /** Instances to request per credential: the wallet's wish, capped at the issuer's batch_size (1 without batch support). */
  private batchSize(): number {
    const max = (this.im.batch_credential_issuance as { batch_size?: unknown } | undefined)?.batch_size;
    if (typeof max !== 'number' || !Number.isInteger(max) || max < 2) return 1;
    const want = this.client.opts.batchSize;
    return typeof want === 'number' && Number.isFinite(want) ? Math.max(1, Math.min(Math.floor(want), max)) : 1;
  }

  private async issueOne(configId: string, config: Record<string, unknown>, token: TokenResponse, anonymous: boolean): Promise<IssuedCredential> {
    const binding = (config.cryptographic_binding_methods_supported as string[] | undefined) ?? ['jwk'];
    const holders: Holder[] = [];
    for (let i = this.batchSize(); i > 0; i--) {
      const key = await this.client.opts.keyStore.create();
      holders.push({ key, did: bindingDid(key.publicJwk, binding) });
    }
    const identifiers = token.authorization_details?.find((d) => d.credential_configuration_id === configId)?.credential_identifiers;
    let nonce = await this.nonce(token);
    let response: Response | undefined;
    let sealed: SealedRequest | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      const proofs = await this.proofs(holders, config, nonce, anonymous);
      const body: Record<string, unknown> = identifiers?.length
        ? { credential_identifier: identifiers[0], proofs }
        : { credential_configuration_id: configId, proofs };
      sealed = this.seal(body);
      response = await this.credentialPost(String(this.im.credential_endpoint), sealed, token);
      if (response.status === 400 && attempt === 0) {
        const err = (await response.clone().json().catch(() => ({}))) as { error?: string };
        if (err.error === 'invalid_nonce') { nonce = await this.nonce(token); continue; }
      }
      break;
    }
    if (!response!.ok) throw await this.error(`Credential request (${configId})`, response!);
    let payload = (await this.open(response!, sealed!)) as { credentials?: Array<{ credential: unknown }>; credential?: unknown; transaction_id?: string;
      interval?: number; notification_id?: string };
    if (response!.status === 202 || (payload.transaction_id && !payload.credentials)) {
      payload = await this.waitDeferred(payload.transaction_id!, payload.interval ?? 5, token) ?? payload;
    }
    return this.complete(configId, config, payload, holders, token);
  }

  /** Asks again for a credential that was still pending when issuance returned (see {@link Oid4vciClient.retrieveDeferred}). */
  async retrieveDeferred(c: IssuedCredential): Promise<IssuedCredential> {
    const p = c.pending;
    if (!p) throw new IssuanceError('The credential is not pending');
    if (!p.accessToken) throw new IssuanceError('No access token was kept for this deferred credential; ask the issuer for a new offer', 'invalid_transaction_id');
    const endpoint = this.im.deferred_credential_endpoint as string | undefined;
    if (!endpoint) throw new IssuanceError('The issuer has no deferred_credential_endpoint');
    const keyStore = this.client.opts.keyStore;
    const binding = (this.configurations[0]!.config.cryptographic_binding_methods_supported as string[] | undefined) ?? ['jwk'];
    const holders: Holder[] = [];
    for (const id of p.holderKeyIds ?? [c.holderKeyId]) {
      const key = await keyStore.get(id);
      if (!key) throw new IssuanceError(`Holder key ${id} of the deferred credential is gone`);
      holders.push({ key, did: bindingDid(key.publicJwk, binding) });
    }
    if (p.dpopKeyId) {
      const key = await keyStore.get(p.dpopKeyId);
      if (!key) throw new IssuanceError('The DPoP key the access token is bound to is gone');
      this.dpop = new Dpop(key);
    }
    let token: TokenResponse = { access_token: p.accessToken, token_type: p.tokenType ?? 'Bearer', refresh_token: p.refreshToken };
    let sealed = this.seal({ transaction_id: p.transactionId });
    let r = await this.credentialPost(endpoint, sealed, token);
    let refreshed = false;
    if (r.status === 401 && p.refreshToken) {
      // The access token expired while the issuer worked: refresh it (same DPoP key, same client authentication as the
      // original token request) and ask once more.
      const auth = p.tokenAuth ?? { attested: false };
      token = await this.token({ grant_type: 'refresh_token', refresh_token: p.refreshToken, ...(auth.clientId ? { client_id: auth.clientId } : {}) },
        auth.attested);
      token.refresh_token ??= p.refreshToken;
      refreshed = true;
      sealed = this.seal({ transaction_id: p.transactionId });
      r = await this.credentialPost(endpoint, sealed, token);
    }
    const stillPending = (interval?: number): IssuedCredential => ({ ...c, pending: { ...p, accessToken: token.access_token, tokenType: token.token_type,
      refreshToken: token.refresh_token, interval: interval ?? p.interval } });
    if (r.status === 202) return stillPending(((await this.open(r, sealed)) as { interval?: number }).interval);
    const pendingInterval = await issuancePending(r);
    if (pendingInterval !== undefined) return stillPending(pendingInterval || undefined);
    if (!r.ok) {
      const err = await this.error('Deferred credential request', r);
      if (refreshed) err.updatedPending = stillPending(); // a rotated refresh token must not be lost
      throw err;
    }
    const done = await this.complete(c.configurationId, this.configurations[0]!.config, await this.open(r, sealed), holders, token, true);
    done.id = c.id;
    return done;
  }

  /** Pairs the received credentials with their keys, verifies them and refuses invalid ones (or records a pending issuance). */
  private async complete(configId: string, config: Record<string, unknown>, payload: { credentials?: Array<{ credential: unknown }>; credential?: unknown;
    transaction_id?: string; interval?: number; notification_id?: string }, holders: Holder[], token: TokenResponse, retry = false): Promise<IssuedCredential> {
    const opts = this.client.opts;
    const format = String(config.format);
    const meta = (config.credential_metadata ?? {}) as Record<string, unknown>;
    const received = payload.credentials?.map((c) => c.credential) ?? (payload.credential !== undefined ? [payload.credential] : []);
    const paired = received.length ? bindInstances(format, received, holders) : { instances: [], dropped: 0 };
    // A refused fresh issuance keeps no keys; a refused retry keeps them for the pending entry, which removing deletes.
    const dropKeys = async (keep: Set<string>) => { for (const h of holders) if (!keep.has(h.key.id)) await opts.keyStore.delete?.(h.key.id); };
    if (paired.error) {
      await this.notifier(token, payload.notification_id)?.('credential_failure', paired.error.slice(0, 200));
      if (!retry) await dropKeys(new Set());
      throw new IssuanceError(paired.error, 'invalid_credential');
    }
    const [primary, ...more] = paired.instances.length ? paired.instances : [{ credential: undefined, holderKeyId: holders[0]!.key.id,
      holderJwk: holders[0]!.key.publicJwk, ...(holders[0]!.did ? { holderDid: holders[0]!.did } : {}) }];
    const issued: IssuedCredential = {
      id: randomId(), format, configurationId: configId, ...primary!, credentialIssuer: this.metadata.credentialIssuer, issuedAt: new Date().toISOString(),
      display: ((meta.display ?? config.display) as Record<string, unknown>[] | undefined)?.[0],
      claimMetadata: (meta.claims ?? config.claims) as unknown[] | undefined,
      ...(more.length ? { instances: more } : {}),
    };
    if (!issued.credential && payload.transaction_id) {
      issued.pending = { transactionId: payload.transaction_id, interval: payload.interval ?? 5, accessToken: token.access_token, tokenType: token.token_type,
        ...(token.refresh_token ? { refreshToken: token.refresh_token, ...(this.tokenAuth ? { tokenAuth: this.tokenAuth } : {}) } : {}),
        ...(this.dpop && token.token_type?.toLowerCase() === 'dpop' ? { dpopKeyId: this.dpop.key.id } : {}), holderKeyIds: holders.map((h) => h.key.id) };
      return issued;
    }
    // One notification_id covers every credential of the response (OID4VCI §8.3, §11).
    const notify = this.notifier(token, payload.notification_id);
    if (opts.verify !== false) {
      // Every instance is verified with its own key; one bad instance refuses the batch.
      for (const instance of [issued, ...more]) {
        instance.report = await verifyCredential(format, instance.credential, { trust: opts.trust, fetch: this.client.fetchFn,
          holderJwk: instance.holderJwk, holderDid: instance.holderDid, credentialIssuer: issued.credentialIssuer });
      }
      if (!payload.credentials && payload.credential) issued.report!.checks.unshift({ id: 'oid4vci.response', label: 'Credential response',
        status: 'warn', detail: 'Pre-1.0 response shape (credential instead of credentials[])' });
      if (paired.dropped) issued.report!.checks.unshift({ id: 'oid4vci.batch', label: 'Batch', status: 'warn',
        detail: `${paired.dropped} further credential(s) for keys already used were not kept` });
      const differs = more.find((x) => !sameDataset(issued.report!.claims, x.report!.claims));
      const refused = opts.rejectInvalid === false ? undefined
        : differs ? { report: differs.report!, reason: 'The batch instances carry different claims; a batch must share one credential dataset (OID4VCI §3.3.2)' }
          : [issued, ...more].map((x) => ({ report: x.report!, reason: rejection(format, x.report!) })).find((x) => x.reason);
      if (refused) {
        const reason = more.length ? `${refused.reason} (one of ${more.length + 1} batch instances)` : refused.reason!;
        await notify?.('credential_failure', reason.slice(0, 200));
        if (!retry) await dropKeys(new Set());
        throw new IssuanceError(reason, 'invalid_credential', undefined, refused.report);
      }
    }
    // Keys the issuer issued nothing for are not kept.
    await dropKeys(new Set([issued, ...more].map((x) => x.holderKeyId)));
    // The primary keeps its full report; further instances keep the outcome without a second copy of the claims.
    for (const x of more) if (x.report) x.report = { ...x.report, claims: {} };
    if (notify) Object.defineProperty(issued, 'notify', { value: notify, enumerable: false });
    return issued;
  }

  private notifier(token: TokenResponse, notificationId?: string) {
    const endpoint = this.im.notification_endpoint as string | undefined;
    return endpoint && notificationId ? async (event: NotificationEvent, description?: string) => {
      await this.credentialPost(endpoint, json({ notification_id: notificationId, event, ...(description ? { event_description: description } : {}) }), token)
        .catch(() => undefined);
    } : undefined;
  }

  /**
   * The proofs member (OID4VCI §8.2, Appendix F) for one or more holder keys (a batch): {@code jwt} proofs signed
   * with ES256 (it must be among the issuer's proof_signing_alg_values_supported), or — when the issuer accepts only
   * key attestations — an {@code attestation} proof: one key attestation of all the keys, bound to the c_nonce.
   */
  private async proofs(holders: Holder[], config: Record<string, unknown>, nonce: string | undefined, anonymous: boolean): Promise<Record<string, string[]>> {
    const types = config.proof_types_supported as Record<string, Record<string, unknown>> | undefined;
    const algsOk = (t?: Record<string, unknown>) => {
      const algs = t?.proof_signing_alg_values_supported as string[] | undefined;
      return !algs || algs.includes('ES256');
    };
    const attested = () => this.client.opts.attester!.keyAttestation(holders.map((h) => h.key.publicJwk), nonce);
    if (!types || (types.jwt && algsOk(types.jwt))) return { jwt: await this.jwtProofs(holders, config, nonce, anonymous) };
    if (types.attestation && this.client.opts.attester && algsOk(types.attestation)) {
      this.checkKeyProtection(types.attestation);
      return { attestation: [await attested()] };
    }
    if (types.jwt) throw new IssuanceError(`The issuer accepts jwt proofs signed with ${JSON.stringify(types.jwt.proof_signing_alg_values_supported)}; this wallet signs with ES256`, 'invalid_proof');
    if (types.attestation) {
      if (!this.client.opts.attester) throw new IssuanceError('The issuer accepts only key attestation proofs and no wallet provider is configured', 'key_attestation_required');
      if (!algsOk(types.attestation)) throw new IssuanceError('The issuer does not accept ES256 key attestations', 'invalid_proof');
      this.checkKeyProtection(types.attestation);
      return { attestation: [await attested()] };
    }
    throw new IssuanceError(`No supported proof type (issuer offers ${Object.keys(types).join(', ')})`, 'invalid_proof');
  }

  /**
   * jwt proofs: one per key, or — with a key attestation — a single proof by the first key whose attestation lists
   * every key of the batch (HAIP §4.5.1; the issuer then issues one credential per attested key, OID4VCI F.1).
   */
  private async jwtProofs(holders: Holder[], config: Record<string, unknown>, nonce: string | undefined, anonymous: boolean): Promise<string[]> {
    const jwtProof = (config.proof_types_supported as Record<string, Record<string, unknown>> | undefined)?.jwt;
    const ka = this.client.opts.keyAttestation ?? 'auto';
    const required = jwtProof?.key_attestations_required as { key_storage?: string[]; user_authentication?: string[] } | undefined;
    if (required && !this.client.opts.attester) throw new IssuanceError('Issuer requires a key attestation but no wallet provider is configured', 'key_attestation_required');
    this.checkKeyProtection(jwtProof);
    if (this.client.opts.attester && ka !== 'never' && (ka === 'always' || required)) {
      const attestation = await this.client.opts.attester.keyAttestation(holders.map((h) => h.key.publicJwk), nonce);
      return [await this.proof(holders[0]!, nonce, anonymous, attestation)];
    }
    return Promise.all(holders.map((h) => this.proof(h, nonce, anonymous)));
  }

  /** Refuses before the request when the issuer demands stronger key storage / user authentication than attested. */
  private checkKeyProtection(proofType?: Record<string, unknown>): void {
    const required = proofType?.key_attestations_required as { key_storage?: string[]; user_authentication?: string[] } | undefined;
    if (!required || !this.client.opts.attester) return;
    const caps = this.client.opts.attester.capabilities;
    const missing = (want: string[] | undefined, have: string[]) => want?.length && !want.some((w) => have.includes(w));
    if (missing(required.key_storage, caps.keyStorage) || missing(required.user_authentication, caps.userAuthentication)) {
      throw new IssuanceError(`Issuer requires key storage ${JSON.stringify(required.key_storage ?? [])} / user authentication `
        + `${JSON.stringify(required.user_authentication ?? [])}; this wallet attests ${JSON.stringify(caps)}`, 'insufficient_key_protection');
    }
  }

  private async proof(holder: Holder, nonce: string | undefined, anonymous: boolean, keyAttestation?: string): Promise<string> {
    const header: Record<string, unknown> = { typ: 'openid4vci-proof+jwt' };
    const did = holder.did;
    if (did) header.kid = did.startsWith('did:jwk:') ? `${did}#0` : `${did}#${did.slice('did:key:'.length)}`;
    else header.jwk = holder.key.publicJwk;
    if (keyAttestation) header.key_attestation = keyAttestation;
    const payload: Record<string, unknown> = { aud: this.metadata.credentialIssuer, iat: nowSeconds() };
    if (nonce) payload.nonce = nonce;
    const clientId = this.attestationWanted() ? this.client.opts.attester!.clientId : this.clientId;
    if (!anonymous && clientId) payload.iss = clientId;
    return signJwt(header, payload, holder.key);
  }

  private async credentialPost(url: string, req: SealedRequest, token: TokenResponse): Promise<Response> {
    const init = { method: 'POST', headers: { 'Content-Type': req.contentType, Accept: req.responseKey ? 'application/jwt' : 'application/json' }, body: req.body };
    if (token.token_type?.toLowerCase() === 'dpop' && this.dpop) return this.dpop.fetch(this.client.fetchFn, url, init, token.access_token);
    return this.client.fetchFn(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token.access_token}` } });
  }

  /**
   * OID4VCI §8.2 / §10. Response encryption is requested with a fresh ECDH-ES P-256 key, and only together with request
   * encryption; the request is a JWE to the issuer's credential_request_encryption key (alg and kid from that JWK).
   */
  private encryptionPlan(): EncryptionPlan {
    const reqMd = this.im.credential_request_encryption as { jwks?: { keys?: Jwk[] }; enc_values_supported?: string[]; encryption_required?: boolean } | undefined;
    const resMd = this.im.credential_response_encryption as { alg_values_supported?: string[]; enc_values_supported?: string[]; encryption_required?: boolean } | undefined;
    const prefer = this.client.opts.encryption === 'preferred';
    const pickEnc = (v?: string[]): JweEnc | undefined => (v?.includes('A256GCM') ? 'A256GCM' : v?.includes('A128GCM') ? 'A128GCM' : undefined);
    const reqKey = reqMd?.jwks?.keys?.find((k) => k.kty === 'EC' && k.crv === 'P-256' && k.alg === 'ECDH-ES' && (!k.use || k.use === 'enc'));
    const reqEnc = pickEnc(reqMd?.enc_values_supported);
    const canSealRequest = !!(reqKey && reqEnc);
    const resEnc = resMd?.alg_values_supported?.includes('ECDH-ES') ? pickEnc(resMd.enc_values_supported) : undefined;
    const unsupported = (what: string) => new IssuanceError(`The issuer requires ${what} encryption with parameters this wallet does not support `
      + '(ECDH-ES on P-256 with A128GCM or A256GCM)', 'invalid_encryption_parameters');
    if (reqMd?.encryption_required && !canSealRequest) throw unsupported('credential request');
    if (resMd?.encryption_required && (!resEnc || !canSealRequest)) throw unsupported('credential response');
    const response = resEnc && canSealRequest && (resMd!.encryption_required || prefer) ? { enc: resEnc } : undefined;
    const request = canSealRequest && (reqMd!.encryption_required || prefer || response) ? { jwk: reqKey!, enc: reqEnc! } : undefined;
    return { request, response };
  }

  private seal(body: Record<string, unknown>): SealedRequest {
    const plan = this.encryptionPlan();
    let responseKey: SoftwareKey | undefined;
    if (plan.response) {
      responseKey = SoftwareKey.generate();
      body = { ...body, credential_response_encryption: { jwk: { ...responseKey.publicJwk, alg: 'ECDH-ES', use: 'enc', kid: randomId() }, enc: plan.response.enc } };
    }
    if (!plan.request) return { body: JSON.stringify(body), contentType: 'application/json', responseKey };
    return { body: encryptJwe(bytes.utf8Encode(JSON.stringify(body)), plan.request.jwk, plan.request.enc), contentType: 'application/jwt', responseKey };
  }

  /** Reads a credential response, decrypting it when encryption was requested (an unencrypted one is then refused). */
  private async open(r: Response, sealed: SealedRequest): Promise<Record<string, unknown>> {
    if (!sealed.responseKey) return (await r.json()) as Record<string, unknown>;
    const contentType = (r.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
    if (contentType !== 'application/jwt') throw new IssuanceError('The issuer answered without encryption although an encrypted response was requested', 'invalid_encryption_parameters');
    const key = sealed.responseKey;
    const { header, plaintext } = decryptJwe((await r.text()).trim(), (peer) => key.ecdh(peer));
    // No zip was requested, so none is accepted (§8.2: absent zip → no compression); this also rules out inflation bombs.
    if (header.zip !== undefined) throw new IssuanceError(`The issuer compressed the response (zip ${String(header.zip)}) although no compression was requested`, 'invalid_encryption_parameters');
    return JSON.parse(bytes.utf8Decode(plaintext)) as Record<string, unknown>;
  }

  private async waitDeferred(transactionId: string, interval: number, token: TokenResponse) {
    const endpoint = this.im.deferred_credential_endpoint as string | undefined;
    if (!endpoint) return undefined;
    const deadline = Date.now() + (this.client.opts.deferredWaitSeconds ?? 30) * 1000;
    let wait = Math.max(1, interval);
    while (Date.now() + wait * 1000 <= deadline) {
      await new Promise((r) => setTimeout(r, wait * 1000));
      const sealed = this.seal({ transaction_id: transactionId });
      const r = await this.credentialPost(endpoint, sealed, token);
      if (r.status === 200) return (await this.open(r, sealed)) as { credentials?: Array<{ credential: unknown }>; notification_id?: string };
      if (r.status === 202) { wait = ((await this.open(r, sealed)) as { interval?: number }).interval ?? wait; continue; }
      const pendingInterval = await issuancePending(r);
      if (pendingInterval !== undefined) { wait = pendingInterval || wait; continue; }
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

/** A pre-1.0 "issuance_pending" answer (400): its interval (0 when none is given), or undefined for anything else. */
async function issuancePending(r: Response): Promise<number | undefined> {
  if (r.status !== 400) return undefined;
  const err = (await r.clone().json().catch(() => ({}))) as { error?: string; interval?: number };
  return err.error === 'issuance_pending' ? (typeof err.interval === 'number' ? err.interval : 0) : undefined;
}

const json = (body: Record<string, unknown>): SealedRequest => ({ body: JSON.stringify(body), contentType: 'application/json' });

/**
 * Pairs each credential of a response with the holder key it is bound to: the response need not follow the order of
 * the proofs. A credential bound to a key this wallet did not send refuses the response, and so does a batch mixing
 * bound and bearer credentials; a further credential for a key already paired is dropped (counted in {@code dropped}).
 * Bearer credentials take the unused keys in order.
 */
function bindInstances(format: string, credentials: unknown[], holders: Holder[]): { instances: CredentialInstance[]; dropped: number; error?: string } {
  const free = [...holders];
  const instances: CredentialInstance[] = [];
  let dropped = 0;
  // A subject DID binds a key when it is a did:jwk or did:key, or when the wallet bound this configuration to DIDs;
  // otherwise it is just the subject's identifier and the credential pairs like a bearer one.
  const bindings = credentials.map((c) => {
    const b = holderBinding(format, c);
    if (b.jwk || !b.did) return b;
    const jwk = didPublicKey(b.did);
    return jwk ? { jwk } : holders.some((h) => h.did) ? b : {};
  });
  const bound = bindings.filter((b) => b.jwk || b.did).length;
  if (bound > 0 && bound < credentials.length) return { instances, dropped, error: 'The batch mixes credentials bound to a key with bearer credentials' };
  const sameKey = (h: Holder, b: { jwk?: Jwk; did?: string }) => (b.jwk ? h.key.publicJwk.x === b.jwk.x && h.key.publicJwk.y === b.jwk.y : h.did === b.did);
  for (const [i, credential] of credentials.entries()) {
    const b = bindings[i]!;
    let h: Holder | undefined;
    if (b.jwk || b.did) {
      const at = free.findIndex((x) => sameKey(x, b));
      if (at >= 0) h = free.splice(at, 1)[0];
      else if (holders.some((x) => sameKey(x, b))) { dropped++; continue; }
      else return { instances, dropped, error: `Credential ${i + 1} of the response is bound to a key this wallet did not send` };
    } else {
      h = free.shift();
      if (!h) { dropped++; continue; }
    }
    instances.push({ credential, holderKeyId: h!.key.id, holderJwk: h!.key.publicJwk, ...(h!.did ? { holderDid: h!.did } : {}) });
  }
  return { instances, dropped };
}

/** Claims that differ between instances of one dataset by design: per-instance key, status entry and timestamps. */
const PER_INSTANCE = new Set(['cnf', 'status', 'iat', 'nbf', 'exp', 'jti', 'id', 'credentialStatus', 'validFrom', 'validUntil', 'issuanceDate', 'expirationDate']);

/**
 * Whether two instances carry the same credential dataset (OID4VCI §3.3.2), ignoring per-instance members. Member
 * order is not data: issuers shuffle selectively disclosed members per instance.
 */
function sameDataset(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const canonical = (v: unknown): unknown => (Array.isArray(v) ? v.map(canonical)
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)).map(([k, x]) => [k, canonical(x)])) : v);
  const strip = (o: Record<string, unknown>) => canonical(Object.fromEntries(Object.entries(o).filter(([k]) => !PER_INSTANCE.has(k))));
  return JSON.stringify(strip(a)) === JSON.stringify(strip(b));
}

/** Why a freshly issued credential must be refused, if it must. */
function rejection(format: string, r: VerificationReport): string | undefined {
  if (!r.valid) {
    const failed = r.checks.filter((x) => x.status === 'fail' && x.id !== 'issuer.trust').map((x) => `${x.label}: ${x.detail ?? 'failed'}`);
    return `The credential failed verification (${failed.join('; ')})`;
  }
  if ((format === 'dc+sd-jwt' || format === 'vc+sd-jwt') && r.issuer.x5c?.length && r.trust?.decision !== 'TRUSTED') {
    return `The SD-JWT VC issuer certificate is not trusted (${r.trust?.summary ?? 'no trust decision'}); SD-JWT VC requires rejecting it`;
  }
  return undefined;
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
