/**
 * One issuance at one issuer, from an offer or on the wallet's initiative: the grant (pre-authorized code or
 * authorization code), the token, a credential request per offered configuration, deferred issuance — waited for or
 * retrieved later — and the credentials the wallet may keep.
 */
import type { IssuerMetadataResult, TrustDecision } from '@vctrust/trust-client';
import { randomId } from '../crypto/jwt.js';
import { Dpop } from '../oauth/dpop.js';
import { createPkce, type Pkce } from '../oauth/pkce.js';
import { bindInstances, credentialResponse, refusal, verifyInstances, type CredentialResponse } from './acceptance.js';
import { AuthorizationServer, type TokenResponse } from './authorization-server.js';
import type { Oid4vciClient } from './client.js';
import { openResponse, sealRequest, type SealedRequest } from './encryption.js';
import { endpointOf, requestError } from './http.js';
import { PRE_AUTH, type CredentialOffer, type TxCode } from './offer.js';
import { bindingDid, bindingMethods, keyProofs, type Holder, type ProofParties } from './proofs.js';
import { IssuanceError, type IssuedCredential, type IssuerClientRegistration, type NotificationEvent } from './types.js';

const SUPPORTED = ['mso_mdoc', 'dc+sd-jwt', 'ldp_vc'] as const;

const json = (body: Record<string, unknown>): SealedRequest => ({ body: JSON.stringify(body), contentType: 'application/json' });

export class IssuanceSession {
  readonly configurations: Array<{ id: string; config: Record<string, unknown> }>;
  readonly grant: 'pre-authorized_code' | 'authorization_code';
  readonly txCode?: TxCode;
  private readonly as: AuthorizationServer;
  private readonly im: Record<string, unknown>;
  private readonly reg?: IssuerClientRegistration;
  private pkce?: Pkce;
  private state?: string;
  private redirectUri: string;

  /** @param confirmed the user already agreed to an issuer the trust layer does not know */
  constructor(private readonly client: Oid4vciClient, readonly offer: CredentialOffer, readonly metadata: IssuerMetadataResult, private confirmed = false) {
    if (metadata.trust.decision === 'NOT_TRUSTED') {
      throw new IssuanceError(`The issuer ${metadata.credentialIssuer} is not trusted: ${metadata.trust.summary}`, 'issuer_not_trusted');
    }
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
    // OID4VCI §4.1.1: the offer's authorization_server is one of the issuer's authorization_servers.
    if (wanted !== undefined && !metadata.authorizationServers[wanted]) {
      throw new IssuanceError(`The offer names the authorization server ${wanted}, which is not one of the issuer's`, 'invalid_credential_offer');
    }
    const as = wanted ?? servers[0] ?? metadata.credentialIssuer;
    this.reg = client.opts.registrations?.[metadata.credentialIssuer];
    this.redirectUri = this.reg?.redirectUri ?? client.opts.redirectUri;
    this.as = new AuthorizationServer(as, metadata.authorizationServers[as] ?? {}, this.grant, this.reg, client.opts, client.fetchFn);
  }

  get credentialIssuer(): string {
    return this.metadata.credentialIssuer;
  }

  get issuerTrust(): TrustDecision {
    return this.metadata.trust;
  }

  /** The trust layer does not know this issuer: beyond the metadata already read, nothing is requested from it until {@link confirmUnknownIssuer}. */
  get needsConfirmation(): boolean {
    return this.metadata.trust.decision !== 'TRUSTED' && !this.confirmed;
  }

  /** The user, told that the issuer is unknown to the trust layer, chose to go on. */
  confirmUnknownIssuer(): void {
    this.confirmed = true;
  }

  private requireConsent(): void {
    if (this.needsConfirmation) {
      throw new IssuanceError(`The issuer ${this.metadata.credentialIssuer} is unknown to the trust service; the user has to confirm it first`, 'issuer_unknown');
    }
  }

  /** Issuer display (OpenID4VCI §12.2.4 display) */
  get issuerDisplay(): Record<string, unknown> | undefined {
    return (this.im.display as Record<string, unknown>[] | undefined)?.[0];
  }

  // ---- pre-authorized code -------------------------------------------------------------------------

  async acceptPreAuthorized(txCode?: string): Promise<IssuedCredential[]> {
    this.requireConsent();
    const pre = this.offer.grants?.[PRE_AUTH];
    if (!pre) throw new IssuanceError('Offer has no pre-authorized code grant');
    if (this.txCode && !txCode) throw new IssuanceError('This offer requires a transaction code', 'tx_code_required');
    const form: Record<string, string> = { grant_type: PRE_AUTH, 'pre-authorized_code': pre['pre-authorized_code'] };
    if (this.txCode) form.tx_code = txCode!;
    const asMd = this.as.metadata;
    const anonymousAllowed = asMd['pre-authorized_grant_anonymous_access_supported'] === true;
    // HAIP 4.4.1: authenticate with the wallet attestation wherever the AS supports it, even if anonymous access is allowed.
    const supportsAttestation = ((asMd.token_endpoint_auth_methods_supported as string[] | undefined) ?? []).includes('attest_jwt_client_auth');
    const attest = this.as.attestationWanted() && (!anonymousAllowed || supportsAttestation || this.client.opts.walletAttestation === 'always');
    if (!anonymousAllowed && this.as.clientId && !attest) form.client_id = this.as.clientId;
    const token = await this.as.token(form, attest);
    return this.issueAll(token, !attest && anonymousAllowed);
  }

  // ---- authorization code -------------------------------------------------------------------------

  /** Builds the authorization request (via PAR when available). Open the returned URL in a browser. */
  async beginAuthorization(): Promise<{ authorizationUrl: string; state: string; redirectUri: string }> {
    this.requireConsent();
    const authEndpoint = this.as.endpoint('authorization_endpoint');
    if (!authEndpoint) throw new IssuanceError('Authorization server has no authorization_endpoint');
    const clientId = this.as.attestationWanted() ? this.client.opts.attester!.clientId : this.as.clientId;
    if (!clientId) throw new IssuanceError('No client_id: configure wallet attestation, a registration or clientId');
    this.pkce = createPkce();
    this.state = randomId();
    const scopes = this.configurations.map((c) => c.config.scope).filter((s): s is string => typeof s === 'string');
    const params: Record<string, string> = {
      response_type: 'code', client_id: clientId, redirect_uri: this.redirectUri, state: this.state,
      code_challenge: this.pkce.challenge, code_challenge_method: 'S256',
    };
    if (scopes.length === this.configurations.length) params.scope = [...new Set(scopes)].join(' ');
    else {
      // OID4VCI §5.1.1: with a separate authorization server, locations names the Credential Issuer.
      const locations = Array.isArray(this.im.authorization_servers) ? { locations: [this.metadata.credentialIssuer] } : {};
      params.authorization_details = JSON.stringify(this.configurations.map((c) => ({ type: 'openid_credential', credential_configuration_id: c.id, ...locations })));
    }
    const issuerState = this.offer.grants?.authorization_code?.issuer_state;
    if (issuerState) params.issuer_state = issuerState;
    const par = this.as.endpoint('pushed_authorization_request_endpoint');
    if (par && this.reg?.usePar !== false) {
      const r = await this.as.post(par, params, this.as.attestationWanted());
      if (!r.ok) {
        throw await requestError('PAR', r);
      }
      const { request_uri: requestUri } = (await r.json()) as { request_uri: string };
      return { authorizationUrl: `${authEndpoint}?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`, state: this.state, redirectUri: this.redirectUri };
    }
    if (this.as.metadata.require_pushed_authorization_requests === true) throw new IssuanceError('AS requires PAR but advertises no endpoint');
    return { authorizationUrl: `${authEndpoint}?${new URLSearchParams(params)}`, state: this.state, redirectUri: this.redirectUri };
  }

  /** Completes the flow with the redirect URL the browser landed on. */
  async completeAuthorization(callbackUrl: string): Promise<IssuedCredential[]> {
    const q = new URLSearchParams(callbackUrl.includes('?') ? callbackUrl.slice(callbackUrl.indexOf('?') + 1).split('#')[0] : '');
    if (q.get('error')) throw new IssuanceError(`Authorization failed: ${q.get('error')} ${q.get('error_description') ?? ''}`, q.get('error')!);
    if (!this.state || q.get('state') !== this.state) throw new IssuanceError('state mismatch in authorization response', 'invalid_state');
    const iss = q.get('iss');
    if (iss && iss !== this.as.metadata.issuer) throw new IssuanceError(`iss ${iss} does not match the authorization server`, 'invalid_iss');
    if (!iss && this.as.metadata.authorization_response_iss_parameter_supported === true) throw new IssuanceError('Missing iss in authorization response (RFC 9207)', 'invalid_iss');
    const code = q.get('code');
    if (!code) throw new IssuanceError('No authorization code in callback');
    const form: Record<string, string> = { grant_type: 'authorization_code', code, code_verifier: this.pkce!.verifier, redirect_uri: this.redirectUri };
    if (!this.as.attestationWanted() && this.as.clientId) form.client_id = this.as.clientId;
    return this.issueAll(await this.as.token(form, this.as.attestationWanted()), false);
  }

  // ---- credential ----------------------------------------------------------------------------------

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
    if (!(SUPPORTED as readonly unknown[]).includes(config.format)) throw new IssuanceError(`This wallet does not hold credentials of format ${String(config.format)}`, 'unsupported_credential_format');
    // OID4VCI §12.2.4: a configuration that names no binding methods issues credentials not bound to a key, and takes no proofs.
    const binding = bindingMethods(config);
    const holders: Holder[] = [];
    for (let i = binding.length ? this.batchSize() : 1; i > 0; i--) {
      const key = await this.client.opts.keyStore.create();
      holders.push({ key, did: bindingDid(key.publicJwk, binding) });
    }
    const identifiers = token.authorization_details?.find((d) => d.credential_configuration_id === configId)?.credential_identifiers;
    let nonce = binding.length ? await this.nonce() : undefined;
    let response: Response | undefined;
    let sealed: SealedRequest | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      const proofs = binding.length ? { proofs: await keyProofs(holders, config, nonce, this.proofParties(anonymous), this.client.opts) } : {};
      // §8.2: credential_identifier when the token response carried authorization_details, else credential_configuration_id.
      const body: Record<string, unknown> = identifiers?.length ? { credential_identifier: identifiers[0], ...proofs } : { credential_configuration_id: configId, ...proofs };
      sealed = this.seal(body);
      response = await this.credentialPost(this.credentialEndpoint(), sealed, token);
      if (response.status === 400 && attempt === 0 && binding.length) {
        const err = (await response.clone().json().catch(() => ({}))) as { error?: string };
        if (err.error === 'invalid_nonce') { nonce = await this.nonce(); continue; }
      }
      break;
    }
    if (!response!.ok) throw await requestError(`Credential request (${configId})`, response!);
    let payload = credentialResponse(await openResponse(response!, sealed!));
    if (payload.transaction_id) payload = await this.waitDeferred(payload.transaction_id, payload.interval ?? 5, token) ?? payload;
    return this.complete(configId, config, payload, holders, token, binding.length > 0);
  }

  private proofParties(anonymous: boolean): ProofParties {
    const clientId = this.as.attestationWanted() ? this.client.opts.attester!.clientId : this.as.clientId;
    return { aud: this.metadata.credentialIssuer, ...(!anonymous && clientId ? { iss: clientId } : {}) };
  }

  // ---- deferred ------------------------------------------------------------------------------------

  private async waitDeferred(transactionId: string, interval: number, token: TokenResponse) {
    const endpoint = this.endpoint('deferred_credential_endpoint');
    if (!endpoint) return undefined;
    const deadline = Date.now() + (this.client.opts.deferredWaitSeconds ?? 30) * 1000;
    let wait = Math.max(1, interval);
    while (Date.now() + wait * 1000 <= deadline) {
      await new Promise((r) => setTimeout(r, wait * 1000));
      const sealed = this.seal({ transaction_id: transactionId });
      const r = await this.credentialPost(endpoint, sealed, token);
      if (r.status === 200) return credentialResponse(await openResponse(r, sealed));
      // §9.2: not ready yet, with the interval to wait before asking again.
      if (r.status === 202) { wait = Math.max(1, ((await openResponse(r, sealed)) as { interval?: number }).interval ?? wait); continue; }
      throw await requestError('Deferred credential request', r);
    }
    return undefined;
  }

  /** Asks again for a credential that was still pending when issuance returned (see {@link Oid4vciClient.retrieveDeferred}). */
  async retrieveDeferred(c: IssuedCredential): Promise<IssuedCredential> {
    const p = c.pending;
    if (!p) throw new IssuanceError('The credential is not pending');
    this.requireConsent();
    if (!p.accessToken) throw new IssuanceError('No access token was kept for this deferred credential; ask the issuer for a new offer', 'invalid_transaction_id');
    const endpoint = this.endpoint('deferred_credential_endpoint');
    if (!endpoint) throw new IssuanceError('The issuer has no deferred_credential_endpoint');
    const keyStore = this.client.opts.keyStore;
    const binding = bindingMethods(this.configurations[0]!.config);
    const holders: Holder[] = [];
    for (const id of p.holderKeyIds ?? [c.holderKeyId]) {
      const key = await keyStore.get(id);
      if (!key) throw new IssuanceError(`Holder key ${id} of the deferred credential is gone`);
      holders.push({ key, did: bindingDid(key.publicJwk, binding) });
    }
    if (p.dpopKeyId) {
      const key = await keyStore.get(p.dpopKeyId);
      if (!key) throw new IssuanceError('The DPoP key the access token is bound to is gone');
      this.as.dpop = new Dpop(key);
    }
    let token: TokenResponse = { access_token: p.accessToken, token_type: p.tokenType ?? 'Bearer', refresh_token: p.refreshToken };
    let sealed = this.seal({ transaction_id: p.transactionId });
    let r = await this.credentialPost(endpoint, sealed, token);
    let refreshed = false;
    if (r.status === 401 && p.refreshToken) {
      // The access token expired while the issuer worked: refresh it (same DPoP key, same client authentication as the
      // original token request) and ask once more.
      const auth = p.tokenAuth ?? { attested: false };
      token = await this.as.token({ grant_type: 'refresh_token', refresh_token: p.refreshToken, ...(auth.clientId ? { client_id: auth.clientId } : {}) },
        auth.attested);
      token.refresh_token ??= p.refreshToken;
      refreshed = true;
      sealed = this.seal({ transaction_id: p.transactionId });
      r = await this.credentialPost(endpoint, sealed, token);
    }
    const stillPending = (interval?: number): IssuedCredential => ({ ...c, pending: { ...p, accessToken: token.access_token, tokenType: token.token_type,
      refreshToken: token.refresh_token, interval: interval ?? p.interval } });
    if (r.status === 202) return stillPending(((await openResponse(r, sealed)) as { interval?: number }).interval);
    if (!r.ok) {
      const err = await requestError('Deferred credential request', r);
      if (refreshed) err.updatedPending = stillPending(); // a rotated refresh token must not be lost
      throw err;
    }
    const done = await this.complete(c.configurationId, this.configurations[0]!.config, credentialResponse(await openResponse(r, sealed)), holders, token,
      binding.length > 0, true);
    done.id = c.id;
    return done;
  }

  // ---- what was issued -----------------------------------------------------------------------------

  /** Pairs the received credentials with their keys, verifies them and refuses what must not be kept (or records a pending issuance). */
  private async complete(configId: string, config: Record<string, unknown>, payload: CredentialResponse, holders: Holder[], token: TokenResponse,
                         bound: boolean, retry = false): Promise<IssuedCredential> {
    const opts = this.client.opts;
    const format = String(config.format);
    const meta = (config.credential_metadata ?? {}) as Record<string, unknown>;
    const received = payload.credentials?.map((c) => c.credential) ?? [];
    const paired = received.length ? bindInstances(format, received, holders, bound) : { instances: [], dropped: 0 };
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
      display: (meta.display as Record<string, unknown>[] | undefined)?.[0],
      claimMetadata: meta.claims as unknown[] | undefined,
      ...(more.length ? { instances: more } : {}), ...(bound ? {} : { unbound: true as const }),
    };
    if (!issued.credential && payload.transaction_id) {
      const { dpop, tokenAuth } = this.as;
      issued.pending = { transactionId: payload.transaction_id, interval: payload.interval ?? 5, accessToken: token.access_token, tokenType: token.token_type,
        ...(token.refresh_token ? { refreshToken: token.refresh_token, ...(tokenAuth ? { tokenAuth } : {}) } : {}),
        ...(dpop && token.token_type?.toLowerCase() === 'dpop' ? { dpopKeyId: dpop.key.id } : {}), holderKeyIds: holders.map((h) => h.key.id),
        ...(this.confirmed ? { confirmedUnknown: true as const } : {}) };
      return issued;
    }
    // One notification_id covers every credential of the response (OID4VCI §8.3, §11).
    const notify = this.notifier(token, payload.notification_id);
    await verifyInstances([issued, ...more], format, config, opts.trust, bound);
    if (paired.dropped) issued.report!.checks.unshift({ id: 'oid4vci.batch', label: 'Batch', status: 'warn',
      detail: `${paired.dropped} further credential(s) for keys already used were not kept` });
    const refused = refusal(issued, more, this.confirmed);
    if (refused) {
      await notify?.('credential_failure', refused.reason.slice(0, 200));
      if (!retry) await dropKeys(new Set());
      throw new IssuanceError(refused.reason, 'invalid_credential', undefined, refused.report);
    }
    // Keys the issuer issued nothing for are not kept.
    await dropKeys(new Set([issued, ...more].map((x) => x.holderKeyId)));
    // The primary keeps its full report; further instances keep the outcome without a second copy of the claims.
    for (const x of more) if (x.report) x.report = { ...x.report, claims: {} };
    if (notify) Object.defineProperty(issued, 'notify', { value: notify, enumerable: false });
    return issued;
  }

  // ---- requests to the credential issuer -----------------------------------------------------------

  /** An endpoint from the issuer's metadata; https only. */
  private endpoint(name: string): string | undefined {
    return endpointOf(this.im, name, this.client.opts.insecureHosts);
  }

  private credentialEndpoint(): string {
    const e = this.endpoint('credential_endpoint');
    if (!e) throw new IssuanceError('The issuer metadata has no credential_endpoint');
    return e;
  }

  /** A c_nonce from the nonce endpoint (OID4VCI §7); an issuer without one asks for no nonce in proofs. */
  private async nonce(): Promise<string | undefined> {
    const ne = this.endpoint('nonce_endpoint');
    if (!ne) return undefined;
    const r = await this.client.fetchFn(ne, { method: 'POST', headers: { Accept: 'application/json' } });
    if (!r.ok) throw await requestError('Nonce request', r);
    const dpopNonce = r.headers.get('DPoP-Nonce');
    if (dpopNonce && this.as.dpop) this.as.dpop.setNonce(this.credentialEndpoint(), dpopNonce);
    const nonce = ((await r.json()) as { c_nonce?: unknown }).c_nonce;
    if (typeof nonce !== 'string' || !nonce) throw new IssuanceError('The nonce endpoint returned no c_nonce', 'invalid_nonce');
    return nonce;
  }

  private seal(body: Record<string, unknown>): SealedRequest {
    return sealRequest(body, this.im, this.client.opts.encryption);
  }

  private async credentialPost(url: string, req: SealedRequest, token: TokenResponse): Promise<Response> {
    const init = { method: 'POST', headers: { 'Content-Type': req.contentType, Accept: req.responseKey ? 'application/jwt' : 'application/json' }, body: req.body };
    const dpop = this.as.dpop;
    if (token.token_type?.toLowerCase() === 'dpop' && dpop) return dpop.fetch(this.client.fetchFn, url, init, token.access_token);
    return this.client.fetchFn(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token.access_token}` } });
  }

  private notifier(token: TokenResponse, notificationId?: string) {
    const endpoint = this.endpoint('notification_endpoint');
    return endpoint && notificationId ? async (event: NotificationEvent, description?: string) => {
      await this.credentialPost(endpoint, json({ notification_id: notificationId, event, ...(description ? { event_description: description } : {}) }), token)
        .catch(() => undefined);
    } : undefined;
  }
}
