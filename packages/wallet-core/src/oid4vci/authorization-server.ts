/**
 * The authorization server of an issuance session: who the wallet is to it (a registration, a wallet attestation or
 * a public client_id) and the requests it receives, with attestation headers, DPoP and the retries it may ask for.
 */
import { Dpop } from '../oauth/dpop.js';
import { endpointOf, requestError } from './http.js';
import { IssuanceError, type IssuerClientRegistration, type Oid4vciOptions } from './types.js';

export type TokenResponse = { access_token: string; token_type: string; refresh_token?: string;
  authorization_details?: Array<{ type: string; credential_configuration_id?: string; credential_identifiers?: string[] }> };

export class AuthorizationServer {
  /** DPoP proofs of the session, for the AS and, once the token is DPoP-bound, for the credential issuer. */
  dpop?: Dpop;
  /** how the last token request authenticated (a refresh repeats it) */
  tokenAuth?: { attested: boolean; clientId?: string };
  /** OAuth-Client-Attestation-Challenge from the last AS response, for the next attestation PoP */
  private attestationChallenge?: string;

  constructor(
    private readonly id: string,
    readonly metadata: Record<string, unknown>,
    private readonly grant: 'pre-authorized_code' | 'authorization_code',
    private readonly reg: IssuerClientRegistration | undefined,
    private readonly opts: Pick<Oid4vciOptions, 'keyStore' | 'attester' | 'clientId' | 'dpop' | 'walletAttestation' | 'insecureHosts'>,
    private readonly f: typeof fetch,
  ) {}

  endpoint(name: string): string | undefined {
    return endpointOf(this.metadata, name, this.opts.insecureHosts);
  }

  get clientId(): string | undefined {
    return this.reg?.clientId ?? this.opts.attester?.clientId ?? this.opts.clientId;
  }

  attestationWanted(): boolean {
    const mode = this.opts.walletAttestation ?? 'auto';
    if (!this.opts.attester || mode === 'never' || this.reg) return false;
    if (mode === 'always') return true;
    const methods = (this.metadata.token_endpoint_auth_methods_supported as string[] | undefined) ?? [];
    return methods.includes('attest_jwt_client_auth') || this.grant === 'authorization_code';
  }

  /**
   * POST form to an AS endpoint with optional attestation and DPoP. Retries once: with attestation on invalid_client,
   * with the AS's new challenge on use_attestation_challenge, with a fresh attestation on use_fresh_attestation.
   */
  async post(url: string, form: Record<string, string>, attest: boolean): Promise<Response> {
    const send = async (withAttestation: boolean) => {
      const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
      const body = { ...form };
      if (withAttestation) {
        Object.assign(headers, await this.attestationHeaders());
        body.client_id = this.opts.attester!.clientId;
      }
      const init = { method: 'POST', headers, body: new URLSearchParams(body).toString() };
      const dpop = await this.ensureDpop();
      const r = dpop ? await dpop.fetch(this.f, url, init) : await this.f(url, init);
      const challenge = r.headers.get('OAuth-Client-Attestation-Challenge');
      if (challenge) this.attestationChallenge = challenge;
      return r;
    };
    const r = await send(attest);
    if (r.status !== 400 && r.status !== 401) return r;
    const err = (await r.clone().json().catch(() => ({}))) as { error?: string };
    // Servers signal missing client authentication with invalid_client as 400 or 401.
    if (!attest && err.error === 'invalid_client' && this.opts.attester && this.opts.walletAttestation !== 'never') return send(true);
    if (attest && (err.error === 'use_attestation_challenge' || err.error === 'use_fresh_attestation')) return send(true);
    return r;
  }

  async token(form: Record<string, string>, attest: boolean): Promise<TokenResponse> {
    const endpoint = this.endpoint('token_endpoint');
    if (!endpoint) throw new IssuanceError('Authorization server has no token_endpoint');
    const r = await this.post(endpoint, form, attest);
    if (!r.ok) throw await requestError('Token request', r);
    if (form.grant_type !== 'refresh_token') this.tokenAuth = { attested: attest, ...(form.client_id ? { clientId: form.client_id } : {}) };
    const t = (await r.json()) as TokenResponse;
    if (this.usesDpop && t.token_type?.toLowerCase() !== 'dpop') throw new IssuanceError(`Expected a DPoP-bound token, got ${t.token_type}`);
    return t;
  }

  private get usesDpop(): boolean {
    return this.opts.dpop !== 'never' && Array.isArray(this.metadata.dpop_signing_alg_values_supported)
      && (this.metadata.dpop_signing_alg_values_supported as string[]).includes('ES256');
  }

  private async ensureDpop(): Promise<Dpop | undefined> {
    if (!this.usesDpop) return undefined;
    if (!this.dpop) this.dpop = new Dpop(await this.opts.keyStore.create());
    return this.dpop;
  }

  /**
   * Attestation headers. The PoP carries a challenge when the AS issues them: the one it last returned in
   * OAuth-Client-Attestation-Challenge, else a fresh one from its challenge endpoint (which must then succeed).
   */
  private async attestationHeaders(): Promise<Record<string, string>> {
    const attester = this.opts.attester!;
    let challenge = this.attestationChallenge;
    this.attestationChallenge = undefined;
    const ce = this.endpoint('challenge_endpoint');
    if (!challenge && ce) {
      const r = await this.f(ce, { method: 'POST', headers: { Accept: 'application/json' } });
      if (!r.ok) throw await requestError('Attestation challenge request', r);
      challenge = ((await r.json()) as { attestation_challenge?: string }).attestation_challenge;
      if (!challenge) throw new IssuanceError('The challenge endpoint returned no attestation_challenge', 'invalid_challenge');
    }
    return attester.headers(String(this.metadata.issuer ?? this.id), challenge);
  }
}
