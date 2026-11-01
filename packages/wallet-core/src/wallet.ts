/** Wallet facade: OpenID4VCI issuance, storage, re-verification and OpenID4VP presentation over one TrustClient. */
import type { TrustClient } from '@vctrust/trust-client';
import type { KeyStore } from './crypto/keys.js';
import type { WalletAttester } from './oauth/attestation.js';
import { Oid4vciClient, type IssuanceSession, type IssuedCredential, type IssuerClientRegistration } from './oid4vci/client.js';
import type { CredentialStore, StoredCredential } from './store/credentials.js';
import { verifyCredential, type VerificationReport } from './verify/index.js';
import { resolveAuthorizationRequest, type AuthorizationRequest, type VerifierView } from './oid4vp/request.js';
import { evaluateDcql, type DcqlResult } from './oid4vp/dcql.js';
import { buildVpToken, submitResponse, type PresentationSelection, type SubmitResult } from './oid4vp/present.js';

export interface WalletOptions {
  trust: TrustClient;
  keyStore: KeyStore;
  credentials: CredentialStore;
  fetch?: typeof fetch;
  attester?: WalletAttester;
  redirectUri: string;
  clientId?: string;
  registrations?: Record<string, IssuerClientRegistration>;
  dpop?: 'auto' | 'never';
  walletAttestation?: 'auto' | 'always' | 'never';
  keyAttestation?: 'auto' | 'always' | 'never';
}

export class Wallet {
  readonly oid4vci: Oid4vciClient;
  private readonly f: typeof fetch;

  constructor(readonly opts: WalletOptions) {
    this.f = opts.fetch ?? fetch;
    this.oid4vci = new Oid4vciClient({ ...opts, fetch: this.f });
  }

  get trust(): TrustClient {
    return this.opts.trust;
  }

  receive(offer: string): Promise<IssuanceSession> {
    return this.oid4vci.startFromOffer(offer);
  }

  async store(issued: IssuedCredential[]): Promise<StoredCredential[]> {
    for (const c of issued) await this.opts.credentials.save(c);
    return issued;
  }

  list(): Promise<StoredCredential[]> {
    return this.opts.credentials.list();
  }

  remove(id: string): Promise<void> {
    return this.opts.credentials.remove(id);
  }

  /** Re-runs verification (signature, validity, status, current issuer trust) for a stored credential. */
  async reverify(id: string): Promise<VerificationReport> {
    const c = await this.opts.credentials.get(id);
    if (!c) throw new Error(`No credential ${id}`);
    const report = await verifyCredential(c.format, c.credential, { trust: this.opts.trust, fetch: this.f, holderJwk: c.holderJwk,
      holderDid: c.holderDid, credentialIssuer: c.credentialIssuer });
    await this.opts.credentials.save({ ...c, report });
    return report;
  }

  async startPresentation(requestUri: string): Promise<PresentationSession> {
    const { request, verifier } = await resolveAuthorizationRequest(requestUri, this.opts.trust, this.f);
    const dcql = await evaluateDcql(request.dcqlQuery, await this.list(), this.opts.trust);
    return new PresentationSession(this, request, verifier, dcql);
  }

  get fetchFn(): typeof fetch {
    return this.f;
  }
}

export class PresentationSession {
  constructor(private readonly wallet: Wallet, readonly request: AuthorizationRequest, readonly verifier: VerifierView, readonly dcql: DcqlResult) {}

  /** Presents the chosen credentials (default: first candidate for every selected query). */
  async respond(choice: Record<string, string> = {}): Promise<SubmitResult> {
    if (!this.dcql.satisfied) throw new Error(this.dcql.reason ?? 'Request cannot be satisfied');
    const selection: PresentationSelection = {};
    for (const id of this.dcql.selected) {
      const m = this.dcql.matches.find((x) => x.query.id === id)!;
      const credential = m.candidates.find((c) => c.id === choice[id]) ?? m.candidates[0]!;
      selection[id] = { credential, claims: m.claims };
    }
    const vpToken = await buildVpToken(this.request, selection, this.wallet.opts.keyStore, this.wallet.fetchFn);
    return submitResponse(this.request, { vp_token: vpToken }, this.wallet.fetchFn);
  }

  /** Tells the verifier the user declined (OpenID4VP §8.5 access_denied). */
  decline(error = 'access_denied', description = 'User declined'): Promise<SubmitResult> {
    return submitResponse(this.request, { error, error_description: description }, this.wallet.fetchFn);
  }
}
