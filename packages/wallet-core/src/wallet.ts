/** Wallet facade: OpenID4VCI issuance, storage, re-verification and OpenID4VP presentation over one TrustClient. */
import type { TrustClient } from '@vctrust/trust-client';
import type { KeyStore } from './crypto/keys.js';
import type { WalletAttester } from './oauth/attestation.js';
import { IssuanceError, Oid4vciClient, type CredentialInstance, type IssuanceSession, type IssuedCredential, type IssuerClientRegistration } from './oid4vci/client.js';
import type { CredentialStore, StoredCredential } from './store/credentials.js';
import { verifyCredential, type VerificationReport } from './verify/index.js';
import { PresentationRequestError, resolveAuthorizationRequest, resolveDcApiRequest, type AuthorizationRequest, type DcApiRequest, type VerifierView } from './oid4vp/request.js';
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
  /** Instances to request of each credential from issuers that support batch issuance (see {@link Oid4vciOptions.batchSize}). */
  batchSize?: number;
}

/** A stored credential's instances; the first is the credential itself. */
export function instancesOf(c: IssuedCredential): CredentialInstance[] {
  return [c, ...(c.instances ?? [])];
}

/**
 * The instance to present next: the least-presented one among those that verified, so each verifier sees a different
 * instance until the batch is used up (OID4VCI §15.4). {@code fresh} is false once every instance has been shown.
 */
export function pickInstance(c: IssuedCredential): { index: number; instance: CredentialInstance; fresh: boolean; total: number; ordinal: number } {
  const all = instancesOf(c);
  const usable = all.map((x, i) => ({ x, i })).filter(({ x }) => x.report?.valid !== false);
  const pool = usable.length ? usable : all.map((x, i) => ({ x, i }));
  const best = pool.reduce((a, b) => ((b.x.presentations ?? 0) < (a.x.presentations ?? 0) ? b : a));
  // index: position among all instances (for markPresented); ordinal: 1-based position among the usable ones (for display)
  return { index: best.i, instance: best.x, fresh: !best.x.presentations, total: pool.length, ordinal: pool.indexOf(best) + 1 };
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

  /** Stores issued credentials, then tells their issuers (credential_accepted, OID4VCI §11). */
  async store(issued: IssuedCredential[]): Promise<StoredCredential[]> {
    for (const c of issued) {
      await this.opts.credentials.save(c);
      await c.notify?.('credential_accepted');
    }
    return issued;
  }

  /** Asks the issuer again for a pending (deferred) credential; once issued it replaces the pending entry and the issuer hears credential_accepted. */
  async retrieveDeferred(id: string): Promise<StoredCredential> {
    const c = await this.opts.credentials.get(id);
    if (!c?.pending) throw new Error(`No pending credential ${id}`);
    let next: IssuedCredential;
    try {
      next = await this.oid4vci.retrieveDeferred(c);
    } catch (e) {
      if (e instanceof IssuanceError && e.updatedPending) await this.opts.credentials.save(e.updatedPending);
      throw e;
    }
    if (next.pending) await this.opts.credentials.save(next);
    else await this.store([next]);
    return next;
  }

  /** The user declined freshly issued credentials: nothing is stored and the issuers hear credential_deleted. */
  async discard(issued: IssuedCredential[]): Promise<void> {
    for (const c of issued) {
      await c.notify?.('credential_deleted', 'Declined by the user');
      for (const x of instancesOf(c)) await this.opts.keyStore.delete?.(x.holderKeyId);
    }
  }

  list(): Promise<StoredCredential[]> {
    return this.opts.credentials.list();
  }

  /** Deletes a credential and the holder keys of all its instances. */
  async remove(id: string): Promise<void> {
    const c = await this.opts.credentials.get(id);
    await this.opts.credentials.remove(id);
    const keys = new Set([...(c ? instancesOf(c).map((x) => x.holderKeyId) : []), ...(c?.pending?.holderKeyIds ?? [])]);
    for (const k of keys) await this.opts.keyStore.delete?.(k);
  }

  /**
   * Re-runs verification (signature, validity, status, current issuer trust) for a stored credential and each of its
   * instances (every instance has its own status entry, HAIP §6.1); returns the first instance's report.
   */
  async reverify(id: string): Promise<VerificationReport> {
    const c = await this.opts.credentials.get(id);
    if (!c) throw new Error(`No credential ${id}`);
    const verify = (x: CredentialInstance) => verifyCredential(c.format, x.credential, { trust: this.opts.trust, fetch: this.f, holderJwk: x.holderJwk,
      holderDid: x.holderDid, credentialIssuer: c.credentialIssuer });
    const report = await verify(c);
    const reports: VerificationReport[] = [];
    for (const x of c.instances ?? []) reports.push({ ...(await verify(x)), claims: {} });
    // Merged into the stored copy as it is now: presentations counted meanwhile are kept, a deleted credential stays deleted.
    const latest = await this.opts.credentials.get(id);
    if (latest) {
      await this.opts.credentials.save({ ...latest, report, ...(latest.instances ? { instances: latest.instances.map((x, i) => ({ ...x, report: reports[i] ?? x.report })) } : {}) });
    }
    return report;
  }

  /** Counts a presentation of one instance, so the next presentation picks another. */
  async markPresented(id: string, index: number): Promise<void> {
    const c = await this.opts.credentials.get(id);
    if (!c) return;
    const bump = <T extends CredentialInstance>(x: T): T => ({ ...x, presentations: (x.presentations ?? 0) + 1 });
    await this.opts.credentials.save(index === 0 ? bump(c) : { ...c, instances: c.instances?.map((x, i) => (i === index - 1 ? bump(x) : x)) });
  }

  async startPresentation(requestUri: string): Promise<PresentationSession> {
    const { request, verifier } = await resolveAuthorizationRequest(requestUri, this.opts.trust, this.f);
    const dcql = await evaluateDcql(request.dcqlQuery, await this.list(), this.opts.trust);
    return new PresentationSession(this, request, verifier, dcql);
  }

  /** A request that arrived through the Digital Credentials API; {@link PresentationSession.respond} returns its response data. */
  async startDcApiPresentation(input: DcApiRequest): Promise<PresentationSession> {
    const { request, verifier } = await resolveDcApiRequest(input, this.opts.trust);
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
    if (this.verifier.refusal) throw new PresentationRequestError(this.verifier.refusal, 'access_denied');
    if (!this.dcql.satisfied) throw new Error(this.dcql.reason ?? 'Request cannot be satisfied');
    const selection: PresentationSelection = {};
    const used: Array<[string, number]> = [];
    for (const id of this.dcql.selected) {
      const m = this.dcql.matches.find((x) => x.query.id === id)!;
      const stored = m.candidates.find((c) => c.id === choice[id]) ?? m.candidates[0]!;
      const { index, instance } = pickInstance(stored);
      selection[id] = { credential: { ...stored, ...instance }, claims: m.claimsFor[stored.id] ?? m.claims };
      used.push([stored.id, index]);
    }
    const vpToken = await buildVpToken(this.request, selection, this.wallet.opts.keyStore, this.wallet.fetchFn);
    // Counted before sending: once a presentation may have reached the verifier, its instance is no longer fresh.
    for (const [id, index] of used) await this.wallet.markPresented(id, index);
    return submitResponse(this.request, { vp_token: vpToken }, this.wallet.fetchFn);
  }

  /** Tells the verifier the user declined (OpenID4VP §8.5 access_denied). */
  decline(error = 'access_denied', description = 'User declined'): Promise<SubmitResult> {
    return submitResponse(this.request, { error, error_description: description }, this.wallet.fetchFn);
  }
}
