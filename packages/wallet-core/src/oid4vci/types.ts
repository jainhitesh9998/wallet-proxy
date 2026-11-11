/** What the OpenID4VCI client is configured with, the credentials it returns, and the error it fails with. */
import type { Jwk, TrustClient } from '@vctrust/trust-client';
import type { KeyStore } from '../crypto/keys.js';
import type { WalletAttester } from '../oauth/attestation.js';
import type { VerificationReport } from '../verify/index.js';

export interface IssuerClientRegistration {
  /** Pre-registered client_id at this issuer's AS (when not using wallet attestation). */
  clientId: string;
  redirectUri?: string;
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
  /** Hosts that may be reached over plain http: local development only (an issuer on localhost). */
  insecureHosts?: string[];
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
    tokenAuth?: { attested: boolean; clientId?: string };
    /** the user confirmed an issuer the trust layer did not know when the credential was requested */
    confirmedUnknown?: true };
  /** Further instances of the same credential from a batch, each bound to its own key. */
  instances?: CredentialInstance[];
  /** The configuration names no binding method: the credential is not bound to the wallet's key (holderKeyId is only a handle). */
  unbound?: true;
  /**
   * Notifies the issuer (OID4VCI §11) — {@link Wallet.store} sends credential_accepted, {@link Wallet.discard}
   * credential_deleted. Not enumerable, so it is never persisted.
   */
  notify?: (event: NotificationEvent, description?: string) => Promise<void>;
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
