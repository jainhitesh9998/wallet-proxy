/**
 * OpenID4VCI 1.0 wallet client with the HAIP 1.0 feature set:
 *  - pre-authorized code (+ tx_code) and authorization code flows; PKCE S256; PAR when offered; RFC 9207 iss check
 *  - DPoP-bound tokens with nonce handling at AS and credential issuer
 *  - wallet attestation (attest_jwt_client_auth) and key attestation in jwt proofs
 *  - nonce endpoint, credential_identifier vs credential_configuration_id, batch and deferred issuance, notification
 *  - credential request / response encryption (ECDH-ES P-256, A128GCM / A256GCM) when the issuer requires or offers it
 *
 * What the wallet is told by the trust layer decides what it does. Issuer metadata and the issuer's trust come from
 * the TrustClient (the proxy first, standard discovery as fallback). An issuer the trust layer refuses is not
 * contacted; an unknown one only after the user confirmed it. Every credential is verified before it is kept, must
 * be the credential that was asked for, and is refused (credential_failure) otherwise.
 *
 * Only OpenID4VCI 1.0 messages are spoken: no c_nonce from the token endpoint, no singular credential member, no
 * issuance_pending error. All endpoints must be https.
 */
import { guardedFetch } from '../net.js';
import { resolveCredentialOffer } from './offer.js';
import { IssuanceSession } from './session.js';
import { IssuanceError, type IssuedCredential, type Oid4vciOptions } from './types.js';

export { IssuanceError, IssuanceSession };
export { bindingDid } from './proofs.js';
export type { CredentialInstance, IssuedCredential, IssuerClientRegistration, NotificationEvent, Oid4vciOptions } from './types.js';

export class Oid4vciClient {
  private readonly f: typeof fetch;

  constructor(readonly opts: Oid4vciOptions) {
    this.f = guardedFetch(opts.fetch ?? fetch, opts.insecureHosts);
  }

  /** Resolves an offer, gets the issuer's metadata and trust through the trust client, and returns a session. */
  async startFromOffer(offerInput: string): Promise<IssuanceSession> {
    const offer = await resolveCredentialOffer(offerInput, this.f, this.opts.insecureHosts);
    await this.refuseUntrusted(offer.credential_issuer);
    const metadata = await this.opts.trust.getIssuerMetadata(offer.credential_issuer);
    return new IssuanceSession(this, offer, metadata);
  }

  /** An issuer the trust layer refuses is turned away on its identifier alone, before anything is fetched from it. */
  private async refuseUntrusted(credentialIssuer: string): Promise<void> {
    const d = await this.opts.trust.evaluateIssuer({ credentialIssuer });
    if (d.decision === 'NOT_TRUSTED') throw new IssuanceError(`The issuer ${credentialIssuer} is not trusted: ${d.summary}`, 'issuer_not_trusted');
  }

  /**
   * Asks the deferred credential endpoint again for a credential stored as pending (OID4VCI §9). Returns it still
   * pending while the issuer is not done; the issued credential keeps the pending one's id.
   */
  async retrieveDeferred(pending: IssuedCredential): Promise<IssuedCredential> {
    await this.refuseUntrusted(pending.credentialIssuer);
    const metadata = await this.opts.trust.getIssuerMetadata(pending.credentialIssuer);
    // What the user agreed to when the credential was requested still holds, and nothing more: an unknown issuer or
    // signer is accepted now only if it was confirmed then.
    return new IssuanceSession(this, { credential_issuer: metadata.credentialIssuer, credential_configuration_ids: [pending.configurationId],
      grants: { authorization_code: {} } }, metadata, pending.pending?.confirmedUnknown === true).retrieveDeferred(pending);
  }

  /** Wallet-initiated issuance (no offer): authorization code flow for the given configurations. */
  async startWalletInitiated(credentialIssuer: string, configurationIds: string[]): Promise<IssuanceSession> {
    await this.refuseUntrusted(credentialIssuer);
    const metadata = await this.opts.trust.getIssuerMetadata(credentialIssuer);
    return new IssuanceSession(this, { credential_issuer: metadata.credentialIssuer, credential_configuration_ids: configurationIds,
      grants: { authorization_code: {} } }, metadata);
  }

  get fetchFn(): typeof fetch {
    return this.f;
  }
}
