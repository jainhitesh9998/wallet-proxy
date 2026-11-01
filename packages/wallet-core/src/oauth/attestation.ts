/**
 * Wallet attestation (OAuth 2.0 Attestation-Based Client Authentication, draft -07 as pinned by OID4VCI 1.0,
 * also valid under -12) and key attestation (OID4VCI 1.0 Appendix D), as required by HAIP 1.0.
 */
import { nowSeconds, randomId, signJwt } from '../crypto/jwt.js';
import type { SigningKey } from '../crypto/keys.js';
import type { Jwk } from '@vctrust/trust-client';

export interface WalletProviderConfig {
  /** Wallet provider identifier (attestation iss). */
  issuer: string;
  /** client_id shared by all instances of this wallet (attestation sub). */
  clientId: string;
  /** Wallet provider signing key and its certificate chain (no trust anchor), base64 DER. */
  signingKey: SigningKey;
  x5c: string[];
  walletName?: string;
  walletLink?: string;
  keyStorage?: string[];
  userAuthentication?: string[];
}

/** The instance key an attestation binds (cnf) for one authorization server. */
export type InstanceKeyProvider = (authorizationServer: string) => Promise<SigningKey>;

/** One instance key per authorization server, so attestations do not correlate the user across issuers. */
export function instanceKeyPerServer(create: () => Promise<SigningKey>): InstanceKeyProvider {
  const keys = new Map<string, Promise<SigningKey>>();
  return (as) => {
    if (!keys.has(as)) keys.set(as, create());
    return keys.get(as)!;
  };
}

/** Issues attestations for this wallet instance. In production this runs in the wallet provider backend. */
export class WalletAttester {
  private readonly keyFor: InstanceKeyProvider;

  /** @param instanceKeys one key for every server, or a provider (e.g. {@link instanceKeyPerServer}) */
  constructor(private readonly provider: WalletProviderConfig, instanceKeys: SigningKey | InstanceKeyProvider) {
    this.keyFor = typeof instanceKeys === 'function' ? instanceKeys : async () => instanceKeys;
  }

  get clientId(): string {
    return this.provider.clientId;
  }

  /** Key storage / user authentication levels this wallet provider attests (ISO/IEC 18045 attack potential). */
  get capabilities(): { keyStorage: string[]; userAuthentication: string[] } {
    return { keyStorage: this.provider.keyStorage ?? ['iso_18045_basic'], userAuthentication: this.provider.userAuthentication ?? ['iso_18045_basic'] };
  }

  async clientAttestation(authorizationServer: string, ttlSeconds = 3600): Promise<string> {
    const instanceKey = await this.keyFor(authorizationServer);
    const iat = nowSeconds();
    return signJwt({ typ: 'oauth-client-attestation+jwt', x5c: this.provider.x5c }, {
      iss: this.provider.issuer, sub: this.provider.clientId, iat, nbf: iat - 5, exp: iat + ttlSeconds,
      cnf: { jwk: instanceKey.publicJwk },
      ...(this.provider.walletName ? { wallet_name: this.provider.walletName } : {}),
      ...(this.provider.walletLink ? { wallet_link: this.provider.walletLink } : {}),
    }, this.provider.signingKey);
  }

  async clientAttestationPop(audience: string, challenge?: string): Promise<string> {
    return signJwt({ typ: 'oauth-client-attestation-pop+jwt' }, {
      iss: this.provider.clientId, aud: audience, jti: randomId(), iat: nowSeconds(), ...(challenge ? { challenge } : {}),
    }, await this.keyFor(audience));
  }

  /** Both headers for a request to an authorization server endpoint: a fresh attestation, bound to that server's instance key. */
  async headers(asIssuer: string, challenge?: string): Promise<Record<string, string>> {
    return {
      'OAuth-Client-Attestation': await this.clientAttestation(asIssuer),
      'OAuth-Client-Attestation-PoP': await this.clientAttestationPop(asIssuer, challenge),
    };
  }

  /** key-attestation+jwt attesting the holder keys, bound to the issuer's c_nonce. */
  async keyAttestation(attestedKeys: Jwk[], nonce?: string, ttlSeconds = 600): Promise<string> {
    const iat = nowSeconds();
    return signJwt({ typ: 'key-attestation+jwt', x5c: this.provider.x5c }, {
      iat, exp: iat + ttlSeconds, ...(nonce ? { nonce } : {}), attested_keys: attestedKeys,
      key_storage: this.provider.keyStorage ?? ['iso_18045_basic'],
      user_authentication: this.provider.userAuthentication ?? ['iso_18045_basic'],
    }, this.provider.signingKey);
  }
}
