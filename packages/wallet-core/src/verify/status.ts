/**
 * Credential status for the verifiers here: IETF Token Status List (JWT for SD-JWT VC, CWT for ISO mdoc) and W3C
 * Bitstring Status List. The checks live in the trust client (shared with verifiers); with a trust client the list
 * is fetched per its lookups.statusLists (issuer or relay) and cached for its ttl, otherwise straight from the issuer.
 */
import { checkBitstringStatus as checkBitstring, checkTokenStatus as checkToken, type FetchedStatusList, type ListCredentialVerifier,
  type PublicKey, type StatusListFetcher, type StatusResult, type TokenStatusReference, type TrustClient, type TrustDecision } from '@vctrust/trust-client';

export type { ListCredentialVerifier, StatusResult };
/** A Token Status List reference ({@code status.status_list}). */
export type StatusListReference = TokenStatusReference;

/** The credential a status belongs to: who may sign its status list. */
export interface StatusContext {
  trust?: TrustClient;
  fetch: typeof fetch;
  /** the credential's signing certificate chain (x5c / x5chain), leaf first, base64 DER */
  signerX5c?: string[];
  /** the credential's signing key, for lists signed without a certificate by the same key */
  signerKey?: PublicKey;
  /** the credential's issuer trust decision (its x509 anchor may also certify the status list signer) */
  decision?: TrustDecision | null;
  /** W3C: the credential's issuer id; a Bitstring Status List credential must come from the same issuer */
  issuer?: string;
  now?: Date;
}

const fromIssuer = (f: typeof fetch): StatusListFetcher => async (uri, accept): Promise<FetchedStatusList> => {
  const r = await f(uri, { headers: { Accept: accept } });
  if (!r.ok) throw new Error(`Status list ${uri}: HTTP ${r.status}`);
  return { body: new Uint8Array(await r.arrayBuffer()), contentType: (r.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase(), source: 'direct' };
};

export async function checkTokenStatus(ref: StatusListReference, ctx: StatusContext, form: 'jwt' | 'cwt' = 'jwt'): Promise<StatusResult> {
  const { trust, fetch: f, ...credential } = ctx;
  if (trust) return trust.checkTokenStatus(ref, { ...credential, form });
  return checkToken(ref, { ...credential, fetchList: fromIssuer(f) }, form);
}

export async function checkBitstringStatus(entry: Record<string, unknown>, ctx: StatusContext & { verifyListCredential?: ListCredentialVerifier }): Promise<StatusResult> {
  const { trust, fetch: f, ...credential } = ctx;
  if (trust) return trust.checkBitstringStatus(entry, credential);
  return checkBitstring(entry, { ...credential, fetchList: fromIssuer(f) });
}
