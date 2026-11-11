/**
 * What the wallet accepts from the credential endpoint: the shape of a credential response, which holder key each
 * credential of a batch belongs to, and whether the verified credentials may be kept.
 */
import type { Jwk, TrustClient } from '@vctrust/trust-client';
import { didPublicKey } from '../crypto/did-key.js';
import { expectedOf, holderBinding, verifyCredential, type VerificationReport } from '../verify/index.js';
import type { Holder } from './proofs.js';
import { IssuanceError, type CredentialInstance } from './types.js';

export interface CredentialResponse {
  credentials?: Array<{ credential: unknown }>;
  transaction_id?: string;
  interval?: number;
  notification_id?: string;
}

/** An OpenID4VCI 1.0 Credential Response (§8.3): credentials, or a transaction_id for deferred issuance; never both, never neither. */
export function credentialResponse(body: Record<string, unknown>): CredentialResponse {
  const { credentials, transaction_id: transactionId } = body;
  const issued = Array.isArray(credentials) && credentials.length > 0 && credentials.every((c) => c && typeof c === 'object' && 'credential' in c);
  if (issued === (typeof transactionId === 'string')) {
    throw new IssuanceError('The credential response is not an OpenID4VCI 1.0 response: it must carry either credentials (a list of {credential}) or a transaction_id',
      'invalid_credential_response');
  }
  return body as CredentialResponse;
}

/**
 * Pairs each credential of a response with the holder key it is bound to: the response need not follow the order of
 * the proofs. A credential bound to a key this wallet did not send refuses the response, and so does a batch mixing
 * bound and bearer credentials; a further credential for a key already paired is dropped (counted in {@code dropped}).
 * Bearer credentials take the unused keys in order.
 */
export function bindInstances(format: string, credentials: unknown[], holders: Holder[], expectBound: boolean): { instances: CredentialInstance[]; dropped: number; error?: string } {
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
  if (!expectBound && credentials.length > 1) return { instances, dropped, error: 'The issuer sent several credentials although one was requested' };
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

/** Every instance is verified with its own key and against what was asked for; one bad instance refuses the batch. */
export async function verifyInstances(instances: CredentialInstance[], format: string, config: Record<string, unknown>, trust: TrustClient, bound: boolean): Promise<void> {
  const expected = expectedOf(config);
  for (const instance of instances) {
    instance.report = await verifyCredential(format, instance.credential, { trust, expected,
      ...(bound ? { holderJwk: instance.holderJwk, holderDid: instance.holderDid } : {}) });
  }
}

/** Why the verified instances of a response must be refused, if they must, with the report that shows it. */
export function refusal(primary: CredentialInstance, more: CredentialInstance[], confirmedUnknown: boolean): { reason: string; report: VerificationReport } | undefined {
  const differs = more.find((x) => !sameDataset(primary.report!.claims, x.report!.claims));
  const refused = differs ? { report: differs.report!, reason: 'The batch instances carry different claims; a batch must share one credential dataset (OID4VCI §3.3.2)' }
    : [primary, ...more].map((x) => ({ report: x.report!, reason: rejection(x.report!, confirmedUnknown) })).find((x) => x.reason);
  if (!refused) return undefined;
  return { report: refused.report, reason: more.length ? `${refused.reason} (one of ${more.length + 1} batch instances)` : refused.reason! };
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

/**
 * Why a freshly issued credential must be refused, if it must: it does not verify; its issuer is one the trust layer
 * refuses; its signing certificate chains to no trusted anchor (ISO 18013-5 §9.3.3 for the Document Signer, HAIP
 * §6.1.1 for SD-JWT VC: the signature then proves nothing); or its signer is unknown and the user did not agree to that.
 */
function rejection(r: VerificationReport, confirmedUnknown: boolean): string | undefined {
  if (!r.valid) {
    const failed = r.checks.filter((x) => x.status === 'fail' && x.id !== 'issuer.trust').map((x) => `${x.label}: ${x.detail ?? 'failed'}`);
    return `The credential failed verification (${failed.join('; ')})`;
  }
  const why = r.trust?.summary ?? 'no trust decision';
  if (r.trust?.decision === 'NOT_TRUSTED') return `The credential's issuer is not trusted (${why})`;
  if (r.trust?.decision === 'TRUSTED') return undefined;
  if (r.issuer.x5c?.length) return `The credential's signing certificate does not chain to a trusted anchor (${why})`;
  return confirmedUnknown ? undefined : `The credential is signed by ${r.issuer.issuer ?? 'an issuer'} unknown to the trust service (${why})`;
}
