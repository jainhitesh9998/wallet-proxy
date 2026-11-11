/**
 * Holder keys in a credential request (OID4VCI §8.2, Appendix F): how a configuration binds credentials to a key,
 * the DID such a key goes by, and the proofs of possession — jwt proofs, with a key attestation when asked for, or
 * attestation proofs.
 */
import type { Jwk } from '@vctrust/trust-client';
import { bytes, base58Encode, writeVarint, MULTICODEC } from '@vctrust/trust-client/primitives';
import { p256 } from '@noble/curves/nist.js';
import { nowSeconds, signJwt } from '../crypto/jwt.js';
import type { SigningKey } from '../crypto/keys.js';
import type { WalletAttester } from '../oauth/attestation.js';
import { IssuanceError, type Oid4vciOptions } from './types.js';

/** A freshly created holder key and the DID it is bound with, if the configuration binds to a DID. */
export interface Holder {
  key: SigningKey;
  did?: string;
}

/** Whom a jwt proof is for (the Credential Issuer) and whom it is from (the client_id; none with anonymous access). */
export interface ProofParties {
  aud: string;
  iss?: string;
}

type ProofOptions = Pick<Oid4vciOptions, 'attester' | 'keyAttestation'>;

/** The binding methods of a configuration; none means its credentials are not bound to a key (§12.2.4). */
export function bindingMethods(config: Record<string, unknown>): string[] {
  const m = config.cryptographic_binding_methods_supported;
  return Array.isArray(m) ? m.filter((x): x is string => typeof x === 'string') : [];
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

/**
 * The proofs member (OID4VCI §8.2, Appendix F) for one or more holder keys (a batch): {@code jwt} proofs signed
 * with ES256 (it must be among the issuer's proof_signing_alg_values_supported), or — when the issuer accepts only
 * key attestations — an {@code attestation} proof: one key attestation of all the keys, bound to the c_nonce.
 */
export async function keyProofs(holders: Holder[], config: Record<string, unknown>, nonce: string | undefined, parties: ProofParties,
                                opts: ProofOptions): Promise<Record<string, string[]>> {
  const types = config.proof_types_supported as Record<string, Record<string, unknown>> | undefined;
  // §12.2.4: proof_types_supported is present whenever the configuration names binding methods.
  if (!types || typeof types !== 'object') throw new IssuanceError('The configuration binds credentials to a key but names no proof_types_supported', 'invalid_issuer_metadata');
  const algsOk = (t?: Record<string, unknown>) => Array.isArray(t?.proof_signing_alg_values_supported) && (t!.proof_signing_alg_values_supported as unknown[]).includes('ES256');
  const attested = () => opts.attester!.keyAttestation(holders.map((h) => h.key.publicJwk), nonce);
  if (types.jwt && algsOk(types.jwt)) return { jwt: await jwtProofs(holders, config, nonce, parties, opts) };
  if (types.attestation && opts.attester && algsOk(types.attestation)) {
    checkKeyProtection(types.attestation, opts.attester);
    return { attestation: [await attested()] };
  }
  if (types.jwt) throw new IssuanceError(`The issuer accepts jwt proofs signed with ${JSON.stringify(types.jwt.proof_signing_alg_values_supported)}; this wallet signs with ES256`, 'invalid_proof');
  if (types.attestation) {
    if (!opts.attester) throw new IssuanceError('The issuer accepts only key attestation proofs and no wallet provider is configured', 'key_attestation_required');
    if (!algsOk(types.attestation)) throw new IssuanceError('The issuer does not accept ES256 key attestations', 'invalid_proof');
    checkKeyProtection(types.attestation, opts.attester);
    return { attestation: [await attested()] };
  }
  throw new IssuanceError(`No supported proof type (issuer offers ${Object.keys(types).join(', ')})`, 'invalid_proof');
}

/**
 * jwt proofs: one per key, or — with a key attestation — a single proof by the first key whose attestation lists
 * every key of the batch (HAIP §4.5.1; the issuer then issues one credential per attested key, OID4VCI F.1).
 */
async function jwtProofs(holders: Holder[], config: Record<string, unknown>, nonce: string | undefined, parties: ProofParties, opts: ProofOptions): Promise<string[]> {
  const jwtProof = (config.proof_types_supported as Record<string, Record<string, unknown>> | undefined)?.jwt;
  const ka = opts.keyAttestation ?? 'auto';
  const required = jwtProof?.key_attestations_required as { key_storage?: string[]; user_authentication?: string[] } | undefined;
  if (required && !opts.attester) throw new IssuanceError('Issuer requires a key attestation but no wallet provider is configured', 'key_attestation_required');
  checkKeyProtection(jwtProof, opts.attester);
  if (opts.attester && ka !== 'never' && (ka === 'always' || required)) {
    const attestation = await opts.attester.keyAttestation(holders.map((h) => h.key.publicJwk), nonce);
    return [await signProof(holders[0]!, nonce, parties, attestation)];
  }
  return Promise.all(holders.map((h) => signProof(h, nonce, parties)));
}

/** Refuses before the request when the issuer demands stronger key storage / user authentication than attested. */
function checkKeyProtection(proofType: Record<string, unknown> | undefined, attester: WalletAttester | undefined): void {
  const required = proofType?.key_attestations_required as { key_storage?: string[]; user_authentication?: string[] } | undefined;
  if (!required || !attester) return;
  const caps = attester.capabilities;
  const missing = (want: string[] | undefined, have: string[]) => want?.length && !want.some((w) => have.includes(w));
  if (missing(required.key_storage, caps.keyStorage) || missing(required.user_authentication, caps.userAuthentication)) {
    throw new IssuanceError(`Issuer requires key storage ${JSON.stringify(required.key_storage ?? [])} / user authentication `
      + `${JSON.stringify(required.user_authentication ?? [])}; this wallet attests ${JSON.stringify(caps)}`, 'insufficient_key_protection');
  }
}

async function signProof(holder: Holder, nonce: string | undefined, parties: ProofParties, keyAttestation?: string): Promise<string> {
  const header: Record<string, unknown> = { typ: 'openid4vci-proof+jwt' };
  const did = holder.did;
  if (did) header.kid = did.startsWith('did:jwk:') ? `${did}#0` : `${did}#${did.slice('did:key:'.length)}`;
  else header.jwk = holder.key.publicJwk;
  if (keyAttestation) header.key_attestation = keyAttestation;
  const payload: Record<string, unknown> = { aud: parties.aud, iat: nowSeconds() };
  if (nonce) payload.nonce = nonce;
  if (parties.iss) payload.iss = parties.iss;
  return signJwt(header, payload, holder.key);
}
