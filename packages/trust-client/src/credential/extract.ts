/**
 * Extracts issuer identity material from a credential so that its issuer can be evaluated, per format:
 * mso_mdoc (IssuerSigned x5chain + MSO docType), dc+sd-jwt (x5c / kid / iss / vct), jwt_vc_json(-ld), ldp_vc.
 */
import { decode, mapGet, Tagged, unwrapEmbedded } from '../encoding/cbor.js';
import { base64Encode, base64UrlDecode } from '../util/bytes.js';
import { decodeJws } from '../jose/jws.js';
import type { TrustQuery } from '../types.js';

export interface IssuerInfo {
  format: string;
  /** DID or URL naming the issuer inside the credential (iss / issuer) */
  issuer?: string;
  /** key reference used to sign (DID URL from kid / verificationMethod) */
  kid?: string;
  /** issuing certificate chain, leaf first, base64 DER */
  x5c?: string[];
  /** doctype / vct / most specific VC type */
  credentialType?: string;
  types?: string[];
}

/** mdoc: accepts base64url IssuerSigned, a Document, a DeviceResponse, or a {docType, issuerSigned} wrapper. */
export function decodeIssuerSigned(input: string | Uint8Array): { issuerSigned: unknown; docType?: string } {
  let v = decode(typeof input === 'string' ? base64UrlDecode(input) : input);
  if (mapGet(v, 'documents')) v = (mapGet(v, 'documents') as unknown[])[0];
  const wrapperDocType = mapGet(v, 'docType') as string | undefined;
  if (mapGet(v, 'issuerSigned')) v = mapGet(v, 'issuerSigned');
  if (!mapGet(v, 'issuerAuth')) throw new Error('Not an mdoc IssuerSigned structure');
  return { issuerSigned: v, docType: wrapperDocType };
}

export interface CoseSign1 {
  protectedBytes: Uint8Array;
  protectedHeader: Map<unknown, unknown>;
  unprotectedHeader: Map<unknown, unknown>;
  payload: Uint8Array | null;
  signature: Uint8Array;
}

export function parseCoseSign1(v: unknown): CoseSign1 {
  const arr = (v instanceof Tagged ? v.value : v) as unknown[];
  if (!Array.isArray(arr) || arr.length !== 4) throw new Error('Not a COSE_Sign1');
  const protectedBytes = arr[0] as Uint8Array;
  const protectedHeader = protectedBytes.length ? (decode(protectedBytes) as Map<unknown, unknown>) : new Map();
  return { protectedBytes, protectedHeader, unprotectedHeader: (arr[1] as Map<unknown, unknown>) ?? new Map(),
    payload: (arr[2] as Uint8Array | null) ?? null, signature: arr[3] as Uint8Array };
}

export function coseX5chain(s: CoseSign1): Uint8Array[] {
  const x = s.unprotectedHeader.get(33) ?? s.protectedHeader.get(33);
  if (!x) return [];
  return Array.isArray(x) ? (x as Uint8Array[]) : [x as Uint8Array];
}

export function extractIssuerInfo(credential: unknown, format: string): IssuerInfo {
  switch (format) {
    case 'mso_mdoc': {
      const { issuerSigned, docType } = decodeIssuerSigned(credential as string);
      const auth = parseCoseSign1(mapGet(issuerSigned, 'issuerAuth'));
      let mso: unknown = auth.payload ? decode(auth.payload) : undefined;
      mso = mso instanceof Tagged ? unwrapEmbedded(mso) : mso;
      return { format, x5c: coseX5chain(auth).map(base64Encode), credentialType: (mapGet(mso, 'docType') as string) ?? docType };
    }
    case 'dc+sd-jwt':
    case 'vc+sd-jwt': {
      const jws = decodeJws(String(credential).split('~')[0]!);
      const x5c = Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : undefined;
      return { format: 'dc+sd-jwt', issuer: jws.payload.iss as string | undefined, kid: jws.header.kid as string | undefined, x5c,
        credentialType: jws.payload.vct as string | undefined };
    }
    case 'jwt_vc_json':
    case 'jwt_vc_json-ld': {
      const jws = decodeJws(String(credential));
      const vc = (jws.payload.vc as Record<string, unknown>) ?? jws.payload;
      const issuer = (jws.payload.iss as string) ?? issuerId(vc.issuer);
      const types = (vc.type as string[]) ?? [];
      const kid = jws.header.kid as string | undefined;
      return { format, issuer, kid: kid && kid.startsWith('#') && issuer ? issuer + kid : kid,
        x5c: Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : undefined, types, credentialType: mostSpecific(types) };
    }
    case 'ldp_vc': {
      const vc = (typeof credential === 'string' ? JSON.parse(credential) : credential) as Record<string, unknown>;
      const proofs = Array.isArray(vc.proof) ? vc.proof : vc.proof ? [vc.proof] : [];
      const types = (Array.isArray(vc.type) ? vc.type : [vc.type]).filter(Boolean) as string[];
      return { format, issuer: issuerId(vc.issuer), kid: (proofs[0] as Record<string, unknown> | undefined)?.verificationMethod as string | undefined,
        types, credentialType: mostSpecific(types) };
    }
    default:
      throw new Error(`Unsupported credential format ${format}`);
  }
}

function issuerId(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object') return (v as { id?: string }).id;
  return undefined;
}

const GENERIC_TYPES = new Set(['VerifiableCredential', 'VerifiableAttestation']);

function mostSpecific(types: string[]): string | undefined {
  return types.find((t) => !GENERIC_TYPES.has(t)) ?? types[0];
}

/**
 * Builds the issuer trust query for a credential. The identifier inside the credential ({@code issuer} /
 * {@code iss}) takes precedence so that a credential cannot borrow trust from the endpoint that delivered it;
 * {@code credentialIssuer} (the OpenID4VCI issuer) is used when the credential names no issuer (mdoc).
 */
export function issuerTrustQuery(info: IssuerInfo, credentialIssuer?: string, protocol = 'oid4vci'): TrustQuery {
  return {
    role: 'issuer',
    // Only the key the signature is verified with: the x5c leaf when there is one (SD-JWT VC, JWT VC), else the DID key.
    subject: { identifier: info.issuer ?? credentialIssuer, x5c: info.x5c,
      kid: !info.x5c?.length && info.kid?.startsWith('did:') ? info.kid : undefined },
    // A W3C VC asserts all its types: each specific one must be authorized, not only the first.
    context: { protocol, credentialFormat: info.format, credentialType: info.credentialType,
      ...(info.types && info.types.filter((t) => !GENERIC_TYPES.has(t)).length > 1 ? { credentialTypes: info.types.filter((t) => !GENERIC_TYPES.has(t)) } : {}) },
  };
}
