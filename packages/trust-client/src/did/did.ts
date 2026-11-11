/** DID parsing, document dereferencing and verification relationship checks. */
import type { DidDocument, DidResolutionResult, VerificationMethod } from '../types.js';

export interface ParsedDid {
  did: string;
  method: string;
  id: string;
  fragment?: string;
}

const DID_RE = /^did:([a-z0-9]+):((?:[A-Za-z0-9._\-]|%[0-9A-Fa-f]{2}|:)*(?:[A-Za-z0-9._\-]|%[0-9A-Fa-f]{2}))(?:[/?][^#]*)?(?:#(.*))?$/;

export function parseDid(didUrl: string): ParsedDid {
  const m = DID_RE.exec(didUrl);
  if (!m) throw new Error(`Invalid DID: ${didUrl}`);
  return { did: `did:${m[1]}:${m[2]}`, method: m[1]!, id: m[2]!, fragment: m[3] };
}

export const DID_ERRORS = {
  INVALID_DID: 'INVALID_DID',
  NOT_FOUND: 'NOT_FOUND',
  METHOD_NOT_SUPPORTED: 'METHOD_NOT_SUPPORTED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  INVALID_DID_DOCUMENT: 'INVALID_DID_DOCUMENT',
} as const;

const LEGACY: Record<string, string> = {
  invalidDid: 'INVALID_DID', notFound: 'NOT_FOUND', methodNotSupported: 'METHOD_NOT_SUPPORTED',
  internalError: 'INTERNAL_ERROR', invalidDidDocument: 'INVALID_DID_DOCUMENT', representationNotSupported: 'REPRESENTATION_NOT_SUPPORTED',
};

/** Error code of a resolution result: RFC 9457 problem types or legacy camelCase strings. */
export function didError(r: DidResolutionResult): string | undefined {
  const e = r.didResolutionMetadata?.error;
  if (!e) return undefined;
  let code = typeof e === 'string' ? e : String((e as { type?: string; title?: string }).type ?? (e as { title?: string }).title ?? '');
  code = code.replace('https://www.w3.org/ns/did#', '');
  return LEGACY[code] ?? code;
}

export function didErrorResult(code: string, detail?: string): DidResolutionResult {
  return {
    didDocument: null,
    didResolutionMetadata: { error: { type: `https://www.w3.org/ns/did#${code}`, title: code, detail } },
    didDocumentMetadata: {},
  };
}

function absolute(docId: string, ref: string): string {
  return ref.startsWith('#') ? docId + ref : ref;
}

function allMethods(doc: DidDocument): VerificationMethod[] {
  const out: VerificationMethod[] = [...(doc.verificationMethod ?? [])];
  for (const rel of ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation']) {
    const v = doc[rel];
    if (Array.isArray(v)) for (const e of v) if (e && typeof e === 'object') out.push(e as VerificationMethod);
  }
  return out;
}

export function findVerificationMethod(doc: DidDocument, didUrl: string): VerificationMethod | undefined {
  const target = absolute(doc.id, didUrl);
  return allMethods(doc).find((vm) => absolute(doc.id, vm.id) === target);
}

/** Whether the verification method is listed in a verification relationship, by reference or embedded (DID Core §5.3). */
export function hasRelationship(doc: DidDocument, relationship: string, didUrl: string): boolean {
  const target = absolute(doc.id, didUrl);
  const rel = doc[relationship];
  if (!Array.isArray(rel)) return false;
  return rel.some((e) => {
    const ref = typeof e === 'string' ? e : (e as VerificationMethod)?.id;
    return !!ref && absolute(doc.id, ref) === target;
  });
}
