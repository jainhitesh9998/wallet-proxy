/**
 * JSON-LD contexts and RDF canonicalization (RDFC-1.0).
 *
 * A context decides which statements a Data Integrity signature covers, so a verifier must know the contexts it
 * processes (VC Data Integrity 1.0 §2.4.1 "Validating Contexts"). The wallet uses the contexts built into it and,
 * for everything else, the trust client: a context the trust service vouches for comes from the signed snapshot (or
 * is checked against the digest it carries); one it does not know is fetched from its own https host and recorded,
 * so the verification report can say so.
 */
import jsonld from 'jsonld';
import type { TrustClient } from '@vctrust/trust-client';
import { BUNDLED_CONTEXTS } from './contexts.js';
import { createMessageDigest } from '../crypto/digest.js';

export interface LoaderStats {
  /** contexts used that neither the wallet nor the trust service vouches for */
  unvouched: Set<string>;
}

export type DocumentLoader = (url: string) => Promise<{ contextUrl: null; documentUrl: string; document: unknown }>;

export function createDocumentLoader(trust?: Pick<TrustClient, 'context'>, stats?: LoaderStats): DocumentLoader {
  const bundled = BUNDLED_CONTEXTS as Record<string, unknown>;
  return async (url: string) => {
    if (Object.prototype.hasOwnProperty.call(bundled, url)) return { contextUrl: null, documentUrl: url, document: bundled[url] };
    if (!trust) throw new Error(`JSON-LD context ${url} is not built into the wallet`);
    const context = await trust.context(url);
    if (!context.vouched) stats?.unvouched.add(url);
    return { contextUrl: null, documentUrl: url, document: context.document };
  };
}

/**
 * Canonical N-Quads. Always in safe mode: a term the contexts do not define, a relative IRI or any other construct
 * that would be dropped silently (and so left out of the signature) is an error.
 */
export async function canonize(doc: object, documentLoader: DocumentLoader): Promise<string> {
  return (jsonld.canonize as (d: object, o: object) => Promise<string>)(doc, {
    algorithm: 'RDFC-1.0', format: 'application/n-quads', documentLoader, safe: true,
    canonizeOptions: { createMessageDigest: () => createMessageDigest('sha256') },
  });
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
/** JSON-LD treats a single value and a list of one alike; so does this comparison. */
const single = (v: unknown): unknown => (Array.isArray(v) && v.length === 1 ? single(v[0]) : v);

function difference(a: unknown, b: unknown, path: string): string | undefined {
  [a, b] = [single(a), single(b)];
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return path || '(document)';
    for (let i = 0; i < a.length; i++) {
      const d = difference(a[i], b[i], `${path}[${i}]`);
      if (d) return d;
    }
    return undefined;
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return path || '(document)';
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!path && k === '@context') continue;
      if (!Object.prototype.hasOwnProperty.call(a, k) || !Object.prototype.hasOwnProperty.call(b, k)) return path ? `${path}.${k}` : k;
      const d = difference(a[k], b[k], path ? `${path}.${k}` : k);
      if (d) return d;
    }
    return undefined;
  }
  return a === b ? undefined : path || '(document)';
}

/**
 * Whether a document is written in the terms of its own contexts: compacted against them, it comes back as it is.
 *
 * A Data Integrity signature covers the statements a document makes (its RDF), while a wallet reads the document as
 * JSON, by member name. The same statement can be written under another name: an absolute IRI instead of the
 * context's term, a value object instead of a plain value. Such a member is signed, and a reader that looks for
 * `validUntil` or `credentialStatus` does not see it. A document in compact form has one spelling for each
 * statement, the one the reader looks for.
 *
 * @returns the path of the first member that is not in compact form, or undefined when the document is
 */
export async function notCompact(doc: Record<string, unknown>, documentLoader: DocumentLoader): Promise<string | undefined> {
  const compacted = await (jsonld.compact as (d: object, c: object, o: object) => Promise<Record<string, unknown>>)(doc, { '@context': doc['@context'] },
    { documentLoader, safe: true });
  return difference(doc, compacted, '');
}
