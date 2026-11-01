/** JSON-LD document loader and RDF canonicalization (RDFC-1.0) with bundled contexts. */
import jsonld from 'jsonld';
import { BUNDLED_CONTEXTS } from './contexts.js';
import { createMessageDigest } from '../crypto/digest.js';

export interface LoaderStats {
  remote: Set<string>;
}

export function createDocumentLoader(f: typeof fetch, stats?: LoaderStats) {
  const cache = new Map<string, unknown>(Object.entries(BUNDLED_CONTEXTS));
  return async (url: string) => {
    const hit = cache.get(url) ?? cache.get(url.replace(/\/$/, ''));
    if (hit) return { contextUrl: null, documentUrl: url, document: hit };
    if (!url.startsWith('https://')) throw new Error(`Refusing to load non-https JSON-LD context ${url}`);
    const r = await f(url, { headers: { Accept: 'application/ld+json, application/json' } });
    if (!r.ok) throw new Error(`JSON-LD context ${url}: HTTP ${r.status}`);
    const document = await r.json();
    cache.set(url, document);
    stats?.remote.add(url);
    return { contextUrl: null, documentUrl: url, document };
  };
}

export type DocumentLoader = ReturnType<typeof createDocumentLoader>;

/** Canonical N-Quads; {@code safe} rejects documents whose terms would be silently dropped. */
export async function canonize(doc: object, documentLoader: DocumentLoader, safe = true): Promise<string> {
  return (jsonld.canonize as (d: object, o: object) => Promise<string>)(doc, {
    algorithm: 'RDFC-1.0', format: 'application/n-quads', documentLoader, safe,
    canonizeOptions: { createMessageDigest: () => createMessageDigest('sha256') },
  });
}
