/** Message digest factory for rdf-canonize that does not depend on platform crypto (React Native safe). */
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { bytes } from '@vctrust/trust-client';

export function createMessageDigest(algorithm = 'sha256') {
  const h = /384/.test(algorithm) ? sha384.create() : sha256.create();
  return {
    update(msg: string) { h.update(bytes.utf8Encode(msg)); },
    digest() { return bytes.toHex(h.digest()); },
  };
}
