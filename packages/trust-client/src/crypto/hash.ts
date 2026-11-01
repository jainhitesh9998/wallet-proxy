import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';

export type HashName = 'SHA-256' | 'SHA-384' | 'SHA-512';

export function digest(name: HashName, data: Uint8Array): Uint8Array {
  switch (name) {
    case 'SHA-256': return sha256(data);
    case 'SHA-384': return sha384(data);
    case 'SHA-512': return sha512(data);
  }
}

export { sha256 };
