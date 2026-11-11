import { sha256 } from '@noble/hashes/sha2.js';
import { bytes } from '@vctrust/trust-client/primitives';

export interface Pkce {
  verifier: string;
  challenge: string;
  method: 'S256';
}

export function createPkce(): Pkce {
  const verifier = bytes.base64UrlEncode(bytes.randomBytes(32));
  return { verifier, challenge: bytes.base64UrlEncode(sha256(bytes.utf8Encode(verifier))), method: 'S256' };
}
