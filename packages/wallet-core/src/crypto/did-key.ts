/** DIDs that are a public key themselves. */
import type { Jwk } from '@vctrust/trust-client';
import { bytes, decodeMultibase, publicKeyFromMulticodec, publicKeyToJwk } from '@vctrust/trust-client/primitives';

/** The public key a did:jwk or did:key (or a DID URL of one) names, read without resolution; undefined for other DIDs. */
export function didPublicKey(did: string): Jwk | undefined {
  const id = did.split('#')[0]!;
  try {
    if (id.startsWith('did:key:')) return publicKeyToJwk(publicKeyFromMulticodec(decodeMultibase(id.slice('did:key:'.length))));
    if (!id.startsWith('did:jwk:')) return undefined;
    const jwk = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(id.slice('did:jwk:'.length)))) as Jwk;
    return typeof jwk.kty === 'string' && !('d' in jwk) ? jwk : undefined;
  } catch {
    return undefined;
  }
}
