/** Public keys from DID verification methods (JsonWebKey, Multikey, Ed25519 2018/2020). */
import { base58Decode, MULTICODEC, readVarint } from './multibase.js';
import { publicKeyFromJwk, publicKeyToJwk, ecPoint, type Jwk, type PublicKey } from '../crypto/keys.js';
import { base64UrlDecode, utf8Decode } from '../util/bytes.js';
import type { VerificationMethod } from '../types.js';

export function decodeMultibase(mb: string): Uint8Array {
  if (mb.startsWith('z')) return base58Decode(mb.slice(1));
  if (mb.startsWith('u')) return base64UrlDecode(mb.slice(1));
  throw new Error(`Unsupported multibase prefix ${mb[0]}`);
}

/** Decodes a multicodec-prefixed public key (Multikey / did:key). */
export function publicKeyFromMulticodec(bytes: Uint8Array): PublicKey {
  const { codec, payload } = readVarint(bytes);
  switch (codec) {
    case MULTICODEC.ed25519: return { kty: 'OKP', crv: 'Ed25519', x: payload };
    case MULTICODEC.p256: return { kty: 'EC', crv: 'P-256', point: ecPoint('P-256', payload) };
    case MULTICODEC.p384: return { kty: 'EC', crv: 'P-384', point: ecPoint('P-384', payload) };
    case MULTICODEC.secp256k1: return { kty: 'EC', crv: 'secp256k1', point: ecPoint('secp256k1', payload) };
    case MULTICODEC.jwkJcs: return publicKeyFromJwk(JSON.parse(utf8Decode(payload)) as Jwk);
    default: throw new Error(`Unsupported multicodec 0x${codec.toString(16)}`);
  }
}

export function verificationMethodPublicKey(vm: VerificationMethod): PublicKey {
  if (vm.publicKeyJwk) return publicKeyFromJwk(vm.publicKeyJwk);
  if (vm.publicKeyMultibase) {
    const raw = decodeMultibase(vm.publicKeyMultibase);
    // Ed25519VerificationKey2020 and Multikey both carry a multicodec header; tolerate bare 32-byte keys.
    if ((vm.type === 'Ed25519VerificationKey2020' || vm.type === 'Ed25519VerificationKey2018') && raw.length === 32) {
      return { kty: 'OKP', crv: 'Ed25519', x: raw };
    }
    return publicKeyFromMulticodec(raw);
  }
  if (vm.publicKeyBase58) {
    const raw = base58Decode(vm.publicKeyBase58);
    if (vm.type.startsWith('Ed25519')) return { kty: 'OKP', crv: 'Ed25519', x: raw };
    if (vm.type.startsWith('EcdsaSecp256k1')) return { kty: 'EC', crv: 'secp256k1', point: ecPoint('secp256k1', raw) };
  }
  throw new Error(`Unsupported verification method ${vm.type}`);
}

export function verificationMethodJwk(vm: VerificationMethod): Jwk {
  return vm.publicKeyJwk ?? publicKeyToJwk(verificationMethodPublicKey(vm));
}

export function samePublicKey(a: PublicKey, b: PublicKey): boolean {
  const ja = publicKeyToJwk(a);
  const jb = publicKeyToJwk(b);
  return ja.kty === jb.kty && ja.crv === jb.crv && ja.x === jb.x && ja.y === jb.y && ja.n === jb.n && ja.e === jb.e;
}
