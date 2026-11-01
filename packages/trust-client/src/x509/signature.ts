/** Signature algorithm identifiers of X.509 certificates and CRLs, and verification of their signatures. */
import { readTlv } from '../encoding/der.js';
import { verifySignature, type JoseAlg } from '../crypto/verify.js';
import type { PublicKey } from '../crypto/keys.js';
import { decodeOid } from './certificate.js';

export interface SignedX509 {
  tbs: Uint8Array;
  signature: Uint8Array;
  signatureAlgorithm: string;
  signatureParams?: Uint8Array;
}

export function x509SignatureAlg(oid: string, params?: Uint8Array): { alg: JoseAlg; format: 'raw' | 'der' } | null {
  switch (oid) {
    case '1.2.840.10045.4.3.2': return { alg: 'ES256', format: 'der' };
    case '1.2.840.10045.4.3.3': return { alg: 'ES384', format: 'der' };
    case '1.2.840.10045.4.3.4': return { alg: 'ES512', format: 'der' };
    case '1.3.101.112': return { alg: 'EdDSA', format: 'raw' };
    case '1.2.840.113549.1.1.11': return { alg: 'RS256', format: 'raw' };
    case '1.2.840.113549.1.1.12': return { alg: 'RS384', format: 'raw' };
    case '1.2.840.113549.1.1.13': return { alg: 'RS512', format: 'raw' };
    case '1.2.840.113549.1.1.10': {
      let hash: JoseAlg = 'PS256';
      if (params) {
        const oids = findOids(params);
        if (oids.includes('2.16.840.1.101.3.4.2.2')) hash = 'PS384';
        else if (oids.includes('2.16.840.1.101.3.4.2.3')) hash = 'PS512';
      }
      return { alg: hash, format: 'raw' };
    }
    default: return null;
  }
}

/** Verifies a certificate's or CRL's signature with the issuer's public key. */
export function verifyX509Signature(signed: SignedX509, issuerKey: PublicKey | null): boolean {
  const a = x509SignatureAlg(signed.signatureAlgorithm, signed.signatureParams);
  if (!a || !issuerKey) return false;
  return verifySignature(a.alg, issuerKey, signed.tbs, signed.signature, a.format);
}

function findOids(der: Uint8Array): string[] {
  const out: string[] = [];
  const walk = (start: number, end: number) => {
    let p = start;
    while (p < end) {
      const t = readTlv(der, p);
      if (t.tag === 0x06) out.push(decodeOid(der.subarray(t.valueStart, t.end)));
      else if (t.tag & 0x20) walk(t.valueStart, t.end);
      p = t.end;
    }
  };
  try { walk(0, der.length); } catch { /* ignore */ }
  return out;
}
