/** X.509 certificate parsing with a small DER reader (no ASN.1 schema library, React Native friendly). */
import { children, readTlv, slice, type Tlv } from '../encoding/der.js';
import { base64Decode, base64Encode, base64UrlEncode, toHex, utf8Decode } from '../util/bytes.js';
import { sha256 } from '../crypto/hash.js';
import { ecPoint, type EcCurve, type PublicKey } from '../crypto/keys.js';
import { bytesToBigInt } from '../util/bytes.js';

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  signatureAlgorithm: string;
  signatureParams?: Uint8Array;
  signature: Uint8Array;
  serialNumber: string;
  issuer: string;
  subject: string;
  issuerRaw: Uint8Array;
  subjectRaw: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  publicKey: PublicKey | null;
  publicKeyAlgorithm: string;
  basicConstraints?: { ca: boolean; pathLen?: number };
  keyUsage?: KeyUsage;
  extendedKeyUsage: string[];
  subjectKeyIdentifier?: string;
  authorityKeyIdentifier?: string;
  dnsNames: string[];
  uriNames: string[];
  /** base64url SHA-256 of the DER encoding (OpenID4VP x509_hash) */
  sha256: string;
  criticalExtensions: string[];
}

export interface KeyUsage {
  digitalSignature: boolean;
  nonRepudiation: boolean;
  keyEncipherment: boolean;
  dataEncipherment: boolean;
  keyAgreement: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
}

export const OID = {
  ecPublicKey: '1.2.840.10045.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  ed25519: '1.3.101.112',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  p521: '1.3.132.0.35',
  secp256k1: '1.3.132.0.10',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  subjectKeyIdentifier: '2.5.29.14',
  authorityKeyIdentifier: '2.5.29.35',
  subjectAltName: '2.5.29.17',
  issuerAltName: '2.5.29.18',
  mdlDocumentSigner: '1.0.18013.5.1.2',
} as const;

const NAME_ATTRS: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'SERIALNUMBER', '2.5.4.97': 'organizationIdentifier', '1.2.840.113549.1.9.1': 'E',
  '0.9.2342.19200300.100.1.25': 'DC', '2.5.4.9': 'STREET', '2.5.4.42': 'GN', '2.5.4.4': 'SN',
};

export function decodeOid(bytes: Uint8Array): string {
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < bytes.length; i++) {
    v = v * 128 + (bytes[i]! & 0x7f);
    if (!(bytes[i]! & 0x80)) {
      if (parts.length === 0) {
        const first = v < 80 ? Math.floor(v / 40) : 2;
        parts.push(first, v - first * 40);
      } else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

function value(data: Uint8Array, t: Tlv): Uint8Array {
  return data.subarray(t.valueStart, t.end);
}

function decodeString(data: Uint8Array, t: Tlv): string {
  const v = value(data, t);
  if (t.tag === 0x1e) {
    let s = '';
    for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i]! << 8) | v[i + 1]!);
    return s;
  }
  return utf8Decode(v);
}

function parseName(data: Uint8Array, t: Tlv): string {
  const rdns: string[] = [];
  for (const set of children(data, t)) {
    const attrs: string[] = [];
    for (const atv of children(data, set)) {
      const [oidT, valT] = children(data, atv) as [Tlv, Tlv];
      const oid = decodeOid(value(data, oidT));
      attrs.push(`${NAME_ATTRS[oid] ?? oid}=${decodeString(data, valT)}`);
    }
    rdns.push(attrs.join('+'));
  }
  // RFC 4514 order: most specific RDN first.
  return rdns.reverse().join(',');
}

function parseTime(data: Uint8Array, t: Tlv): Date {
  const s = utf8Decode(value(data, t));
  if (t.tag === 0x17) {
    const yy = parseInt(s.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, parseInt(s.slice(2, 4), 10) - 1, parseInt(s.slice(4, 6), 10),
      parseInt(s.slice(6, 8), 10), parseInt(s.slice(8, 10), 10), parseInt(s.slice(10, 12), 10)));
  }
  return new Date(Date.UTC(parseInt(s.slice(0, 4), 10), parseInt(s.slice(4, 6), 10) - 1, parseInt(s.slice(6, 8), 10),
    parseInt(s.slice(8, 10), 10), parseInt(s.slice(10, 12), 10), parseInt(s.slice(12, 14), 10)));
}

function parseSpki(data: Uint8Array, t: Tlv): { key: PublicKey | null; alg: string } {
  const [algT, bitsT] = children(data, t) as [Tlv, Tlv];
  const algParts = children(data, algT);
  const alg = decodeOid(value(data, algParts[0]!));
  const bits = value(data, bitsT).subarray(1);
  try {
    if (alg === OID.ecPublicKey && algParts[1]?.tag === 0x06) {
      const curveOid = decodeOid(value(data, algParts[1]));
      const crv: EcCurve | undefined = curveOid === OID.p256 ? 'P-256' : curveOid === OID.p384 ? 'P-384'
        : curveOid === OID.p521 ? 'P-521' : curveOid === OID.secp256k1 ? 'secp256k1' : undefined;
      return { key: crv ? { kty: 'EC', crv, point: ecPoint(crv, bits) } : null, alg };
    }
    if (alg === OID.ed25519) return { key: { kty: 'OKP', crv: 'Ed25519', x: bits }, alg };
    if (alg === OID.rsaEncryption) {
      const seq = readTlv(bits, 0);
      const [nT, eT] = children(bits, seq) as [Tlv, Tlv];
      return { key: { kty: 'RSA', n: bytesToBigInt(value(bits, nT)), e: bytesToBigInt(value(bits, eT)) }, alg };
    }
  } catch {
    return { key: null, alg };
  }
  return { key: null, alg };
}

export function parseCertificate(input: Uint8Array | string): Certificate {
  const der = typeof input === 'string' ? decodeCertificateText(input) : input;
  const root = readTlv(der, 0);
  const [tbsT, sigAlgT, sigT] = children(der, root) as [Tlv, Tlv, Tlv];
  const tbsParts = children(der, tbsT);
  let i = 0;
  if (tbsParts[0]!.tag === 0xa0) i++;
  const serialT = tbsParts[i++]!;
  i++; // signature algorithm (inner)
  const issuerT = tbsParts[i++]!;
  const validityT = tbsParts[i++]!;
  const subjectT = tbsParts[i++]!;
  const spkiT = tbsParts[i++]!;
  const [nbT, naT] = children(der, validityT) as [Tlv, Tlv];
  const sigAlgParts = children(der, sigAlgT);
  const spki = parseSpki(der, spkiT);
  const cert: Certificate = {
    der,
    tbs: slice(der, tbsT),
    signatureAlgorithm: decodeOid(value(der, sigAlgParts[0]!)),
    signatureParams: sigAlgParts[1] && sigAlgParts[1].tag !== 0x05 ? slice(der, sigAlgParts[1]) : undefined,
    signature: value(der, sigT).subarray(1),
    serialNumber: toHex(value(der, serialT)),
    issuer: parseName(der, issuerT),
    subject: parseName(der, subjectT),
    issuerRaw: slice(der, issuerT),
    subjectRaw: slice(der, subjectT),
    notBefore: parseTime(der, nbT),
    notAfter: parseTime(der, naT),
    publicKey: spki.key,
    publicKeyAlgorithm: spki.alg,
    extendedKeyUsage: [],
    dnsNames: [],
    uriNames: [],
    sha256: base64UrlEncode(sha256(der)),
    criticalExtensions: [],
  };
  const extWrapper = tbsParts.slice(i).find((t) => t.tag === 0xa3);
  if (extWrapper) {
    const extSeq = children(der, extWrapper)[0]!;
    for (const ext of children(der, extSeq)) {
      const parts = children(der, ext);
      const oid = decodeOid(value(der, parts[0]!));
      const critical = parts.length === 3 && parts[1]!.tag === 0x01 && value(der, parts[1]!)[0] !== 0;
      const octets = value(der, parts[parts.length - 1]!);
      if (critical) cert.criticalExtensions.push(oid);
      parseExtension(cert, oid, octets);
    }
  }
  return cert;
}

function parseExtension(cert: Certificate, oid: string, d: Uint8Array): void {
  const t = readTlv(d, 0);
  switch (oid) {
    case OID.basicConstraints: {
      const parts = children(d, t);
      let ca = false;
      let pathLen: number | undefined;
      for (const p of parts) {
        if (p.tag === 0x01) ca = value(d, p)[0] !== 0;
        if (p.tag === 0x02) pathLen = Number(bytesToBigInt(value(d, p)));
      }
      cert.basicConstraints = { ca, pathLen };
      break;
    }
    case OID.keyUsage: {
      const v = value(d, t);
      const b0 = v[1] ?? 0;
      const b1 = v[2] ?? 0;
      cert.keyUsage = {
        digitalSignature: !!(b0 & 0x80), nonRepudiation: !!(b0 & 0x40), keyEncipherment: !!(b0 & 0x20),
        dataEncipherment: !!(b0 & 0x10), keyAgreement: !!(b0 & 0x08), keyCertSign: !!(b0 & 0x04), cRLSign: !!(b0 & 0x02),
      };
      void b1;
      break;
    }
    case OID.extKeyUsage:
      cert.extendedKeyUsage = children(d, t).map((p) => decodeOid(value(d, p)));
      break;
    case OID.subjectKeyIdentifier:
      cert.subjectKeyIdentifier = base64UrlEncode(value(d, t));
      break;
    case OID.authorityKeyIdentifier: {
      const kid = children(d, t).find((p) => p.tag === 0x80);
      if (kid) cert.authorityKeyIdentifier = base64UrlEncode(value(d, kid));
      break;
    }
    case OID.subjectAltName:
      for (const gn of children(d, t)) {
        if (gn.tag === 0x82) cert.dnsNames.push(utf8Decode(value(d, gn)));
        if (gn.tag === 0x86) cert.uriNames.push(utf8Decode(value(d, gn)));
      }
      break;
    default:
  }
}

/** Accepts PEM, base64 or base64url DER. */
export function decodeCertificateText(text: string): Uint8Array {
  const m = text.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
  return base64Decode(m ? m[1]! : text);
}

export function certificateToBase64(cert: Certificate): string {
  return base64Encode(cert.der);
}

export function subjectCountry(name: string): string | undefined {
  const m = name.match(/(?:^|,)C=([^,+]+)/);
  return m?.[1];
}
