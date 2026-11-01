/** X.509 CRL (RFC 5280 §5) parsing with the same small DER reader as certificates. */
import { children, readTlv, slice, type Tlv } from '../encoding/der.js';
import { base64Decode, base64UrlEncode, bytesToBigInt, toHex } from '../util/bytes.js';
import { decodeOid, distributionPointUris, OID, parseName, parseTime } from './certificate.js';

export interface CrlEntry {
  revokedAt: Date;
  /** CRLReason (RFC 5280 §5.3.1); absent = unspecified */
  reason?: number;
  /** the entry names another certificate issuer (indirect CRL) */
  certificateIssuer: boolean;
}

export interface IssuingDistributionPoint {
  uris: string[];
  onlyContainsUserCerts: boolean;
  onlyContainsCACerts: boolean;
  onlySomeReasons: boolean;
  indirectCRL: boolean;
  onlyContainsAttributeCerts: boolean;
}

export interface Crl {
  der: Uint8Array;
  tbs: Uint8Array;
  signatureAlgorithm: string;
  signatureParams?: Uint8Array;
  signature: Uint8Array;
  issuer: string;
  issuerRaw: Uint8Array;
  thisUpdate: Date;
  nextUpdate?: Date;
  /** revoked serial numbers (lowercase hex, no leading zeros) */
  entries: Map<string, CrlEntry>;
  crlNumber?: string;
  authorityKeyIdentifier?: string;
  issuingDistributionPoint?: IssuingDistributionPoint;
  /** deltaCRLIndicator present */
  delta: boolean;
  /** critical CRL extensions this parser does not understand */
  unsupportedCritical: string[];
}

export const CRL_OID = {
  crlNumber: '2.5.29.20',
  reasonCode: '2.5.29.21',
  deltaCrlIndicator: '2.5.29.27',
  issuingDistributionPoint: '2.5.29.28',
  certificateIssuer: '2.5.29.29',
  freshestCrl: '2.5.29.46',
} as const;

const KNOWN_CRL_EXTENSIONS = new Set<string>([CRL_OID.crlNumber, OID.authorityKeyIdentifier, CRL_OID.issuingDistributionPoint,
  CRL_OID.freshestCrl, CRL_OID.deltaCrlIndicator]);

/** RFC 5280 CRLReason names, as used in revocation evidence. */
export const CRL_REASONS: Record<number, string> = {
  0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise', 3: 'affiliationChanged', 4: 'superseded', 5: 'cessationOfOperation',
  6: 'certificateHold', 8: 'removeFromCRL', 9: 'privilegeWithdrawn', 10: 'aACompromise',
};

/** Serial numbers as compared across certificates and CRLs: lowercase hex without leading zeros. */
export function normalizeSerial(hex: string): string {
  return BigInt(`0x${hex || '0'}`).toString(16);
}

const value = (d: Uint8Array, t: Tlv) => d.subarray(t.valueStart, t.end);
const isTime = (t?: Tlv) => t?.tag === 0x17 || t?.tag === 0x18;

/** Accepts DER, PEM ("X509 CRL") or base64. */
export function parseCrl(input: Uint8Array | string): Crl {
  const der = typeof input === 'string' ? decodeCrlText(input)
    : input[0] === 0x2d ? decodeCrlText(new TextDecoder().decode(input)) : input; // '-': PEM bytes
  const root = readTlv(der, 0);
  const [tbsT, sigAlgT, sigT] = children(der, root) as [Tlv, Tlv, Tlv];
  const parts = children(der, tbsT);
  let i = 0;
  if (parts[0]?.tag === 0x02) i++; // version
  i++; // inner signature algorithm
  const issuerT = parts[i++]!;
  const thisUpdate = parseTime(der, parts[i++]!);
  const nextUpdate = isTime(parts[i]) ? parseTime(der, parts[i++]!) : undefined;
  const sigAlgParts = children(der, sigAlgT);
  const crl: Crl = {
    der, tbs: slice(der, tbsT),
    signatureAlgorithm: decodeOid(value(der, sigAlgParts[0]!)),
    signatureParams: sigAlgParts[1] && sigAlgParts[1].tag !== 0x05 ? slice(der, sigAlgParts[1]) : undefined,
    signature: value(der, sigT).subarray(1),
    issuer: parseName(der, issuerT), issuerRaw: slice(der, issuerT),
    thisUpdate, nextUpdate, entries: new Map(), delta: false, unsupportedCritical: [],
  };
  if (parts[i]?.tag === 0x30) {
    for (const entry of children(der, parts[i++]!)) {
      const [serialT, dateT, extsT] = children(der, entry) as [Tlv, Tlv, Tlv | undefined];
      const e: CrlEntry = { revokedAt: parseTime(der, dateT), certificateIssuer: false };
      for (const [oid, , octets] of extensions(der, extsT)) {
        if (oid === CRL_OID.reasonCode) e.reason = value(octets, readTlv(octets, 0))[0];
        if (oid === CRL_OID.certificateIssuer) e.certificateIssuer = true;
      }
      crl.entries.set(normalizeSerial(toHex(value(der, serialT))), e);
    }
  }
  const extWrapper = parts.slice(i).find((t) => t.tag === 0xa0);
  for (const [oid, critical, octets] of extensions(der, extWrapper ? children(der, extWrapper)[0] : undefined)) {
    const t = readTlv(octets, 0);
    if (oid === CRL_OID.crlNumber) crl.crlNumber = bytesToBigInt(value(octets, t)).toString();
    else if (oid === OID.authorityKeyIdentifier) {
      const kid = children(octets, t).find((p) => p.tag === 0x80);
      if (kid) crl.authorityKeyIdentifier = base64UrlEncode(value(octets, kid));
    } else if (oid === CRL_OID.issuingDistributionPoint) crl.issuingDistributionPoint = parseIdp(octets, t);
    else if (oid === CRL_OID.deltaCrlIndicator) crl.delta = true;
    if (critical && !KNOWN_CRL_EXTENSIONS.has(oid)) crl.unsupportedCritical.push(oid);
  }
  return crl;
}

/** [oid, critical, extnValue octets] for each extension of an Extensions SEQUENCE. */
function extensions(der: Uint8Array, seq?: Tlv): Array<[string, boolean, Uint8Array]> {
  if (!seq) return [];
  return children(der, seq).map((ext) => {
    const p = children(der, ext);
    const critical = p.length === 3 && p[1]!.tag === 0x01 && value(der, p[1]!)[0] !== 0;
    return [decodeOid(value(der, p[0]!)), critical, value(der, p[p.length - 1]!)];
  });
}

function parseIdp(d: Uint8Array, seq: Tlv): IssuingDistributionPoint {
  const flag = (tag: number) => { const f = children(d, seq).find((p) => p.tag === tag); return !!f && value(d, f)[0] !== 0; };
  return {
    uris: distributionPointUris(d, seq),
    onlyContainsUserCerts: flag(0x81), onlyContainsCACerts: flag(0x82),
    onlySomeReasons: children(d, seq).some((p) => p.tag === 0x83),
    indirectCRL: flag(0x84), onlyContainsAttributeCerts: flag(0x85),
  };
}

export function decodeCrlText(text: string): Uint8Array {
  const m = text.match(/-----BEGIN X509 CRL-----([\s\S]+?)-----END X509 CRL-----/);
  return base64Decode(m ? m[1]! : text.trim());
}
