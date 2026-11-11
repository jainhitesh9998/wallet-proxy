/**
 * X.509 CRL (RFC 5280 §5) parsing with the same strict DER reader as certificates: one encoding, nothing after the
 * CertificateList, the same signature algorithm inside and outside the signed part, no extension twice.
 */
import { booleanValue, children, expectTag, integerBytes, octetAlignedBitString, readSingle, sequence, slice, smallInteger, TAG,
  unsignedInteger, value, type Tlv } from '../encoding/der.js';
import { base64Decode, base64UrlEncode, bytesEqual, toHex } from '../util/bytes.js';
import { distributionPointName, OID, parseAlgorithm, parseName, parseTime, readExtensions } from './certificate.js';

export interface CrlEntry {
  revokedAt: Date;
  /** CRLReason (RFC 5280 §5.3.1); absent = unspecified */
  reason?: number;
  /** the entry names another certificate issuer (indirect CRL) */
  certificateIssuer: boolean;
}

export interface IssuingDistributionPoint {
  /** uniformResourceIdentifier names of the distribution point */
  uris: string[];
  /**
   * The distribution point is named in a way that is not compared here (a directoryName or another GeneralName form,
   * or a name relative to the CRL issuer). Such a CRL covers only certificates that one of {@link uris} places in it.
   */
  unsupportedName?: boolean;
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
  /**
   * Revoked serial numbers (lowercase hex, no leading zeros). A serial listed more than once keeps its gravest entry:
   * a revocation over a hold, either over removeFromCRL.
   */
  entries: Map<string, CrlEntry>;
  /** a serial number is listed more than once: what the CRL says about the certificates it does not list is then not relied on */
  duplicateSerials?: boolean;
  crlNumber?: string;
  authorityKeyIdentifier?: string;
  issuingDistributionPoint?: IssuingDistributionPoint;
  /** deltaCRLIndicator present */
  delta: boolean;
  /** critical CRL extensions and critical CRL entry extensions this parser does not understand */
  unsupportedCritical: string[];
}

export const CRL_OID = {
  crlNumber: '2.5.29.20',
  reasonCode: '2.5.29.21',
  invalidityDate: '2.5.29.24',
  deltaCrlIndicator: '2.5.29.27',
  issuingDistributionPoint: '2.5.29.28',
  certificateIssuer: '2.5.29.29',
  freshestCrl: '2.5.29.46',
} as const;

const KNOWN_CRL_EXTENSIONS = new Set<string>([CRL_OID.crlNumber, OID.authorityKeyIdentifier, CRL_OID.issuingDistributionPoint,
  CRL_OID.freshestCrl, CRL_OID.deltaCrlIndicator]);
const KNOWN_ENTRY_EXTENSIONS = new Set<string>([CRL_OID.reasonCode, CRL_OID.invalidityDate, CRL_OID.certificateIssuer]);

/** RFC 5280 CRLReason names, as used in revocation evidence. */
export const CRL_REASONS: Record<number, string> = {
  0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise', 3: 'affiliationChanged', 4: 'superseded', 5: 'cessationOfOperation',
  6: 'certificateHold', 8: 'removeFromCRL', 9: 'privilegeWithdrawn', 10: 'aACompromise',
};
export const REASON_CERTIFICATE_HOLD = 6;
export const REASON_REMOVE_FROM_CRL = 8;

/** Serial numbers as compared across certificates and CRLs: lowercase hex without leading zeros. */
export function normalizeSerial(hex: string): string {
  return BigInt(`0x${hex || '0'}`).toString(16);
}

const isTime = (t?: Tlv) => t?.tag === TAG.utcTime || t?.tag === TAG.generalizedTime;
/** removeFromCRL < certificateHold < any revocation */
const gravity = (e: CrlEntry) => (e.reason === REASON_REMOVE_FROM_CRL ? 0 : e.reason === REASON_CERTIFICATE_HOLD ? 1 : 2);

/** Accepts DER, PEM ("X509 CRL") or base64. */
export function parseCrl(input: Uint8Array | string): Crl {
  const der = typeof input === 'string' ? decodeCrlText(input)
    : input[0] === 0x2d ? decodeCrlText(new TextDecoder().decode(input)) : input; // '-': PEM bytes
  const outer = sequence(der, readSingle(der, 'CRL'), 'CertificateList');
  if (outer.length !== 3) throw new Error('DER: a CRL is exactly tbsCertList, signatureAlgorithm and signatureValue');
  const [tbsT, sigAlgT, sigT] = outer as [Tlv, Tlv, Tlv];
  const parts = sequence(der, tbsT, 'tbsCertList');
  let i = 0;
  let version = 1;
  if (parts[0]?.tag === TAG.integer) {
    version = smallInteger(der, parts[i++], 'CRL version') + 1;
    if (version !== 2) throw new Error(`Unsupported CRL version ${version}`);
  }
  const innerAlgT = expectTag(parts[i++], TAG.sequence, 'tbsCertList signature');
  const issuerT = expectTag(parts[i++], TAG.sequence, 'CRL issuer');
  if (!isTime(parts[i])) throw new Error('DER: CRL thisUpdate is missing');
  const thisUpdate = parseTime(der, parts[i++]!);
  const nextUpdate = isTime(parts[i]) ? parseTime(der, parts[i++]!) : undefined;
  const sigAlg = parseAlgorithm(der, sigAlgT, 'signatureAlgorithm');
  if (!bytesEqual(slice(der, innerAlgT), slice(der, sigAlgT))) {
    throw new Error('CRL signature algorithm inside tbsCertList differs from the outer signatureAlgorithm');
  }
  const crl: Crl = {
    der, tbs: slice(der, tbsT),
    signatureAlgorithm: sigAlg.oid,
    signatureParams: sigAlg.params,
    signature: octetAlignedBitString(der, sigT, 'signatureValue'),
    issuer: parseName(der, issuerT), issuerRaw: slice(der, issuerT),
    thisUpdate, nextUpdate, entries: new Map(), delta: false, unsupportedCritical: [],
  };
  if (parts[i]?.tag === TAG.sequence) {
    for (const entry of children(der, parts[i++]!)) {
      const fields = sequence(der, entry, 'revoked certificate');
      if (fields.length < 2 || fields.length > 3) throw new Error('DER: malformed revoked certificate entry');
      const serial = normalizeSerial(toHex(integerBytes(der, fields[0], 'revoked serial number')));
      const e: CrlEntry = { revokedAt: parseTime(der, fields[1]!), certificateIssuer: false };
      if (fields[2]) {
        if (version < 2) throw new Error('A version 1 CRL cannot have entry extensions');
        for (const ext of readExtensions(der, fields[2], 'CRL entry')) {
          if (ext.oid === CRL_OID.reasonCode) e.reason = smallInteger(ext.value, readSingle(ext.value, 'reasonCode'), 'reasonCode', TAG.enumerated);
          if (ext.oid === CRL_OID.certificateIssuer) e.certificateIssuer = true;
          if (ext.critical && !KNOWN_ENTRY_EXTENSIONS.has(ext.oid) && !crl.unsupportedCritical.includes(ext.oid)) crl.unsupportedCritical.push(ext.oid);
        }
      }
      const listed = crl.entries.get(serial);
      if (listed) crl.duplicateSerials = true;
      if (!listed || gravity(e) > gravity(listed)) crl.entries.set(serial, e);
    }
  }
  if (parts[i]?.tag === 0xa0) {
    if (version < 2) throw new Error('A version 1 CRL cannot have extensions');
    const wrapper = children(der, parts[i++]!);
    if (wrapper.length !== 1) throw new Error('DER: malformed CRL extensions');
    for (const ext of readExtensions(der, wrapper[0]!, 'CRL')) {
      const d = ext.value;
      if (ext.oid === CRL_OID.crlNumber) crl.crlNumber = unsignedInteger(d, readSingle(d, 'cRLNumber'), 'cRLNumber').toString();
      else if (ext.oid === OID.authorityKeyIdentifier) {
        const kid = sequence(d, readSingle(d, 'authorityKeyIdentifier'), 'authorityKeyIdentifier').find((p) => p.tag === 0x80);
        if (kid) crl.authorityKeyIdentifier = base64UrlEncode(value(d, kid));
      } else if (ext.oid === CRL_OID.issuingDistributionPoint) crl.issuingDistributionPoint = parseIdp(d, readSingle(d, 'issuingDistributionPoint'));
      else if (ext.oid === CRL_OID.deltaCrlIndicator) crl.delta = true;
      if (ext.critical && !KNOWN_CRL_EXTENSIONS.has(ext.oid) && !crl.unsupportedCritical.includes(ext.oid)) crl.unsupportedCritical.push(ext.oid);
    }
  }
  if (i !== parts.length) throw new Error('DER: unexpected element in tbsCertList');
  return crl;
}

/**
 * IssuingDistributionPoint (RFC 5280 §5.2.5): distributionPoint [0], onlyContainsUserCerts [1], onlyContainsCACerts
 * [2], onlySomeReasons [3], indirectCRL [4], onlyContainsAttributeCerts [5], each at most once and in this order.
 */
function parseIdp(d: Uint8Array, seq: Tlv): IssuingDistributionPoint {
  const idp: IssuingDistributionPoint = { uris: [], onlyContainsUserCerts: false, onlyContainsCACerts: false, onlySomeReasons: false,
    indirectCRL: false, onlyContainsAttributeCerts: false };
  let last = -1;
  for (const p of sequence(d, seq, 'issuingDistributionPoint')) {
    const n = p.tag === 0xa0 ? 0 : p.tag >= 0x81 && p.tag <= 0x85 ? p.tag - 0x80 : -1;
    if (n <= last) throw new Error('DER: unexpected element in issuingDistributionPoint');
    last = n;
    if (n === 0) {
      const name = distributionPointName(d, p);
      idp.uris = name.uris;
      if (name.otherNames) idp.unsupportedName = true;
    } else if (n === 3) idp.onlySomeReasons = true;
    else {
      const flag = booleanValue(d, p, 'issuingDistributionPoint flag', p.tag);
      if (n === 1) idp.onlyContainsUserCerts = flag;
      else if (n === 2) idp.onlyContainsCACerts = flag;
      else if (n === 4) idp.indirectCRL = flag;
      else idp.onlyContainsAttributeCerts = flag;
    }
  }
  return idp;
}

export function decodeCrlText(text: string): Uint8Array {
  const m = text.match(/-----BEGIN X509 CRL-----([\s\S]+?)-----END X509 CRL-----/);
  return base64Decode(m ? m[1]! : text.trim());
}
