/**
 * X.509 certificate parsing with a small strict DER reader (no ASN.1 schema library, React Native friendly).
 *
 * The parser accepts exactly one encoding of a certificate: DER, the three fields of Certificate and nothing after
 * them, the same signature algorithm inside and outside the signed part, no extension twice, well-formed times.
 * Anything else is an ordinary Error at parse time, so a malformed certificate never reaches path validation and the
 * SHA-256 of the bytes identifies one certificate only.
 */
import { bitString, booleanValue, children, decodeOid, expectTag, integerBytes, octetAlignedBitString, oid as readOid, readSingle, sequence,
  slice, smallInteger, TAG, unsignedInteger, value, type Tlv } from '../encoding/der.js';
import { base64Decode, base64Encode, base64UrlEncode, bytesEqual, toHex, utf8Decode } from '../util/bytes.js';
import { sha256 } from '../crypto/hash.js';
import { ecPoint, type EcCurve, type PublicKey } from '../crypto/keys.js';

export { decodeOid };

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  /** 1, 2 or 3 */
  version: number;
  signatureAlgorithm: string;
  signatureParams?: Uint8Array;
  signature: Uint8Array;
  serialNumber: string;
  issuer: string;
  subject: string;
  /** the subject's country: its first C attribute in encoded order */
  subjectCountry?: string;
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
  /** URIs of the CRL distribution points (fullName) */
  crlDistributionPoints: string[];
  /**
   * The subset of {@link crlDistributionPoints} from distribution points that cover every revocation reason and name
   * no other CRL issuer: only these put the certificate in the scope of a CRL partitioned by distribution point.
   */
  crlFullScopeUris: string[];
  /** OCSP responder URLs from Authority Information Access */
  ocspUrls: string[];
  /** base64url SHA-256 of the DER encoding (OpenID4VP x509_hash) */
  sha256: string;
  /** OIDs of all extensions, in certificate order (each occurs once) */
  extensions: string[];
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
  crlDistributionPoints: '2.5.29.31',
  nameConstraints: '2.5.29.30',
  policyConstraints: '2.5.29.36',
  certificatePolicies: '2.5.29.32',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  ocsp: '1.3.6.1.5.5.7.48.1',
  mdlDocumentSigner: '1.0.18013.5.1.2',
} as const;

/** The attribute types written by keyword in a name; every other type is written as its dotted OID with a hex value. */
const NAME_ATTRS: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.9': 'STREET',
  '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID',
};
const COUNTRY = '2.5.4.6';

/** Strict UTF-8: no overlong forms, no surrogates, nothing past U+10FFFF, no truncated sequence. */
function strictUtf8(b: Uint8Array): string | undefined {
  let out = '';
  for (let i = 0; i < b.length;) {
    const c = b[i]!;
    let [n, cp, min] = c < 0x80 ? [0, c, 0] : c >= 0xc2 && c < 0xe0 ? [1, c & 0x1f, 0x80] : c >= 0xe0 && c < 0xf0 ? [2, c & 0x0f, 0x800]
      : c >= 0xf0 && c < 0xf5 ? [3, c & 0x07, 0x10000] : [-1, 0, 0];
    if (n < 0 || i + n > b.length - 1) return undefined;
    for (let k = 1; k <= n; k++) {
      const t = b[i + k]!;
      if ((t & 0xc0) !== 0x80) return undefined;
      cp = (cp << 6) | (t & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return undefined;
    out += String.fromCodePoint(cp);
    i += n + 1;
  }
  return out;
}

/** The text of a UTF8String, PrintableString or IA5String whose content is valid UTF-8; undefined for anything else. */
function nameText(data: Uint8Array, t: Tlv): string | undefined {
  return t.tag === 0x0c || t.tag === 0x13 || t.tag === 0x16 ? strictUtf8(value(data, t)) : undefined;
}

function escapeValue(s: string): string {
  let [lead, trail] = [0, s.length - 1];
  while (lead < s.length && s[lead] === ' ') lead++;
  while (trail >= 0 && s[trail] === ' ') trail--;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '\0') out += '\\00';
    else if (',=+<>#;"\\'.includes(ch) || i < lead || i > trail) out += `\\${ch}`;
    else out += ch;
  }
  return out;
}

/** The attributes of a Name, per RDN, in encoded order. */
function nameAttributes(data: Uint8Array, t: Tlv): Array<Array<{ type: string; value: Tlv }>> {
  const rdns: Array<Array<{ type: string; value: Tlv }>> = [];
  for (const set of sequence(data, t, 'Name')) {
    const atvs = sequence(data, set, 'RelativeDistinguishedName', TAG.set);
    if (atvs.length === 0) throw new Error('DER: RelativeDistinguishedName is empty');
    rdns.push(atvs.map((atv) => {
      const parts = sequence(data, atv, 'AttributeTypeAndValue');
      if (parts.length !== 2) throw new Error('DER: AttributeTypeAndValue must have a type and a value');
      return { type: readOid(data, parts[0], 'attribute type'), value: parts[1]! };
    }));
  }
  return rdns;
}

/**
 * A distinguished name as text, by the rules the service uses (Certificates.rfc2253 in Java), so that the two render
 * the same string from the same bytes and names can be compared as strings:
 *  - RFC 2253 order: the last RDN of the encoding first, RDNs joined by ',', the attributes of a multi-valued RDN in
 *    encoded order joined by '+';
 *  - CN, C, L, ST, O, OU, STREET, DC and UID by keyword; any other attribute type as its dotted OID;
 *  - the value as text when its type is written by keyword, it is a UTF8String, PrintableString or IA5String, and its
 *    bytes are valid UTF-8; otherwise '#' and the lower-case hex of the value's DER encoding;
 *  - in text, , = + < > # ; " \ are escaped with a backslash wherever they stand, NUL is written \00, and spaces at
 *    either end are escaped with a backslash.
 */
export function parseName(data: Uint8Array, t: Tlv): string {
  return nameAttributes(data, t).map((rdn) => rdn.map(({ type, value: v }) => {
    const keyword = NAME_ATTRS[type];
    const text = keyword ? nameText(data, v) : undefined;
    return text === undefined ? `${keyword ?? type}=#${toHex(slice(data, v))}` : `${keyword}=${escapeValue(text)}`;
  }).join('+')).reverse().join(',');
}

/** The country of a name: the first C attribute in encoded order whose value is text. */
export function parseCountry(data: Uint8Array, t: Tlv): string | undefined {
  for (const rdn of nameAttributes(data, t)) {
    for (const { type, value: v } of rdn) {
      const text = type === COUNTRY ? nameText(data, v) : undefined;
      if (text !== undefined) return text;
    }
  }
  return undefined;
}

const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * UTCTime {@code YYMMDDHHMMSSZ} or GeneralizedTime {@code YYYYMMDDHHMMSSZ} (RFC 5280 section 4.1.2.5: seconds
 * present, Zulu, no fraction). Anything else, including a date that does not exist, is an error.
 */
export function parseTime(data: Uint8Array, t: Tlv): Date {
  const v = value(data, t);
  const yearDigits = t.tag === TAG.utcTime ? 2 : t.tag === TAG.generalizedTime ? 4 : 0;
  if (!yearDigits) throw new Error(`DER: a time must be UTCTime or GeneralizedTime, not tag 0x${t.tag.toString(16)}`);
  const form = yearDigits === 2 ? 'UTCTime YYMMDDHHMMSSZ' : 'GeneralizedTime YYYYMMDDHHMMSSZ';
  if (v.length !== yearDigits + 11 || v[v.length - 1] !== 0x5a) throw new Error(`DER: time is not in the form ${form}`);
  let p = 0;
  const num = (len: number): number => {
    let n = 0;
    for (let i = 0; i < len; i++) {
      const d = v[p++]! - 0x30;
      if (d < 0 || d > 9) throw new Error(`DER: time is not in the form ${form}`);
      n = n * 10 + d;
    }
    return n;
  };
  let year = num(yearDigits);
  if (yearDigits === 2) year += year >= 50 ? 1900 : 2000;
  const [month, day, hour, minute, second] = [num(2), num(2), num(2), num(2), num(2)];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  if (month < 1 || month > 12 || day < 1 || day > DAYS[month - 1]! + (month === 2 && leap ? 1 : 0) || hour > 23 || minute > 59 || second > 59) {
    throw new Error('DER: time is not a valid date and time');
  }
  // setUTCFullYear, not Date.UTC: years 0 to 99 must not be read as 1900 to 1999.
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, 0);
  return d;
}

/** AlgorithmIdentifier: the algorithm OID and, when present and not NULL, the encoded parameters. */
export function parseAlgorithm(data: Uint8Array, t: Tlv | undefined, what: string): { oid: string; params?: Uint8Array; paramsTlv?: Tlv } {
  const parts = sequence(data, t, what);
  if (parts.length < 1 || parts.length > 2) throw new Error(`DER: ${what} must be an algorithm and optional parameters`);
  const p = parts[1];
  return { oid: readOid(data, parts[0], `${what} algorithm`), params: p && p.tag !== TAG.null ? slice(data, p) : undefined, paramsTlv: p };
}

function parseSpki(data: Uint8Array, t: Tlv): { key: PublicKey | null; alg: string } {
  const parts = sequence(data, t, 'subjectPublicKeyInfo');
  if (parts.length !== 2) throw new Error('DER: subjectPublicKeyInfo must have an algorithm and a key');
  const algorithm = parseAlgorithm(data, parts[0], 'subjectPublicKeyInfo algorithm');
  const alg = algorithm.oid;
  const bits = octetAlignedBitString(data, parts[1], 'subjectPublicKey');
  // A key this library cannot use (unknown algorithm or curve, malformed key) leaves the certificate readable:
  // nothing verifies with a null key.
  try {
    if (alg === OID.ecPublicKey && algorithm.paramsTlv?.tag === TAG.oid) {
      const curveOid = decodeOid(value(data, algorithm.paramsTlv));
      const crv: EcCurve | undefined = curveOid === OID.p256 ? 'P-256' : curveOid === OID.p384 ? 'P-384'
        : curveOid === OID.p521 ? 'P-521' : curveOid === OID.secp256k1 ? 'secp256k1' : undefined;
      return { key: crv ? { kty: 'EC', crv, point: ecPoint(crv, bits) } : null, alg };
    }
    if (alg === OID.ed25519) return { key: algorithm.paramsTlv || bits.length !== 32 ? null : { kty: 'OKP', crv: 'Ed25519', x: bits }, alg };
    if (alg === OID.rsaEncryption) {
      const key = sequence(bits, readSingle(bits, 'RSA public key'), 'RSA public key');
      if (key.length !== 2) return { key: null, alg };
      return { key: { kty: 'RSA', n: unsignedInteger(bits, key[0], 'RSA modulus'), e: unsignedInteger(bits, key[1], 'RSA public exponent') }, alg };
    }
  } catch {
    return { key: null, alg };
  }
  return { key: null, alg };
}

/** GeneralNames: each a context-tagged choice [0]..[8]; the IA5String forms must be ASCII. */
function generalNames(d: Uint8Array, names: Tlv[], what: string): Tlv[] {
  for (const g of names) {
    if ((g.tag & 0xc0) !== 0x80 || (g.tag & 0x1f) > 8) throw new Error(`DER: ${what} has an element that is not a GeneralName`);
    if (g.tag === 0x81 || g.tag === 0x82 || g.tag === 0x86) {
      for (let i = g.valueStart; i < g.end; i++) if (d[i]! > 0x7f) throw new Error(`DER: ${what} has a name that is not an IA5String`);
    }
  }
  return names;
}

const ascii = (d: Uint8Array, t: Tlv): string => utf8Decode(value(d, t));

export interface DistributionPointName {
  /** uniformResourceIdentifier entries of fullName */
  uris: string[];
  /** it also (or only) names the point some other way: another GeneralName form, or relative to the CRL issuer */
  otherNames: boolean;
}

/**
 * A DistributionPointName inside its [0] wrapper, as in a DistributionPoint (RFC 5280 section 4.2.1.13) and an
 * IssuingDistributionPoint (section 5.2.5): fullName [0] GeneralNames or nameRelativeToCRLIssuer [1].
 */
export function distributionPointName(d: Uint8Array, wrapper: Tlv): DistributionPointName {
  const inner = children(d, wrapper);
  if (inner.length !== 1) throw new Error('DER: a distribution point name must be exactly one choice');
  const name = inner[0]!;
  if (name.tag === 0xa1) return { uris: [], otherNames: true };
  const names = generalNames(d, sequence(d, name, 'distribution point fullName', 0xa0), 'distribution point');
  if (names.length === 0) throw new Error('DER: a distribution point fullName is empty');
  return { uris: names.filter((g) => g.tag === 0x86).map((g) => ascii(d, g)), otherNames: names.some((g) => g.tag !== 0x86) };
}

export function parseCertificate(input: Uint8Array | string): Certificate {
  const der = typeof input === 'string' ? decodeCertificateText(input) : input;
  const outer = sequence(der, readSingle(der, 'certificate'), 'Certificate');
  if (outer.length !== 3) throw new Error('DER: a Certificate is exactly tbsCertificate, signatureAlgorithm and signatureValue');
  const [tbsT, sigAlgT, sigT] = outer as [Tlv, Tlv, Tlv];
  const tbsParts = sequence(der, tbsT, 'tbsCertificate');
  let i = 0;
  let version = 1;
  if (tbsParts[0]?.tag === 0xa0) {
    const v = children(der, tbsParts[i++]!);
    if (v.length !== 1) throw new Error('DER: certificate version is malformed');
    version = smallInteger(der, v[0], 'certificate version') + 1;
    // v1 is the DEFAULT and is not encoded in DER.
    if (version !== 2 && version !== 3) throw new Error(`Unsupported certificate version ${version}`);
  }
  const serial = integerBytes(der, tbsParts[i++], 'serialNumber');
  const innerAlgT = expectTag(tbsParts[i++], TAG.sequence, 'tbsCertificate signature');
  const issuerT = expectTag(tbsParts[i++], TAG.sequence, 'issuer');
  const validity = sequence(der, tbsParts[i++], 'validity');
  const subjectT = expectTag(tbsParts[i++], TAG.sequence, 'subject');
  const spkiT = expectTag(tbsParts[i++], TAG.sequence, 'subjectPublicKeyInfo');
  if (validity.length !== 2) throw new Error('DER: validity must be notBefore and notAfter');
  const sigAlg = parseAlgorithm(der, sigAlgT, 'signatureAlgorithm');
  // RFC 5280 section 4.1.1.2: the signed algorithm identifier must be the one the signature is verified with.
  if (!bytesEqual(slice(der, innerAlgT), slice(der, sigAlgT))) {
    throw new Error('Certificate signature algorithm inside tbsCertificate differs from the outer signatureAlgorithm');
  }
  const spki = parseSpki(der, spkiT);
  const cert: Certificate = {
    der,
    tbs: slice(der, tbsT),
    version,
    signatureAlgorithm: sigAlg.oid,
    signatureParams: sigAlg.params,
    signature: octetAlignedBitString(der, sigT, 'signatureValue'),
    serialNumber: toHex(serial),
    issuer: parseName(der, issuerT),
    subject: parseName(der, subjectT),
    subjectCountry: parseCountry(der, subjectT),
    issuerRaw: slice(der, issuerT),
    subjectRaw: slice(der, subjectT),
    notBefore: parseTime(der, validity[0]!),
    notAfter: parseTime(der, validity[1]!),
    publicKey: spki.key,
    publicKeyAlgorithm: spki.alg,
    extendedKeyUsage: [],
    dnsNames: [],
    uriNames: [],
    crlDistributionPoints: [],
    crlFullScopeUris: [],
    ocspUrls: [],
    sha256: base64UrlEncode(sha256(der)),
    extensions: [],
    criticalExtensions: [],
  };
  // issuerUniqueID [1], subjectUniqueID [2] (v2 or v3), extensions [3] (v3): each at most once, in this order.
  let last = 0;
  for (const t of tbsParts.slice(i)) {
    const n = t.tag === 0x81 || t.tag === 0xa1 ? 1 : t.tag === 0x82 || t.tag === 0xa2 ? 2 : t.tag === 0xa3 ? 3 : 0;
    if (n === 0 || n <= last) throw new Error('DER: unexpected element in tbsCertificate');
    if (version < (n === 3 ? 3 : 2)) throw new Error(`A version ${version} certificate cannot have ${n === 3 ? 'extensions' : 'unique identifiers'}`);
    last = n;
    if (n === 3) parseExtensions(cert, der, t);
  }
  return cert;
}

/** [oid, critical, extnValue] of each Extension of an Extensions SEQUENCE; an extension may appear only once. */
export function readExtensions(der: Uint8Array, seq: Tlv, what: string): Array<{ oid: string; critical: boolean; value: Uint8Array }> {
  const out: Array<{ oid: string; critical: boolean; value: Uint8Array }> = [];
  const seen = new Set<string>();
  const list = sequence(der, seq, `${what} extensions`);
  if (list.length === 0) throw new Error(`DER: ${what} extensions are present but empty`);
  for (const ext of list) {
    const parts = sequence(der, ext, `${what} extension`);
    if (parts.length < 2 || parts.length > 3) throw new Error(`DER: malformed ${what} extension`);
    const id = readOid(der, parts[0], `${what} extension id`);
    // critical DEFAULT FALSE: an encoded FALSE is tolerated (it is signed and unambiguous); any other octet is not.
    const critical = parts.length === 3 ? booleanValue(der, parts[1], `critical flag of ${what} extension ${id}`) : false;
    if (seen.has(id)) throw new Error(`The ${what} has more than one ${id} extension`);
    seen.add(id);
    out.push({ oid: id, critical, value: value(der, expectTag(parts[parts.length - 1], TAG.octetString, `value of ${what} extension ${id}`)) });
  }
  return out;
}

function parseExtensions(cert: Certificate, der: Uint8Array, wrapper: Tlv): void {
  const inner = children(der, wrapper);
  if (inner.length !== 1) throw new Error('DER: malformed certificate extensions');
  for (const ext of readExtensions(der, inner[0]!, 'certificate')) {
    cert.extensions.push(ext.oid);
    if (ext.critical) cert.criticalExtensions.push(ext.oid);
    parseExtension(cert, ext.oid, ext.value);
  }
}

function parseExtension(cert: Certificate, oid: string, d: Uint8Array): void {
  switch (oid) {
    case OID.basicConstraints: {
      const parts = sequence(d, readSingle(d, 'basicConstraints'), 'basicConstraints');
      let k = 0;
      // cA DEFAULT FALSE; an encoded FALSE is tolerated, as for the critical flag.
      const ca = parts[k]?.tag === TAG.boolean ? booleanValue(d, parts[k++], 'basicConstraints cA') : false;
      const pathLen = parts[k]?.tag === TAG.integer ? smallInteger(d, parts[k++], 'pathLenConstraint') : undefined;
      if (k !== parts.length) throw new Error('DER: unexpected element in basicConstraints');
      cert.basicConstraints = { ca, pathLen };
      break;
    }
    case OID.keyUsage: {
      const { bytes } = bitString(d, readSingle(d, 'keyUsage'), 'keyUsage');
      const b0 = bytes[0] ?? 0;
      cert.keyUsage = {
        digitalSignature: !!(b0 & 0x80), nonRepudiation: !!(b0 & 0x40), keyEncipherment: !!(b0 & 0x20),
        dataEncipherment: !!(b0 & 0x10), keyAgreement: !!(b0 & 0x08), keyCertSign: !!(b0 & 0x04), cRLSign: !!(b0 & 0x02),
      };
      break;
    }
    case OID.extKeyUsage: {
      const purposes = sequence(d, readSingle(d, 'extKeyUsage'), 'extKeyUsage');
      if (purposes.length === 0) throw new Error('The extKeyUsage extension lists no key purpose');
      cert.extendedKeyUsage = purposes.map((p) => readOid(d, p, 'key purpose'));
      break;
    }
    case OID.subjectKeyIdentifier:
      cert.subjectKeyIdentifier = base64UrlEncode(value(d, expectTag(readSingle(d, 'subjectKeyIdentifier'), TAG.octetString, 'subjectKeyIdentifier')));
      break;
    case OID.authorityKeyIdentifier: {
      // keyIdentifier [0], authorityCertIssuer [1], authorityCertSerialNumber [2]
      let last = -1;
      for (const p of sequence(d, readSingle(d, 'authorityKeyIdentifier'), 'authorityKeyIdentifier')) {
        const n = p.tag === 0x80 ? 0 : p.tag === 0xa1 ? 1 : p.tag === 0x82 ? 2 : -1;
        if (n <= last) throw new Error('DER: unexpected element in authorityKeyIdentifier');
        last = n;
        if (n === 0) cert.authorityKeyIdentifier = base64UrlEncode(value(d, p));
      }
      break;
    }
    case OID.subjectAltName:
    case OID.issuerAltName: {
      const what = oid === OID.subjectAltName ? 'subjectAltName' : 'issuerAltName';
      const names = generalNames(d, sequence(d, readSingle(d, what), what), what);
      if (names.length === 0) throw new Error(`The ${what} extension has no names`);
      if (oid === OID.subjectAltName) {
        for (const gn of names) {
          if (gn.tag === 0x82) cert.dnsNames.push(ascii(d, gn));
          if (gn.tag === 0x86) cert.uriNames.push(ascii(d, gn));
        }
      }
      break;
    }
    case OID.crlDistributionPoints: {
      const points = sequence(d, readSingle(d, 'cRLDistributionPoints'), 'cRLDistributionPoints');
      if (points.length === 0) throw new Error('The cRLDistributionPoints extension has no distribution point');
      for (const dp of points) {
        // distributionPoint [0], reasons [1], cRLIssuer [2]
        let last = -1;
        let name: DistributionPointName | undefined;
        let partial = false;
        for (const p of sequence(d, dp, 'DistributionPoint')) {
          const n = p.tag === 0xa0 ? 0 : p.tag === 0x81 ? 1 : p.tag === 0xa2 ? 2 : -1;
          if (n <= last) throw new Error('DER: unexpected element in a DistributionPoint');
          last = n;
          if (n === 0) name = distributionPointName(d, p);
          else partial = true;
        }
        if (!name) continue;
        cert.crlDistributionPoints.push(...name.uris);
        if (!partial) cert.crlFullScopeUris.push(...name.uris);
      }
      break;
    }
    case OID.authorityInfoAccess: {
      const descriptions = sequence(d, readSingle(d, 'authorityInfoAccess'), 'authorityInfoAccess');
      if (descriptions.length === 0) throw new Error('The authorityInfoAccess extension has no access description');
      for (const ad of descriptions) {
        const parts = sequence(d, ad, 'AccessDescription');
        if (parts.length !== 2) throw new Error('DER: malformed AccessDescription');
        const method = readOid(d, parts[0], 'access method');
        const [location] = generalNames(d, [parts[1]!], 'authorityInfoAccess');
        if (method === OID.ocsp && location!.tag === 0x86) cert.ocspUrls.push(ascii(d, location!));
      }
      break;
    }
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


