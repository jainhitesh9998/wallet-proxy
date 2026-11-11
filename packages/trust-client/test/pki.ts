/**
 * A small DER / X.509 / CRL factory for tests: it builds certificates and CRLs field by field and signs them with
 * node:crypto, so a test can produce exactly the malformed or unusual encoding it is about. Test use only.
 */
import crypto, { type KeyObject } from 'node:crypto';

type Bytes = Uint8Array | number[];
export interface KeyPair { publicKey: KeyObject; privateKey: KeyObject }

export const cat = (...p: Bytes[]): Buffer => Buffer.concat(p.map((x) => Buffer.from(x as Uint8Array)));
export function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const b: number[] = [];
  while (n > 0) { b.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | b.length, ...b]);
}
export const tlv = (tag: number, ...content: Bytes[]): Buffer => { const c = cat(...content); return cat([tag], len(c.length), c); };
export const seq = (...c: Bytes[]) => tlv(0x30, ...c);
export const set = (...c: Bytes[]) => tlv(0x31, ...c);
export const octet = (b: Bytes) => tlv(0x04, b);
export const bool = (v: boolean) => tlv(0x01, [v ? 0xff : 0x00]);
export const nul = () => Buffer.from([0x05, 0x00]);
export const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, 'utf8'));
export const printable = (s: string) => tlv(0x13, Buffer.from(s, 'latin1'));
export const bitstr = (b: Bytes, unused = 0) => tlv(0x03, [unused], b);
/** constructed context tag [n] */
export const ctx = (n: number, ...c: Bytes[]) => tlv(0xa0 | n, ...c);
/** primitive context tag [n] */
export const ctxp = (n: number, b: Bytes) => tlv(0x80 | n, b);
export function int(v: number | bigint | Bytes): Buffer {
  if (typeof v !== 'number' && typeof v !== 'bigint') return tlv(0x02, v);
  let hex = BigInt(v).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const b = Buffer.from(hex, 'hex');
  return tlv(0x02, b[0]! & 0x80 ? cat([0], b) : b);
}
export function oid(s: string): Buffer {
  const p = s.split('.').map(Number);
  const out = [p[0]! * 40 + p[1]!];
  for (const v of p.slice(2)) {
    const stack = [v & 0x7f];
    let x = Math.floor(v / 128);
    while (x > 0) { stack.unshift((x & 0x7f) | 0x80); x = Math.floor(x / 128); }
    out.push(...stack);
  }
  return tlv(0x06, out);
}
const pad = (n: number, w = 2) => String(n).padStart(w, '0');
const stamp = (d: Date) => `${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
export const utc = (d: Date) => tlv(0x17, Buffer.from(`${pad(d.getUTCFullYear() % 100)}${stamp(d)}`));
export const gen = (d: Date) => tlv(0x18, Buffer.from(`${pad(d.getUTCFullYear(), 4)}${stamp(d)}`));
export const rawTime = (tag: number, s: string) => tlv(tag, Buffer.from(s));

export type Rdns = Array<[string, string]>;
const ATTR: Record<string, string> = { CN: '2.5.4.3', C: '2.5.4.6', O: '2.5.4.10', OU: '2.5.4.11', ST: '2.5.4.8' };
/** name([['C','US'],['O','X'],['CN','Y']]): an RDNSequence in the given (most general first) order */
export const name = (rdns: Rdns, str: (s: string) => Buffer = utf8) =>
  seq(...rdns.map(([k, v]) => set(seq(oid(ATTR[k] ?? k), (k === 'C' ? printable : str)(v)))));

export const ALG = {
  ecdsaSha256: seq(oid('1.2.840.10045.4.3.2')),
  ecdsaSha384: seq(oid('1.2.840.10045.4.3.3')),
  rsaSha256: seq(oid('1.2.840.113549.1.1.11'), nul()),
  rsaSha1: seq(oid('1.2.840.113549.1.1.5'), nul()),
  ed25519: seq(oid('1.3.101.112')),
};

export const ecKey = (curve = 'prime256v1'): KeyPair => crypto.generateKeyPairSync('ec', { namedCurve: curve });
export const rsaKey = (bits = 2048, e = 65537): KeyPair => crypto.generateKeyPairSync('rsa', { modulusLength: bits, publicExponent: e });
export const edKey = (): KeyPair => crypto.generateKeyPairSync('ed25519');
export const spki = (k: KeyPair): Buffer => k.publicKey.export({ type: 'spki', format: 'der' });
/** SubjectPublicKeyInfo of an RSA key given as numbers (for keys node:crypto would not generate, such as e = 1). */
export const rsaSpki = (n: bigint, e: bigint) => seq(seq(oid('1.2.840.113549.1.1.1'), nul()), bitstr(seq(int(n), int(e))));

export const ext = (o: string, critical: boolean, value: Bytes) => seq(oid(o), ...(critical ? [bool(true)] : []), octet(value));
export const X = {
  bc: (ca: boolean, pathLen?: number, critical = true) => ext('2.5.29.19', critical, seq(...(ca ? [bool(true)] : []), ...(pathLen !== undefined ? [int(pathLen)] : []))),
  /** bits: positions (0 = digitalSignature … 5 = keyCertSign, 6 = cRLSign) */
  ku: (bits: number[], critical = true) => {
    let b = 0;
    for (const i of bits) b |= 0x80 >> i;
    return ext('2.5.29.15', critical, bitstr([b], 0));
  },
  eku: (oids: string[], critical = false) => ext('2.5.29.37', critical, seq(...oids.map(oid))),
  sanDns: (names: string[], critical = false) => ext('2.5.29.17', critical, seq(...names.map((n) => ctxp(2, Buffer.from(n))))),
  ski: (id: Bytes) => ext('2.5.29.14', false, octet(id)),
  aki: (id: Bytes) => ext('2.5.29.35', false, seq(ctxp(0, id))),
  crlDp: (uris: string[]) => ext('2.5.29.31', false, seq(...uris.map((u) => seq(ctx(0, ctx(0, ctxp(6, Buffer.from(u)))))))),
  nameConstraintsDns: (permitted: string[], critical = true) => ext('2.5.29.30', critical, seq(ctx(0, ...permitted.map((d) => seq(ctxp(2, Buffer.from(d))))))),
  policyConstraints: (critical = true) => ext('2.5.29.36', critical, seq(ctxp(0, [0]))),
  inhibitAnyPolicy: (critical = true) => ext('2.5.29.54', critical, int(0)),
  unknown: (critical = true) => ext('1.3.6.1.4.1.99999.1', critical, utf8('x')),
};

export function sign(key: KeyPair, data: Bytes, hash = 'sha256'): Buffer {
  const t = key.privateKey.asymmetricKeyType;
  if (t === 'ed25519') return crypto.sign(null, Buffer.from(data as Uint8Array), key.privateKey);
  if (t === 'ec') return crypto.sign(hash, Buffer.from(data as Uint8Array), { key: key.privateKey, dsaEncoding: 'der' });
  return crypto.sign(hash, Buffer.from(data as Uint8Array), key.privateKey);
}
export function algFor(key: KeyPair): Buffer {
  const t = key.privateKey.asymmetricKeyType;
  return t === 'ed25519' ? ALG.ed25519 : t === 'ec' ? ALG.ecdsaSha256 : ALG.rsaSha256;
}

const DAY = 86400_000;
export interface CertOptions {
  subject: Rdns | Buffer;
  issuer: Rdns | Buffer;
  /** the subject's key pair (or {@link spki}) */
  key?: KeyPair;
  spki?: Buffer;
  /** the issuer's key pair */
  signer: KeyPair;
  serial?: number | bigint | Buffer;
  notBefore?: Date;
  notAfter?: Date;
  exts?: Buffer[];
  alg?: Buffer;
  /** tbsCertificate.signature when it should differ from the outer algorithm */
  innerAlg?: Buffer;
  hash?: string;
  /** the encoded version number (default 2 = v3); 'absent' leaves the field out (v1) */
  version?: number | 'absent';
  rawValidity?: Buffer;
  /** extra elements appended to the outer SEQUENCE, outside the signature */
  outerExtra?: Buffer[];
  /** extra elements appended to tbsCertificate */
  tbsExtra?: Buffer[];
  sigTransform?: (sig: Buffer) => Buffer;
  /** computes the signature from tbsCertificate instead of signing with {@link signer} */
  signWith?: (tbs: Buffer) => Buffer;
}

/** EMSA-PKCS1-v1_5 encoding of SHA-256(data) for a k-byte modulus: with e = 1 this is its own "signature". */
export function pkcs1Sha256Em(data: Bytes, k = 256): Buffer {
  const t = cat(Buffer.from('3031300d060960864801650304020105000420', 'hex'), crypto.createHash('sha256').update(Buffer.from(data as Uint8Array)).digest());
  const em = Buffer.alloc(k, 0xff);
  em[0] = 0;
  em[1] = 1;
  em[k - t.length - 1] = 0;
  t.copy(em, k - t.length);
  return em;
}

export function cert(o: CertOptions): Buffer {
  const now = Date.now();
  const alg = o.alg ?? algFor(o.signer);
  const nm = (n: Rdns | Buffer) => (Buffer.isBuffer(n) ? n : name(n));
  const validity = o.rawValidity ?? seq(utc(o.notBefore ?? new Date(now - DAY)), utc(o.notAfter ?? new Date(now + 365 * DAY)));
  const tbs = seq(
    ...(o.version === 'absent' ? [] : [ctx(0, int(o.version ?? 2))]),
    Buffer.isBuffer(o.serial) ? tlv(0x02, o.serial) : int(o.serial ?? (BigInt(`0x${crypto.randomBytes(8).toString('hex')}`) | 1n)),
    o.innerAlg ?? alg, nm(o.issuer), validity, nm(o.subject), o.spki ?? spki(o.key!),
    ...(o.exts && o.exts.length ? [ctx(3, seq(...o.exts))] : []),
    ...(o.tbsExtra ?? []),
  );
  let sig = o.signWith ? o.signWith(tbs) : sign(o.signer, tbs, o.hash ?? 'sha256');
  if (o.sigTransform) sig = o.sigTransform(sig);
  return seq(tbs, alg, bitstr(sig), ...(o.outerExtra ?? []));
}

export interface CrlOptions {
  issuer: Rdns | Buffer;
  signer: KeyPair;
  thisUpdate?: Date;
  /** null leaves nextUpdate out */
  nextUpdate?: Date | null;
  entries?: Array<{ serial: number | bigint | Buffer; date?: Date; exts?: Buffer[] }>;
  exts?: Buffer[];
  alg?: Buffer;
  innerAlg?: Buffer;
  rawNextUpdate?: Buffer;
  outerExtra?: Buffer[];
}

export function crl(o: CrlOptions): Buffer {
  const now = Date.now();
  const alg = o.alg ?? algFor(o.signer);
  const nm = (n: Rdns | Buffer) => (Buffer.isBuffer(n) ? n : name(n));
  const entries = (o.entries ?? []).map((e) => seq(Buffer.isBuffer(e.serial) ? tlv(0x02, e.serial) : int(e.serial), utc(e.date ?? new Date(now - DAY)),
    ...(e.exts && e.exts.length ? [seq(...e.exts)] : [])));
  const tbs = seq(int(1), o.innerAlg ?? alg, nm(o.issuer), utc(o.thisUpdate ?? new Date(now - 3600_000)),
    ...(o.rawNextUpdate ? [o.rawNextUpdate] : o.nextUpdate === null ? [] : [utc(o.nextUpdate ?? new Date(now + 7 * DAY))]),
    ...(entries.length ? [seq(...entries)] : []),
    ...(o.exts && o.exts.length ? [ctx(0, seq(...o.exts))] : []));
  return seq(tbs, alg, bitstr(sign(o.signer, tbs)), ...(o.outerExtra ?? []));
}

export interface IdpOptions { uri?: string; dirName?: Buffer; relativeName?: boolean; onlyUser?: boolean; onlyCA?: boolean; onlySomeReasons?: boolean; indirect?: boolean; onlyAttribute?: boolean }
export const CX = {
  reason: (code: number, critical = false) => ext('2.5.29.21', critical, tlv(0x0a, [code])),
  crlNumber: (n: number) => ext('2.5.29.20', false, int(n)),
  delta: (n = 1) => ext('2.5.29.27', true, int(n)),
  idp: (p: IdpOptions, critical = true) => ext('2.5.29.28', critical, seq(
    ...(p.uri ? [ctx(0, ctx(0, ctxp(6, Buffer.from(p.uri))))] : []),
    ...(p.dirName ? [ctx(0, ctx(0, ctx(4, p.dirName)))] : []),
    ...(p.relativeName ? [ctx(0, ctx(1, seq(oid('2.5.4.3'), utf8('partition 7'))))] : []),
    ...(p.onlyUser ? [ctxp(1, [0xff])] : []), ...(p.onlyCA ? [ctxp(2, [0xff])] : []),
    ...(p.onlySomeReasons ? [ctxp(3, [0x01, 0x40])] : []), ...(p.indirect ? [ctxp(4, [0xff])] : []),
    ...(p.onlyAttribute ? [ctxp(5, [0xff])] : []))),
  certIssuer: (nameDer: Buffer, critical = true) => ext('2.5.29.29', critical, seq(ctx(4, nameDer))),
  unknown: (critical = true) => ext('1.3.6.1.4.1.99999.2', critical, utf8('x')),
};
