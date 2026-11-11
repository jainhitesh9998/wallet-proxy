/**
 * The certificate reader accepts one encoding of a certificate and nothing else, and the path validator refuses what
 * it does not implement: these are the cases an independent review found accepted. Certificates are built and signed
 * at test time (test/pki.ts), so each test states exactly the defect it is about.
 */
import { describe, expect, it } from 'vitest';
import { parseCertificate, validateCertificateChain, type LocalAnchor } from '../src/primitives.js';
import * as P from './pki.js';

const DAY = 86400_000;
const ROOT: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'Root CA']];
const INT: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'Intermediate CA']];
const INT2: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'Intermediate CA 2']];
const LEAF: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'leaf.example']];
const rootKey = P.ecKey();
const intKey = P.ecKey();
const int2Key = P.ecKey();
const leafKey = P.ecKey();
const CA_EXTS = [P.X.bc(true), P.X.ku([5, 6])];

const mkRoot = (o: Partial<P.CertOptions> = {}) => P.cert({ subject: ROOT, issuer: ROOT, key: rootKey, signer: rootKey, exts: CA_EXTS, ...o });
const mkInt = (o: Partial<P.CertOptions> = {}) => P.cert({ subject: INT, issuer: ROOT, key: intKey, signer: rootKey, exts: CA_EXTS, ...o });
const mkLeaf = (o: Partial<P.CertOptions> = {}) => P.cert({ subject: LEAF, issuer: INT, key: leafKey, signer: intKey, exts: [P.X.ku([0])], ...o });
/** a leaf issued directly by the root */
const mkLeafRoot = (o: Partial<P.CertOptions> = {}) => P.cert({ subject: LEAF, issuer: ROOT, key: leafKey, signer: rootKey, exts: [P.X.ku([0])], ...o });
const anchorOf = (der: Uint8Array, domain = 'test'): LocalAnchor[] => [{ certificate: parseCertificate(der), domain }];
const anchors = anchorOf(mkRoot());
const validate = (chain: Uint8Array[], a: LocalAnchor[] = anchors, opts = {}) => validateCertificateChain(chain, a, opts);
const errors = (r: { issues: { code: string; severity: string }[] }) => r.issues.filter((i) => i.severity === 'ERROR').map((i) => i.code);
/** Parsing fails with an ordinary Error (not a RangeError or TypeError from deep inside) whose message matches. */
function rejects(der: Uint8Array, message: RegExp): void {
  let thrown: unknown;
  try { parseCertificate(der); } catch (e) { thrown = e; }
  expect(thrown, 'the certificate was accepted').toBeInstanceOf(Error);
  expect((thrown as Error).constructor).toBe(Error);
  expect((thrown as Error).message).toMatch(message);
}

describe('baseline: well-formed chains still validate', () => {
  it('leaf, intermediate and root, with the anchor omitted or included', () => {
    for (const chain of [[mkLeaf(), mkInt()], [mkLeaf(), mkInt(), mkRoot()], [mkLeafRoot()]]) {
      const r = validate(chain);
      expect(r.valid, JSON.stringify(r.issues)).toBe(true);
    }
    expect(validate([mkLeafRoot({ exts: [P.X.unknown(false)] })]).valid).toBe(true);
    expect(validate([mkLeaf(), mkInt({ exts: [P.X.bc(true)] })]).valid).toBe(true); // a CA without keyUsage
  });
});

describe('a trust anchor issues only within its own limits', () => {
  const EE: P.Rdns = [['C', 'US'], ['O', 'Pinned'], ['CN', 'pinned-verifier.example']];
  const eeKey = P.ecKey();
  const child = P.cert({ subject: [['CN', 'bank.example']], issuer: EE, key: leafKey, signer: eeKey, exts: [P.X.sanDns(['bank.example'])] });
  const opts = { domain: 'verifier-access', expectedDnsName: 'bank.example' };
  const NOT_CA = { code: 'x509.anchor_not_ca', message: 'The trust anchor is not a CA certificate allowed to sign certificates', severity: 'ERROR' };
  const PATH_LENGTH = { code: 'x509.anchor_path_length', message: "The chain is longer than the trust anchor's path length allows", severity: 'ERROR' };

  it('an end-entity anchor (CA:FALSE, no keyCertSign) cannot issue; pinned itself it stays valid', () => {
    const ee = P.cert({ subject: EE, issuer: EE, key: eeKey, signer: eeKey, exts: [P.X.bc(false), P.X.ku([0]), P.X.sanDns(['pinned-verifier.example'])] });
    const a = anchorOf(ee, 'verifier-access');
    const itself = validate([ee], a, { domain: 'verifier-access', expectedDnsName: 'pinned-verifier.example' });
    expect(itself.valid, JSON.stringify(itself.issues)).toBe(true);
    expect(itself.issues.map((i) => i.code)).toContain('x509.pinned');
    for (const chain of [[child], [child, ee]]) {
      const r = validate(chain, a, opts);
      expect(r.valid).toBe(false);
      expect(r.anchorFound).toBe(true);
      expect(r.issues).toContainEqual(NOT_CA);
    }
  });

  it('an anchor without basicConstraints, or whose keyUsage lacks keyCertSign, cannot issue', () => {
    const noBc = P.cert({ subject: EE, issuer: EE, key: eeKey, signer: eeKey, exts: [] });
    expect(validate([child], anchorOf(noBc)).issues).toContainEqual(NOT_CA);
    const v1 = P.cert({ subject: EE, issuer: EE, key: eeKey, signer: eeKey, version: 'absent' });
    expect(validate([child], anchorOf(v1)).issues).toContainEqual(NOT_CA);
    const caWithoutCertSign = P.cert({ subject: EE, issuer: EE, key: eeKey, signer: eeKey, exts: [P.X.bc(true), P.X.ku([0, 6])] });
    expect(validate([child], anchorOf(caWithoutCertSign)).issues).toContainEqual(NOT_CA);
    // CA:TRUE with keyCertSign, or with no keyUsage at all, issues.
    for (const exts of [[P.X.bc(true), P.X.ku([5])], [P.X.bc(true)]]) {
      const r = validate([child], anchorOf(P.cert({ subject: EE, issuer: EE, key: eeKey, signer: eeKey, exts })));
      expect(r.valid, JSON.stringify(r.issues)).toBe(true);
    }
  });

  it("the anchor's pathLenConstraint bounds the non-self-issued intermediates below it", () => {
    const root0 = anchorOf(mkRoot({ exts: [P.X.bc(true, 0), P.X.ku([5, 6])] }));
    expect(validate([mkLeafRoot()], root0).valid).toBe(true);
    const tooLong = validate([mkLeaf(), mkInt()], root0);
    expect(tooLong.valid).toBe(false);
    expect(tooLong.issues).toContainEqual(PATH_LENGTH);
    expect(validate([mkLeaf(), mkInt(), mkRoot({ exts: [P.X.bc(true, 0), P.X.ku([5, 6])] })], root0).issues.map((i) => i.code)).not.toContain('x509.path.invalid_signature');
    // A re-issued (self-issued) root between the leaf and the anchor does not count against the path length.
    const renewed = mkRoot({ exts: [P.X.bc(true, 0), P.X.ku([5, 6])], notAfter: new Date(Date.now() + 700 * DAY) });
    const viaRenewed = validate([mkLeafRoot(), renewed], root0);
    expect(viaRenewed.valid, JSON.stringify(viaRenewed.issues)).toBe(true);
    // pathLen 1: one intermediate is allowed, two are not.
    const root1 = anchorOf(mkRoot({ exts: [P.X.bc(true, 1), P.X.ku([5, 6])] }));
    expect(validate([mkLeaf(), mkInt()], root1).valid).toBe(true);
    const int2 = P.cert({ subject: INT2, issuer: INT, key: int2Key, signer: intKey, exts: CA_EXTS });
    const leaf2 = P.cert({ subject: LEAF, issuer: INT2, key: leafKey, signer: int2Key });
    expect(validate([leaf2, int2, mkInt()], root1).issues).toContainEqual(PATH_LENGTH);
    expect(validate([leaf2, int2, mkInt()]).valid).toBe(true);
  });
});

describe('strict DER: one encoding per certificate', () => {
  const good = mkLeafRoot();

  it('rejects trailing bytes and extra elements, so the certificate hash is not malleable', () => {
    expect(parseCertificate(good).subject).toBe('CN=leaf.example,O=Test,C=US');
    rejects(P.cat(good, [0xde, 0xad, 0xbe, 0xef]), /Trailing bytes after the certificate/);
    rejects(P.cat(good, [0x00]), /Trailing bytes/);
    rejects(mkLeafRoot({ outerExtra: [P.utf8('unsigned extra')] }), /exactly tbsCertificate, signatureAlgorithm and signatureValue/);
    rejects(mkLeafRoot({ tbsExtra: [P.utf8('extra')] }), /unexpected element in tbsCertificate/);
    rejects(P.seq(P.seq(), P.ALG.ecdsaSha256), /exactly tbsCertificate/);
  });

  it('rejects lengths that are not DER: indefinite, or longer than needed', () => {
    const body = good.subarray(4); // good is 30 82 LL LL …
    const l = good.readUInt16BE(2);
    rejects(P.cat([0x30, 0x83, 0x00, l >> 8, l & 0xff], body), /DER length is not in its shortest form/);
    rejects(P.cat([0x30, 0x80], body, [0x00, 0x00]), /indefinite length/);
    // a long-form length for a short value, deep inside (the version INTEGER: 02 81 01 02)
    const nonMinimalInside = mkLeafRoot({ tbsExtra: [] });
    const at = nonMinimalInside.indexOf(Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]));
    expect(at).toBeGreaterThan(0);
    const patched = P.cat(nonMinimalInside.subarray(0, at), [0xa0, 0x04, 0x02, 0x81, 0x01, 0x02], nonMinimalInside.subarray(at + 5));
    patched.writeUInt16BE(patched.readUInt16BE(2) + 1, 2);
    patched.writeUInt16BE(patched.readUInt16BE(6) + 1, 6);
    rejects(patched, /DER length is not in its shortest form/);
    rejects(P.cat([0x3f, 0x21], good), /tag numbers above 30/);
  });

  it('rejects INTEGERs that are not minimally encoded', () => {
    rejects(mkLeafRoot({ serial: Buffer.from([0, 0, 1]) }), /serialNumber is not a minimally encoded INTEGER/);
    rejects(mkLeafRoot({ serial: Buffer.from([0xff, 0xff, 0x01]) }), /not a minimally encoded INTEGER/);
    rejects(mkLeafRoot({ serial: Buffer.alloc(0) }), /serialNumber is an empty INTEGER/);
    expect(parseCertificate(mkLeafRoot({ serial: Buffer.from([0x00, 0x80]) })).serialNumber).toBe('0080');
  });

  it('rejects a negative or non-minimal pathLenConstraint instead of reading it as 255', () => {
    const bc = (pathLen: number[]) => P.ext('2.5.29.19', true, P.seq(P.bool(true), P.tlv(0x02, pathLen)));
    rejects(mkInt({ exts: [bc([0xff]), P.X.ku([5, 6])] }), /pathLenConstraint is negative/);
    rejects(mkInt({ exts: [bc([0x00, 0x01]), P.X.ku([5, 6])] }), /pathLenConstraint is not a minimally encoded INTEGER/);
    rejects(mkInt({ exts: [bc([]), P.X.ku([5, 6])] }), /pathLenConstraint is an empty INTEGER/);
    expect(parseCertificate(mkInt({ exts: [bc([0x00]), P.X.ku([5, 6])] })).basicConstraints).toEqual({ ca: true, pathLen: 0 });
    rejects(mkInt({ exts: [P.ext('2.5.29.19', true, P.seq(P.int(0), P.bool(true)))] }), /unexpected element in basicConstraints/);
    rejects(mkInt({ exts: [P.ext('2.5.29.19', true, P.cat(P.seq(P.bool(true)), [0x05, 0x00]))] }), /Trailing bytes after the basicConstraints/);
  });

  it('rejects duplicate extensions (CA:FALSE then CA:TRUE was read as a CA)', () => {
    rejects(mkInt({ exts: [P.X.bc(false), P.X.bc(true), P.X.ku([5, 6])] }), /more than one 2\.5\.29\.19 extension/);
    rejects(mkInt({ exts: [P.X.bc(true), P.X.bc(false), P.X.ku([5, 6])] }), /more than one 2\.5\.29\.19 extension/);
    rejects(mkInt({ exts: [P.X.bc(true), P.X.ku([0]), P.X.ku([5])] }), /more than one 2\.5\.29\.15 extension/);
    rejects(mkLeafRoot({ exts: [P.X.unknown(false), P.X.unknown(false)] }), /more than one 1\.3\.6\.1\.4\.1\.99999\.1 extension/);
  });

  it('rejects a signature algorithm that differs between tbsCertificate and the certificate', () => {
    rejects(mkLeafRoot({ innerAlg: P.ALG.ecdsaSha384 }), /signature algorithm inside tbsCertificate differs/);
    rejects(mkLeafRoot({ innerAlg: P.ALG.rsaSha1 }), /signature algorithm inside tbsCertificate differs/);
    rejects(mkLeafRoot({ innerAlg: P.seq(P.oid('1.2.840.10045.4.3.2'), P.nul()) }), /differs/);
    // ecdsa-with-SHA384 over a P-256 key is legitimate in X.509 when both fields say so
    expect(validate([mkLeafRoot({ alg: P.ALG.ecdsaSha384, hash: 'sha384' })]).valid).toBe(true);
  });

  it('rejects malformed times at parse, with an ordinary Error', () => {
    const T = (s: string, tag = 0x17) => P.rawTime(tag, s);
    const validity = (notAfter: Buffer) => mkLeafRoot({ rawValidity: P.seq(T('200101000000Z'), notAfter) });
    for (const bad of [T('XXXXXXXXXXXXZ'), T('2001020000Z'), T(''), T('210101000000+0100'), T('2101010000000'), T('211301000000Z'), T('210230000000Z'),
      T('210101240000Z'), T('210101006000Z'), T('210101000060Z'), T('20210101000000Z'), T('garbagegarbageZ', 0x18), T('20241332000000Z', 0x18),
      T('20200101000000.5Z', 0x18), T('20230229000000Z', 0x18), T('2020010100Z', 0x18), T('200101000000Z', 0x18), T('20200101000000Z', 0x13)]) {
      rejects(validity(bad), /DER: (time|a time)/);
    }
    expect(parseCertificate(validity(T('491231235959Z'))).notAfter.toISOString()).toBe('2049-12-31T23:59:59.000Z');
    expect(parseCertificate(validity(T('500101000000Z'))).notAfter.toISOString()).toBe('1950-01-01T00:00:00.000Z');
    expect(parseCertificate(validity(T('99991231235959Z', 0x18))).notAfter.toISOString()).toBe('9999-12-31T23:59:59.000Z');
    expect(parseCertificate(validity(T('20240229120000Z', 0x18))).notAfter.toISOString()).toBe('2024-02-29T12:00:00.000Z');
    // The validator is never reached with an invalid date: the same input used to throw RangeError inside it.
    let thrown: unknown;
    try { validate([validity(T('XXXXXXXXXXXXZ'))]); } catch (e) { thrown = e; }
    expect((thrown as Error).constructor).toBe(Error);
    expect((thrown as Error).message).toMatch(/time is not in the form UTCTime/);
  });

  it('rejects other encodings that are not DER or not X.509', () => {
    const unknownExt = (critical: number[]) => P.seq(P.oid('1.3.6.1.4.1.99999.1'), P.tlv(0x01, critical), P.octet(P.utf8('x')));
    rejects(mkLeafRoot({ exts: [unknownExt([0x01])] }), /not a DER BOOLEAN/);
    rejects(mkLeafRoot({ exts: [unknownExt([0xff, 0xff])] }), /not a DER BOOLEAN/);
    // an encoded critical FALSE is tolerated: it is signed and reads one way only
    expect(validate([mkLeafRoot({ exts: [unknownExt([0x00])] })]).valid).toBe(true);
    rejects(mkInt({ version: 'absent' }), /version 1 certificate cannot have extensions/);
    rejects(mkLeafRoot({ version: 1 }), /version 2 certificate cannot have extensions/);
    rejects(mkLeafRoot({ version: 7 }), /Unsupported certificate version 8/);
    rejects(mkLeafRoot({ version: 0, exts: [] }), /Unsupported certificate version 1/);
    rejects(mkLeafRoot({ exts: [P.ext('2.5.29.37', false, P.seq())] }), /extKeyUsage extension lists no key purpose/);
    rejects(mkLeafRoot({ exts: [P.ext('2.5.29.17', false, Buffer.from('example.com'))] }), /DER/);
    rejects(mkLeafRoot({ exts: [P.ext('2.5.29.15', true, P.bitstr([0x80], 9))] }), /invalid unused-bits count/);
    rejects(mkLeafRoot({ exts: [P.ext('2.5.29.15', true, P.bitstr([0x81], 1))] }), /non-zero unused bits/);
    // the signature BIT STRING must be whole octets
    const tbsLen = good.readUInt16BE(6) + 4;
    const bitStringAt = 4 + tbsLen + P.ALG.ecdsaSha256.length;
    expect(good[bitStringAt]).toBe(0x03);
    const unusedAt = bitStringAt + (good[bitStringAt + 1]! & 0x80 ? 2 + (good[bitStringAt + 1]! & 0x7f) : 2);
    const patched = Buffer.from(good);
    patched[unusedAt] = 7;
    rejects(patched, /signatureValue/);
  });
});

describe('names', () => {
  it('renders names unambiguously (RFC 2253 escaping, as the service writes them), so that equal strings mean equal names', () => {
    // one RDN whose value spells out the root's whole name: it used to render like the root's subject and chain to it
    const lookalike = P.cert({ subject: LEAF, issuer: [['CN', 'Root CA,O=Test,C=US']], key: leafKey, signer: rootKey });
    expect(parseCertificate(lookalike).issuer).toBe('CN=Root CA\\,O\\=Test\\,C\\=US');
    expect(parseCertificate(mkRoot()).subject).toBe('CN=Root CA,O=Test,C=US');
    const r = validate([lookalike]);
    expect(r.valid).toBe(false);
    expect(errors(r)).toEqual(['x509.no_anchor']);
    expect(parseCertificate(P.cert({ subject: [['CN', ' a+b;"c"<d>\\#e ']], issuer: ROOT, key: leafKey, signer: rootKey })).subject)
      .toBe('CN=\\ a\\+b\\;\\"c\\"\\<d\\>\\\\\\#e\\ ');
    // the same text in another string type is still the same name
    const printable = P.cert({ subject: LEAF, issuer: P.name(ROOT, P.printable), key: leafKey, signer: rootKey });
    expect(validate([printable]).valid).toBe(true);
    // a name with an empty RDN, or an attribute without a value, is malformed
    rejects(P.cert({ subject: P.seq(P.set()), issuer: ROOT, key: leafKey, signer: rootKey }), /RelativeDistinguishedName is empty/);
    rejects(P.cert({ subject: P.seq(P.set(P.seq(P.oid('2.5.4.3')))), issuer: ROOT, key: leafKey, signer: rootKey }), /AttributeTypeAndValue must have a type and a value/);
  });
});

describe('what the validator does not implement, it refuses', () => {
  const codes = (r: { issues: { code: string }[] }) => r.issues.map((i) => i.code);

  it('an unknown critical extension fails the path, wherever it is', () => {
    expect(errors(validate([mkLeafRoot({ exts: [P.X.unknown(true)] })]))).toEqual(['x509.path.unrecognized_critical_extension']);
    expect(errors(validate([mkLeaf(), mkInt({ exts: [...CA_EXTS, P.X.unknown(true)] })]))).toEqual(['x509.path.unrecognized_critical_extension']);
    const viaAnchor = validate([mkLeafRoot()], anchorOf(mkRoot({ exts: [...CA_EXTS, P.X.unknown(true)] })));
    expect(viaAnchor.valid).toBe(false);
    expect(viaAnchor.issues).toContainEqual({ code: 'x509.path.unrecognized_critical_extension', severity: 'ERROR', message: 'Trust anchor has unsupported critical extension 1.3.6.1.4.1.99999.1' });
    expect(errors(validate([mkLeaf(), mkInt({ exts: [...CA_EXTS, P.X.inhibitAnyPolicy(true)] })]))).toEqual(['x509.path.unrecognized_critical_extension']);
    expect(validate([mkLeaf(), mkInt({ exts: [...CA_EXTS, P.X.unknown(false)] })]).valid).toBe(true);
  });

  it('name constraints, critical or not, fail the path with a message that says why', () => {
    const san = [P.X.sanDns(['evil.example'])];
    for (const critical of [true, false]) {
      const nc = P.X.nameConstraintsDns(['good.example'], critical);
      const viaIntermediate = validate([mkLeaf({ exts: san }), mkInt({ exts: [...CA_EXTS, nc] })]);
      expect(viaIntermediate.valid, `critical=${critical}`).toBe(false);
      expect(errors(viaIntermediate)).toEqual(['x509.path.unsupported_constraints']);
      expect(viaIntermediate.issues.find((i) => i.severity === 'ERROR')!.message)
        .toBe('Certificate 1 carries name constraints (2.5.29.30), which this validator does not evaluate: the chain is refused rather than the constraint ignored');
      const viaAnchor = validate([mkLeafRoot({ exts: san })], anchorOf(mkRoot({ exts: [...CA_EXTS, nc] })));
      expect(viaAnchor.valid, `critical=${critical}`).toBe(false);
      expect(viaAnchor.issues.find((i) => i.severity === 'ERROR')!.message).toMatch(/^Trust anchor carries name constraints .* does not evaluate/);
      // also when the leaf would satisfy the constraint: it is not evaluated, so it cannot be honoured
      expect(validate([mkLeaf({ exts: [P.X.sanDns(['good.example'])] }), mkInt({ exts: [...CA_EXTS, nc] })]).valid).toBe(false);
    }
  });

  it('policy constraints, critical or not, fail the path', () => {
    for (const critical of [true, false]) {
      const r = validate([mkLeaf(), mkInt({ exts: [...CA_EXTS, P.X.policyConstraints(critical)] })]);
      expect(r.valid).toBe(false);
      expect(errors(r)).toEqual(['x509.path.unsupported_constraints']);
      expect(r.issues.find((i) => i.severity === 'ERROR')!.message).toMatch(/carries policy constraints \(2\.5\.29\.36\), which this validator does not evaluate/);
      expect(codes(validate([mkLeafRoot()], anchorOf(mkRoot({ exts: [...CA_EXTS, P.X.policyConstraints(critical)] }))))).toContain('x509.path.unsupported_constraints');
    }
  });

  it('contradictory CA fields and empty names fail the path', () => {
    // keyCertSign without CA, on a leaf
    expect(errors(validate([mkLeafRoot({ exts: [P.X.bc(false), P.X.ku([0, 5])] })]))).toEqual(['x509.path.inconsistent_ca']);
    // a path length on a certificate that is not a CA
    expect(errors(validate([mkLeafRoot({ exts: [P.ext('2.5.29.19', true, P.seq(P.int(0)))] })]))).toEqual(['x509.path.inconsistent_ca']);
    // an empty subject needs a critical subjectAltName
    const emptySubject = (exts: Buffer[]) => P.cert({ subject: [], issuer: ROOT, key: leafKey, signer: rootKey, exts });
    expect(errors(validate([emptySubject([P.X.sanDns(['a.example'], false)])]))).toEqual(['x509.path.invalid_name']);
    expect(validate([emptySubject([P.X.sanDns(['a.example'], true)])]).valid).toBe(true);
  });
});

describe('RSA key floor in certificates', () => {
  const RR: P.Rdns = [['CN', 'RSA Root']];
  const strong = P.rsaKey(2048);
  const weak = P.rsaKey(1024);

  it('verifies with RSA-2048 and not with RSA-1024', () => {
    const root = P.cert({ subject: RR, issuer: RR, key: strong, signer: strong, exts: CA_EXTS });
    const ok = validate([P.cert({ subject: LEAF, issuer: RR, key: leafKey, signer: strong })], anchorOf(root));
    expect(ok.valid, JSON.stringify(ok.issues)).toBe(true);
    const weakRoot = P.cert({ subject: RR, issuer: RR, key: weak, signer: weak, exts: CA_EXTS });
    const underWeakRoot = validate([P.cert({ subject: LEAF, issuer: RR, key: leafKey, signer: weak })], anchorOf(weakRoot));
    expect(underWeakRoot.valid).toBe(false);
    expect(errors(underWeakRoot)).toEqual(['x509.no_anchor']);
  });

  it('refuses a weak RSA key anywhere in the path, also in the leaf', () => {
    const weakInt = P.cert({ subject: INT, issuer: ROOT, key: weak, signer: rootKey, exts: CA_EXTS });
    const r = validate([P.cert({ subject: LEAF, issuer: INT, key: leafKey, signer: weak }), weakInt]);
    expect(r.valid).toBe(false);
    expect(errors(r)).toEqual(expect.arrayContaining(['x509.path.invalid_signature', 'x509.path.weak_key']));
    const weakLeaf = validate([mkLeafRoot({ key: weak })]);
    expect(errors(weakLeaf)).toEqual(['x509.path.weak_key']);
    expect(weakLeaf.issues.find((i) => i.severity === 'ERROR')!.message).toMatch(/the modulus has 1024 bits, fewer than 2048/);
  });

  it('refuses a public exponent of 1 or an even one', () => {
    const n = strong.publicKey.export({ format: 'jwk' }).n!;
    const modulus = BigInt(`0x${Buffer.from(n, 'base64url').toString('hex')}`);
    expect(errors(validate([mkLeafRoot({ spki: P.rsaSpki(modulus, 1n) })]))).toEqual(['x509.path.weak_key']);
    expect(errors(validate([mkLeafRoot({ spki: P.rsaSpki(modulus, 65536n) })]))).toEqual(['x509.path.weak_key']);
    expect(validate([mkLeafRoot({ spki: P.rsaSpki(modulus, 3n) })]).valid).toBe(true);
    // a root with e = 1 "signs" anything: the signature is the padded hash itself
    const forgedRoot = P.cert({ subject: RR, issuer: RR, spki: P.rsaSpki(modulus, 1n), signer: strong, exts: CA_EXTS });
    const forged = P.cert({ subject: LEAF, issuer: RR, key: leafKey, signer: strong, alg: P.ALG.rsaSha256, signWith: (tbs) => P.pkcs1Sha256Em(tbs) });
    const r = validate([forged], anchorOf(forgedRoot));
    expect(r.valid).toBe(false);
    expect(errors(r)).toEqual(['x509.no_anchor']);
  });
});
