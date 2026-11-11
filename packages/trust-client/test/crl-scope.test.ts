/**
 * What a CRL may and may not prove: scope (issuingDistributionPoint), delta and indirect CRLs, removeFromCRL, several
 * CRLs for one issuer, critical extensions, and a CRL that states no nextUpdate. CRLs are built and signed at test
 * time (test/pki.ts). The rule under test: a certificate is good only when a complete, current CRL whose scope can
 * be evaluated does not list it.
 */
import { describe, expect, it } from 'vitest';
import { parseCertificate, parseCrl, validateCertificateChain, type HeldCrl, type LocalAnchor } from '../src/primitives.js';
import { MAX_CRL_AGE_WITHOUT_NEXT_UPDATE_MS } from '../src/x509/revocation.js';
import * as P from './pki.js';

const DAY = 86400_000;
const HOUR = 3600_000;
const ROOT: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'Root CA']];
const INT: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'Intermediate CA']];
const LEAF: P.Rdns = [['C', 'US'], ['O', 'Test'], ['CN', 'leaf.example']];
const rootKey = P.ecKey();
const intKey = P.ecKey();
const leafKey = P.ecKey();
const CA_EXTS = [P.X.bc(true), P.X.ku([5, 6])];
const DP = 'http://crl.example/root.crl';
const SERIAL = 0x1234n;
const root = P.cert({ subject: ROOT, issuer: ROOT, key: rootKey, signer: rootKey, exts: CA_EXTS });
const leaf = P.cert({ subject: LEAF, issuer: ROOT, key: leafKey, signer: rootKey, serial: SERIAL, exts: [P.X.ku([0]), P.X.crlDp([DP])] });
const leafNoDp = P.cert({ subject: LEAF, issuer: ROOT, key: leafKey, signer: rootKey, serial: SERIAL, exts: [P.X.ku([0])] });
const anchors: LocalAnchor[] = [{ certificate: parseCertificate(root), domain: 'test' }];
const mk = (o: Partial<P.CrlOptions> = {}) => P.crl({ issuer: ROOT, signer: rootKey, ...o });
const revoked = [{ serial: SERIAL }];
const ago = (ms: number) => new Date(Date.now() - ms);

/** The leaf's revocation status given these CRLs (in this order of preference). */
function status(crls: Uint8Array | Uint8Array[], o: { leaf?: Uint8Array; chain?: Uint8Array[]; index?: number } = {}) {
  const held: HeldCrl[] = (Array.isArray(crls) ? crls : [crls]).map((d) => ({ crl: parseCrl(d), source: 'test' }));
  const r = validateCertificateChain(o.chain ?? [o.leaf ?? leaf], anchors, { revocation: { crls: held, require: true } });
  const s = r.revocation![o.index ?? 0]!;
  // With require, anything but GOOD fails the chain.
  if (!o.chain) expect(r.valid).toBe(s.status === 'GOOD');
  return s;
}

describe('baseline', () => {
  it('a complete CRL decides: not listed, revoked, on hold', () => {
    expect(status(mk({ entries: [{ serial: 0x9999n }] }))).toMatchObject({ status: 'GOOD', method: 'crl' });
    expect(status(mk({ entries: revoked }))).toMatchObject({ status: 'REVOKED', reason: 'unspecified' });
    expect(status(mk({ entries: [{ serial: SERIAL, exts: [P.CX.reason(1)] }] }))).toMatchObject({ status: 'REVOKED', reason: 'keyCompromise' });
    expect(status(mk({ entries: [{ serial: SERIAL, exts: [P.CX.reason(6)] }] }))).toMatchObject({ status: 'ON_HOLD' });
    expect(status(mk({ exts: [P.CX.unknown(false)] })).status).toBe('GOOD');
    expect(status(mk({ exts: [P.CX.crlNumber(7)] })).status).toBe('GOOD');
  });
});

describe('issuing distribution point: a scope that cannot be evaluated does not cover the certificate', () => {
  it('a distribution point named by directoryName or relative to the issuer covers nothing here (was: everything)', () => {
    const byDirectoryName = mk({ exts: [P.CX.idp({ dirName: P.name([['CN', 'CRL partition 7']]) })] });
    expect(parseCrl(byDirectoryName).issuingDistributionPoint).toMatchObject({ uris: [], unsupportedName: true });
    expect(status(byDirectoryName)).toMatchObject({ status: 'UNKNOWN' });
    expect(status(byDirectoryName, { leaf: leafNoDp }).status).toBe('UNKNOWN');
    expect(status(mk({ exts: [P.CX.idp({ relativeName: true })] })).status).toBe('UNKNOWN');
    // a partition that cannot be matched to the certificate says nothing about it, whatever it lists
    expect(status(mk({ entries: revoked, exts: [P.CX.idp({ dirName: P.name([['CN', 'CRL partition 7']]) })] })).status).toBe('UNKNOWN');
  });

  it('a URI distribution point covers the certificates that name it', () => {
    expect(status(mk({ exts: [P.CX.idp({ uri: DP })] })).status).toBe('GOOD');
    expect(status(mk({ entries: revoked, exts: [P.CX.idp({ uri: DP })] })).status).toBe('REVOKED');
    expect(status(mk({ exts: [P.CX.idp({ uri: 'http://crl.example/partition2.crl' })] })).status).toBe('UNKNOWN');
    expect(status(mk({ exts: [P.CX.idp({ uri: DP })] }), { leaf: leafNoDp }).status).toBe('UNKNOWN');
    // a distribution point limited to some reasons, or naming another CRL issuer, does not place the certificate in the partition
    const dpWithReasons = P.ext('2.5.29.31', false, P.seq(P.seq(P.ctx(0, P.ctx(0, P.ctxp(6, Buffer.from(DP)))), P.ctxp(1, [0x01, 0x40]))));
    const partial = P.cert({ subject: LEAF, issuer: ROOT, key: leafKey, signer: rootKey, serial: SERIAL, exts: [dpWithReasons] });
    expect(parseCertificate(partial)).toMatchObject({ crlDistributionPoints: [DP], crlFullScopeUris: [] });
    expect(status(mk({ exts: [P.CX.idp({ uri: DP })] }), { leaf: partial }).status).toBe('UNKNOWN');
    expect(status(mk({}), { leaf: partial }).status).toBe('GOOD'); // a complete CRL covers it all the same
  });

  it('onlyContainsUserCerts / CACerts / AttributeCerts must match the certificate', () => {
    expect(status(mk({ exts: [P.CX.idp({ onlyUser: true })] })).status).toBe('GOOD');
    expect(status(mk({ exts: [P.CX.idp({ onlyCA: true })] })).status).toBe('UNKNOWN');
    expect(status(mk({ exts: [P.CX.idp({ onlyCA: true }, false)] })).status).toBe('UNKNOWN');
    expect(status(mk({ exts: [P.CX.idp({ onlyAttribute: true })] })).status).toBe('UNKNOWN');
    // an intermediate CA is not covered by a user-certificates CRL, and is by a CA-certificates CRL
    const int = P.cert({ subject: INT, issuer: ROOT, key: intKey, signer: rootKey, serial: 0x77n, exts: CA_EXTS });
    const below = P.cert({ subject: LEAF, issuer: INT, key: leafKey, signer: intKey });
    expect(status(mk({ exts: [P.CX.idp({ onlyUser: true })] }), { chain: [below, int], index: 1 }).status).toBe('UNKNOWN');
    expect(status(mk({ exts: [P.CX.idp({ onlyCA: true })] }), { chain: [below, int], index: 1 }).status).toBe('GOOD');
  });

  it('CRLs partitioned by reason and indirect CRLs never say good', () => {
    expect(status(mk({ exts: [P.CX.idp({ onlySomeReasons: true })] }))).toMatchObject({ status: 'UNKNOWN', reason: 'CRLs partitioned by reason are not supported' });
    expect(status(mk({ exts: [P.CX.idp({ indirect: true })] }))).toMatchObject({ status: 'UNKNOWN', reason: 'indirect CRLs are not supported' });
    expect(status(mk({ entries: [{ serial: 0x9999n, exts: [P.CX.certIssuer(P.name([['CN', 'Other CA']]))] }] })).status).toBe('UNKNOWN');
  });
});

describe('delta CRLs and removeFromCRL', () => {
  it('a delta CRL is not a complete list: not listed is not good', () => {
    expect(status(mk({ exts: [P.CX.delta()] }))).toMatchObject({ status: 'UNKNOWN', reason: 'delta CRLs are not supported' });
    // it can still show a revocation
    expect(status(mk({ entries: [{ serial: SERIAL, exts: [P.CX.reason(1)] }], exts: [P.CX.delta()] }))).toMatchObject({ status: 'REVOKED' });
    // and a complete CRL next to it decides the rest
    expect(status([mk({ exts: [P.CX.delta()] }), mk({})]).status).toBe('GOOD');
    expect(status(mk({ entries: [{ serial: SERIAL, exts: [P.CX.reason(8)] }], exts: [P.CX.delta()] })).status).toBe('UNKNOWN');
  });

  it('removeFromCRL in a complete CRL is not good on its own', () => {
    const r = status(mk({ entries: [{ serial: SERIAL, exts: [P.CX.reason(8)] }] }));
    expect(r).toMatchObject({ status: 'UNKNOWN', reason: expect.stringMatching(/removeFromCRL, which only a delta CRL may use/) });
    // listed twice, as revoked and as removed: the revocation stands, in either order
    for (const reasons of [[1, 8], [8, 1]]) {
      expect(status(mk({ entries: reasons.map((c) => ({ serial: SERIAL, exts: [P.CX.reason(c)] })) }))).toMatchObject({ status: 'REVOKED', reason: 'keyCompromise' });
    }
    expect(status(mk({ entries: [{ serial: SERIAL, exts: [P.CX.reason(6)] }, { serial: SERIAL, exts: [P.CX.reason(8)] }] })).status).toBe('ON_HOLD');
    // a CRL that lists some other serial twice is not a sound list: it does not prove this certificate good
    const twice = mk({ entries: [{ serial: 0x9999n }, { serial: 0x9999n }] });
    expect(parseCrl(twice).duplicateSerials).toBe(true);
    expect(status(twice)).toMatchObject({ status: 'UNKNOWN', reason: 'the CRL lists a serial number more than once' });
    expect(status([twice, mk({})]).status).toBe('GOOD');
  });
});

describe('several CRLs for one issuer', () => {
  const older = (o: Partial<P.CrlOptions> = {}) => mk({ thisUpdate: ago(6 * DAY), nextUpdate: new Date(Date.now() + DAY), ...o });
  const newer = (o: Partial<P.CrlOptions> = {}) => mk({ thisUpdate: ago(HOUR), ...o });

  it('a revocation in any current CRL wins, whatever the order they are held in', () => {
    expect(status([older(), newer({ entries: revoked })])).toMatchObject({ status: 'REVOKED' }); // was GOOD: the first CRL decided
    expect(status([newer({ entries: revoked }), older()]).status).toBe('REVOKED');
    expect(status([newer(), older({ entries: revoked })]).status).toBe('REVOKED');
    expect(status([older({ entries: revoked }), newer()]).status).toBe('REVOKED');
  });

  it('an older CRL does not override a newer one', () => {
    const hold = [{ serial: SERIAL, exts: [P.CX.reason(6)] }];
    // newly suspended: the older "not listed" must not win
    expect(status([older(), newer({ entries: hold })]).status).toBe('ON_HOLD');
    expect(status([newer({ entries: hold }), older()]).status).toBe('ON_HOLD');
    // the hold was lifted: the newer CRL no longer lists it
    expect(status([older({ entries: hold }), newer()]).status).toBe('GOOD');
    expect(status([newer(), older({ entries: hold })]).status).toBe('GOOD');
    // same thisUpdate: the higher CRL number is the newer one
    const at = ago(HOUR);
    expect(status([mk({ thisUpdate: at, exts: [P.CX.crlNumber(1)] }), mk({ thisUpdate: at, entries: hold, exts: [P.CX.crlNumber(2)] })]).status).toBe('ON_HOLD');
    // an expired CRL takes no part
    expect(status([mk({ thisUpdate: ago(10 * DAY), nextUpdate: ago(DAY), entries: revoked }), newer()]).status).toBe('GOOD');
  });
});

describe('critical extensions and freshness', () => {
  it('a CRL with an unknown critical extension, or an unknown critical entry extension, is not used', () => {
    expect(status(mk({ exts: [P.CX.unknown(true)] }))).toMatchObject({ status: 'UNKNOWN', reason: 'CRL has unsupported critical extension 1.3.6.1.4.1.99999.2' });
    // on another certificate's entry: the CRL as a whole cannot be used (RFC 5280 section 5.3)
    const onAnotherEntry = mk({ entries: [{ serial: 0x9999n, exts: [P.CX.unknown(true)] }] });
    expect(parseCrl(onAnotherEntry).unsupportedCritical).toEqual(['1.3.6.1.4.1.99999.2']);
    expect(status(onAnotherEntry)).toMatchObject({ status: 'UNKNOWN', reason: 'CRL has unsupported critical extension 1.3.6.1.4.1.99999.2' });
    expect(status(mk({ entries: [{ serial: 0x9999n, exts: [P.CX.unknown(false)] }] })).status).toBe('GOOD');
    expect(status(mk({ entries: [{ serial: 0x9999n, exts: [P.CX.reason(1, true)] }] })).status).toBe('GOOD');
  });

  it('a CRL without nextUpdate is current for seven days from thisUpdate', () => {
    expect(MAX_CRL_AGE_WITHOUT_NEXT_UPDATE_MS).toBe(7 * DAY);
    expect(status(mk({ thisUpdate: ago(HOUR), nextUpdate: null })).status).toBe('GOOD');
    expect(status(mk({ thisUpdate: ago(7 * DAY - HOUR), nextUpdate: null })).status).toBe('GOOD');
    expect(status(mk({ thisUpdate: ago(7 * DAY + HOUR), nextUpdate: null }))).toMatchObject({ status: 'UNKNOWN', reason: expect.stringMatching(/states no next update and was issued more than 7 days ago/) });
    expect(status(mk({ thisUpdate: ago(5 * 365 * DAY), nextUpdate: null })).status).toBe('UNKNOWN'); // was GOOD
    // an old CRL that is no longer current does not hide the revocation in a current one either
    expect(status([mk({ thisUpdate: ago(30 * DAY), nextUpdate: null }), mk({ entries: revoked })]).status).toBe('REVOKED');
    expect(status(mk({ thisUpdate: ago(10 * DAY), nextUpdate: ago(DAY) })).reason).toMatch(/^CRL expired at/);
    expect(status(mk({ thisUpdate: new Date(Date.now() + DAY), nextUpdate: new Date(Date.now() + 2 * DAY) })).reason).toMatch(/^CRL is not valid before/);
  });
});

describe('strict CRL parsing', () => {
  const rejects = (der: Uint8Array, message: RegExp) => {
    let thrown: unknown;
    try { parseCrl(der); } catch (e) { thrown = e; }
    expect(thrown, 'the CRL was accepted').toBeInstanceOf(Error);
    expect((thrown as Error).constructor).toBe(Error);
    expect((thrown as Error).message).toMatch(message);
  };

  it('rejects trailing bytes, extra elements, mismatched algorithms, bad times, duplicate extensions and non-minimal serials', () => {
    const good = mk({ entries: revoked });
    expect(parseCrl(good).entries.size).toBe(1);
    rejects(P.cat(good, [0x00]), /Trailing bytes after the CRL/);
    rejects(mk({ outerExtra: [P.utf8('x')] }), /exactly tbsCertList, signatureAlgorithm and signatureValue/);
    rejects(mk({ innerAlg: P.ALG.ecdsaSha384 }), /signature algorithm inside tbsCertList differs/);
    rejects(mk({ rawNextUpdate: P.rawTime(0x17, 'XXXXXXXXXXXXZ') }), /time is not in the form UTCTime/);
    rejects(mk({ exts: [P.CX.crlNumber(1), P.CX.crlNumber(2)] }), /more than one 2\.5\.29\.20 extension/);
    rejects(mk({ entries: [{ serial: Buffer.from([0, 0, 0x12, 0x34]) }] }), /not a minimally encoded INTEGER/);
    rejects(mk({ exts: [P.ext('2.5.29.28', true, P.seq(P.ctxp(1, [0x01])))] }), /not a DER BOOLEAN/);
    rejects(mk({ exts: [P.ext('2.5.29.28', true, P.seq(P.ctxp(2, [0xff]), P.ctxp(1, [0xff])))] }), /unexpected element in issuingDistributionPoint/);
  });
});
