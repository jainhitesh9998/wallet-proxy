/** CRL parsing and revocation checks (device side; the service's RevocationChecker applies the same rules). */
import { describe, expect, it } from 'vitest';
import { checkRevocation, parseCertificate, parseCrl, validateCertificateChain, type HeldCrl } from '../src/index.js';
import { fixture, pem } from './helpers.js';

const crlDer = () => new Uint8Array(fixture('pki/iaca.crl'));
const iaca = parseCertificate(pem('iaca'));
const anchors = [{ certificate: iaca, domain: 'mdoc-iaca' }];
const held = (c = parseCrl(crlDer())): HeldCrl[] => [{ crl: c, source: 'snapshot' }];
const validate = (name: string, crls: HeldCrl[] = held(), require = false) =>
  validateCertificateChain([pem(name)], anchors, { domain: 'mdoc-iaca', revocation: { crls, require } });

describe('CRL parsing', () => {
  it('reads issuer, validity, number and revoked entries with reasons', () => {
    const c = parseCrl(crlDer());
    expect(c.issuer).toBe('CN=Utopia IACA,O=Utopia DMV,C=UT');
    expect(c.crlNumber).toBe('1');
    expect(c.nextUpdate!.getUTCFullYear()).toBeGreaterThanOrEqual(2045);
    expect(c.authorityKeyIdentifier).toBe(iaca.subjectKeyIdentifier);
    const reasons = [...c.entries.values()].map((e) => e.reason).sort();
    expect(reasons).toEqual([1, 6]);
    expect(c.entries.has(parseCertificate(pem('ds-revoked')).serialNumber.replace(/^0+/, '').toLowerCase())).toBe(true);
  });

  it('accepts PEM and reads CRL distribution points and OCSP URLs from certificates', () => {
    const b64 = Buffer.from(crlDer()).toString('base64');
    expect(parseCrl(`-----BEGIN X509 CRL-----\n${b64}\n-----END X509 CRL-----`).entries.size).toBe(2);
    expect(parseCertificate(pem('ds-revoked')).crlDistributionPoints).toEqual(['http://crl.utopia.example/iaca.crl']);
    expect(parseCertificate(pem('ds-ocsp')).ocspUrls).toEqual(['http://ocsp.utopia.example']);
    expect(parseCertificate(pem('ds')).crlDistributionPoints).toEqual([]);
  });
});

describe('revocation', () => {
  it('a complete CRL from the anchor covers its certificates, with or without a distribution point', () => {
    for (const name of ['ds', 'ds-crldp']) {
      const r = validate(name);
      expect(r.valid).toBe(true);
      expect(r.revocation).toEqual([expect.objectContaining({ index: 0, status: 'GOOD', method: 'crl', source: 'snapshot' })]);
      expect(r.issues.map((i) => i.code)).toContain('x509.not_revoked');
    }
  });

  it('rejects revoked and suspended certificates', () => {
    const revoked = validate('ds-revoked');
    expect(revoked.valid).toBe(false);
    expect(revoked.revocation![0]).toMatchObject({ status: 'REVOKED', reason: 'keyCompromise' });
    expect(revoked.issues.find((i) => i.severity === 'ERROR')?.code).toBe('x509.revoked');
    const hold = validate('ds-hold');
    expect(hold.revocation![0]).toMatchObject({ status: 'ON_HOLD', reason: 'certificateHold' });
    expect(hold.issues.find((i) => i.severity === 'ERROR')?.code).toBe('x509.on_hold');
  });

  it('an unknown status is a warning, or an error when the policy requires a status', () => {
    const lenient = validate('ds-revoked', []);
    expect(lenient.valid).toBe(true);
    expect(lenient.issues.find((i) => i.code === 'x509.revocation_unknown')).toMatchObject({ severity: 'WARNING' });
    expect(lenient.revocation![0]!.reason).toMatch(/not been obtained/);
    const strict = validate('ds-revoked', [], true);
    expect(strict.valid).toBe(false);
    expect(validate('ds', [], true).revocation![0]!.reason).toBe('no CRL is published for it');
    expect(validate('ds-ocsp', [], true).revocation![0]!.reason).toMatch(/only OCSP, which this device does not use/);
  });

  it('never uses an expired, forged or foreign CRL', () => {
    const expired = parseCrl(crlDer());
    expired.nextUpdate = new Date(Date.now() - 1000);
    expect(validate('ds-revoked', held(expired)).revocation![0]).toMatchObject({ status: 'UNKNOWN', reason: expect.stringMatching(/^CRL expired at/) });
    const forged = crlDer();
    forged[forged.length - 3]! ^= 0xff;
    expect(validate('ds-revoked', held(parseCrl(forged))).revocation![0]).toMatchObject({ status: 'UNKNOWN', reason: 'CRL signature does not verify' });
    const delta = parseCrl(crlDer());
    delta.delta = true;
    expect(validate('ds', held(delta)).revocation![0]!.reason).toBe('delta CRLs are not supported');
    const rogue = validateCertificateChain([pem('rogue-ds')], [{ certificate: parseCertificate(pem('rogue-iaca')), domain: 'mdoc-iaca' }],
      { domain: 'mdoc-iaca', revocation: { crls: held() } });
    expect(rogue.revocation![0]!.status).toBe('UNKNOWN');
  });

  it('honours the issuing distribution point scope', () => {
    const caOnly = parseCrl(crlDer());
    caOnly.issuingDistributionPoint = { uris: [], onlyContainsUserCerts: false, onlyContainsCACerts: true, onlySomeReasons: false, indirectCRL: false, onlyContainsAttributeCerts: false };
    expect(validate('ds-revoked', held(caOnly)).revocation![0]!.status).toBe('UNKNOWN');
    const partition = parseCrl(crlDer());
    partition.issuingDistributionPoint = { ...caOnly.issuingDistributionPoint, onlyContainsCACerts: false, uris: ['http://crl.utopia.example/other.crl'] };
    expect(validate('ds-revoked', held(partition)).revocation![0]!.status).toBe('UNKNOWN');
    partition.issuingDistributionPoint.uris = ['http://crl.utopia.example/iaca.crl'];
    expect(validate('ds-revoked', held(partition)).revocation![0]!.status).toBe('REVOKED');
  });

  it('does not check a directly pinned certificate (it is an anchor)', () => {
    const r = validateCertificateChain([pem('ds-revoked')], [{ certificate: parseCertificate(pem('ds-revoked')), domain: 'mdoc-iaca' }],
      { revocation: { crls: held() } });
    expect(r.valid).toBe(true);
    expect(r.revocation).toBeUndefined();
    expect(checkRevocation([], iaca, new Date(), { crls: [] }).statuses).toEqual([]);
  });
});
