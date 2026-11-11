import { describe, expect, it } from 'vitest';
import { parseCertificate, validateCertificateChain, extractIssuerInfo, type LocalAnchor } from '../src/primitives.js';
import { b64, fixture, pem } from './helpers.js';

const anchor = (name: string, domain: string, constraints: Record<string, unknown> = {}): LocalAnchor =>
  ({ certificate: parseCertificate(pem(name)), domain, constraints });

describe('certificate parsing', () => {
  it('parses extensions', () => {
    const ds = parseCertificate(pem('ds'));
    expect(ds.extendedKeyUsage).toContain('1.0.18013.5.1.2');
    expect(ds.keyUsage?.digitalSignature).toBe(true);
    expect(ds.basicConstraints?.ca).toBe(false);
    expect(ds.subject).toContain('CN=Utopia DS');
    expect(ds.authorityKeyIdentifier).toBe(parseCertificate(pem('iaca')).subjectKeyIdentifier);
    expect(parseCertificate(pem('rp')).dnsNames).toEqual(['verifier.example']);
  });

  it('rejects malformed DER lengths instead of looping (a 4-byte length must not wrap negative)', () => {
    expect(() => parseCertificate('MAYwhP////o=')).toThrow(/DER/);
    expect(() => parseCertificate('MIQAAAAB')).toThrow(/DER/);
    expect(() => parseCertificate('MAMwAQ==')).toThrow(/DER/);
  });

  it('parses the real Animo playground IACA', () => {
    const c = parseCertificate(new Uint8Array(fixture('animo-root-2024.der')));
    // RFC 4514 renders RDNs in reverse DER order; this certificate encodes CN before C.
    expect(c.subject).toBe('C=NL,CN=Animo');
    expect(c.basicConstraints).toEqual({ ca: true, pathLen: 0 });
    expect(c.keyUsage?.keyCertSign).toBe(true);
  });
});

describe('local path validation', () => {
  it('validates a Document Signer to its IACA', () => {
    const r = validateCertificateChain([pem('ds')], [anchor('iaca', 'mdoc-iaca')], { domain: 'mdoc-iaca' });
    expect(r.valid, JSON.stringify(r.issues)).toBe(true);
  });

  it('accepts chains that include the anchor and RSA signatures', () => {
    const r = validateCertificateChain([pem('rsa-leaf'), pem('rsa-root')], [anchor('rsa-root', 'credential-issuer')], { domain: 'credential-issuer' });
    expect(r.valid, JSON.stringify(r.issues)).toBe(true);
    expect(r.path).toHaveLength(1);
  });

  it('honours the status of a directly pinned anchor, as the service does', () => {
    const pinned = (status: string): LocalAnchor => ({ ...anchor('rp', 'verifier-access'), status });
    expect(validateCertificateChain([pem('rp')], [pinned('ACTIVE')], { domain: 'verifier-access' }).valid).toBe(true);
    const revoked = validateCertificateChain([pem('rp')], [pinned('REVOKED')], { domain: 'verifier-access' });
    expect(revoked.valid).toBe(false);
    expect(revoked.issues.map((i) => i.code)).toContain('x509.anchor_unusable');
  });

  it('reports unknown anchors without claiming invalidity', () => {
    const r = validateCertificateChain([pem('rogue-ds')], [anchor('iaca', 'mdoc-iaca')], { domain: 'mdoc-iaca' });
    expect(r.valid).toBe(false);
    expect(r.anchorFound).toBe(false);
  });

  it('enforces the ISO 18013-5 DS profile', () => {
    const noEku = validateCertificateChain([pem('ds-noeku')], [anchor('iaca', 'mdoc-iaca')], { domain: 'mdoc-iaca' });
    expect(noEku.issues.map((i) => i.code)).toContain('mdoc.ds.eku');
    const nl = validateCertificateChain([pem('ds-nl')], [anchor('iaca', 'mdoc-iaca')], { domain: 'mdoc-iaca' });
    expect(nl.issues.map((i) => i.code)).toContain('mdoc.ds.country');
  });

  it('checks verifier SAN and doctype constraints', () => {
    expect(validateCertificateChain([pem('rp')], [anchor('rp-ca', 'verifier-access')], { domain: 'verifier-access', expectedDnsName: 'verifier.example' }).valid).toBe(true);
    expect(validateCertificateChain([pem('rp')], [anchor('rp-ca', 'verifier-access')], { domain: 'verifier-access', expectedDnsName: 'evil.example' }).valid).toBe(false);
    const constrained = anchor('iaca', 'mdoc-iaca', { docTypes: ['org.iso.18013.5.1.mDL'] });
    expect(validateCertificateChain([pem('ds')], [constrained], { domain: 'mdoc-iaca', docType: 'eu.europa.ec.eudi.pid.1' }).valid).toBe(false);
  });

  it('rejects a chain at a time outside validity', () => {
    const r = validateCertificateChain([pem('ds')], [anchor('iaca', 'mdoc-iaca')], { domain: 'mdoc-iaca', time: new Date('2090-01-01') });
    expect(r.valid).toBe(false);
  });

  it('finds the anchor of the real MOSIP collab mDL signer (RSA root) and reports its profile violations as errors', () => {
    const sample = JSON.parse(fixture('mosip-mock-mdl.json').toString());
    const info = extractIssuerInfo(sample.credentials?.[0]?.credential ?? sample.credential, 'mso_mdoc');
    const root = fixture('mosip-mock-mdl-root.pem').toString();
    const strict = validateCertificateChain(info.x5c!, [{ certificate: parseCertificate(root), domain: 'mdoc-iaca' }], { domain: 'mdoc-iaca' });
    expect(strict.anchorFound).toBe(true);
    expect(strict.valid).toBe(false);
    expect(strict.issues.map((i) => i.code)).toEqual(expect.arrayContaining(['mdoc.ds.eku', 'mdoc.ds.is_ca']));
    // There is no relaxed profile any more: an anchor constraint cannot turn profile errors into warnings.
    const once = validateCertificateChain(info.x5c!, [{ certificate: parseCertificate(root), domain: 'mdoc-iaca', constraints: { relaxProfile: true } }], { domain: 'mdoc-iaca' });
    expect(once.valid).toBe(false);
    expect(once.issues.filter((i) => i.code.startsWith('mdoc.ds.')).every((i) => i.severity === 'ERROR')).toBe(true);
    expect(once.issues.map((i) => i.code)).not.toContain('x509.profile_relaxed');
    // Without a profile the path itself is sound.
    const plain = validateCertificateChain(info.x5c!, [{ certificate: parseCertificate(root), domain: 'mdoc-iaca' }]);
    expect(plain.valid, JSON.stringify(plain.issues)).toBe(true);
  });

  it('accepts base64 DER input', () => {
    expect(validateCertificateChain([b64(pem('ds'))], [anchor('iaca', 'mdoc-iaca')], { domain: 'mdoc-iaca' }).valid).toBe(true);
  });
});
