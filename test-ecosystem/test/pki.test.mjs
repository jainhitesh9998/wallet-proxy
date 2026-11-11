/**
 * The reference PKI against the certificate and CRL profiles of ISO/IEC 18013-5 Annex B (IACA root certificate B.1.2,
 * Document Signer certificate B.1.4, CRL profile), read back with @peculiar/x509.
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createHash, webcrypto } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { createCrl, derOf, generatePki, isRevoked, loadCa, loadOrCreatePki, MDOC_DS_EKU, validateChain } from '../src/pki.mjs';

const OID = { subjectKeyIdentifier: '2.5.29.14', keyUsage: '2.5.29.15', subjectAltName: '2.5.29.17', issuerAltName: '2.5.29.18', basicConstraints: '2.5.29.19',
  cRLNumber: '2.5.29.20', cRLDistributionPoints: '2.5.29.31', authorityKeyIdentifier: '2.5.29.35', extKeyUsage: '2.5.29.37' };
const DAY = 86_400_000;
const names = { issuerUrl: 'http://localhost:8791', verifierHost: 'localhost' };

const extension = (cert, oid) => cert.extensions.find((e) => e.type === oid);
const extensionOids = (cert) => cert.extensions.map((e) => e.type).sort();
const criticalOids = (cert) => cert.extensions.filter((e) => e.critical).map((e) => e.type).sort();
const der = (name) => Buffer.from(name.toArrayBuffer()).toString('hex');
const generalNames = (ext) => ext.names.items.map(({ type, value }) => `${type}:${value}`);
const crlUrls = (cert) => extension(cert, OID.cRLDistributionPoints).distributionPoints.flatMap((p) => p.distributionPoint.fullName.map((n) => n.uniformResourceIdentifier));
/** RFC 5280 section 4.2.1.2 method 1: SHA-1 of the subjectPublicKey bit string, here the uncompressed EC point. */
const keyIdentifier = async (cert) => createHash('sha1').update(Buffer.from(await webcrypto.subtle.exportKey('raw', await cert.publicKey.export()))).digest('hex');

describe('reference PKI', () => {
  let pki;
  let iaca;
  let ds;
  beforeAll(async () => {
    pki = await generatePki(names);
    iaca = new x509.X509Certificate(pki.iaca.pem);
    ds = new x509.X509Certificate(pki.ds.pem);
  });

  it('issues an IACA root certificate that meets Annex B.1.2', async () => {
    expect(await iaca.isSelfSigned()).toBe(true);
    expect(der(iaca.issuerName)).toBe(der(iaca.subjectName));
    // Serial number: positive, at most 20 octets, at least 63 bits from a CSPRNG (here 126).
    expect(iaca.serialNumber).toMatch(/^[0-7][0-9a-f]{31}$/);
    // countryName is mandatory, an ISO 3166-1 alpha-2 shaped code, and a PrintableString (tag 0x13) of two characters.
    expect(iaca.subjectName.getField('C')).toEqual(['UT']);
    expect(der(iaca.subjectName)).toContain(`0603550406${'1302'}${Buffer.from('UT').toString('hex')}`);
    expect(iaca.subjectName.getField('CN')).toHaveLength(1);
    expect(iaca.notAfter - iaca.notBefore).toBeLessThanOrEqual(20 * 365.25 * DAY);
    expect(iaca.signatureAlgorithm).toMatchObject({ name: 'ECDSA', hash: { name: 'SHA-256' } });
    expect(iaca.publicKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });

    expect(extensionOids(iaca)).toEqual([OID.subjectKeyIdentifier, OID.keyUsage, OID.issuerAltName, OID.basicConstraints, OID.cRLDistributionPoints].sort());
    expect(criticalOids(iaca)).toEqual([OID.keyUsage, OID.basicConstraints].sort());
    expect(extension(iaca, OID.basicConstraints)).toMatchObject({ ca: true, pathLength: 0 });
    expect(extension(iaca, OID.keyUsage).usages).toBe(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign);
    expect(extension(iaca, OID.subjectKeyIdentifier).keyId).toBe(await keyIdentifier(iaca));
    expect(generalNames(extension(iaca, OID.issuerAltName))).toEqual([`url:${names.issuerUrl}`]);
    expect(crlUrls(iaca)).toEqual([pki.crlUrl]);
  });

  it('issues a Document Signer certificate that meets Annex B.1.4', async () => {
    expect(der(ds.issuerName)).toBe(der(iaca.subjectName));
    expect(await ds.verify({ publicKey: iaca.publicKey, signatureOnly: true })).toBe(true);
    expect(ds.serialNumber).toMatch(/^[0-7][0-9a-f]{31}$/);
    expect(ds.subjectName.getField('C')).toEqual(iaca.subjectName.getField('C'));
    expect(ds.notAfter - ds.notBefore).toBeLessThanOrEqual(457 * DAY);
    expect(ds.notBefore >= iaca.notBefore && ds.notAfter <= iaca.notAfter).toBe(true);
    expect(ds.signatureAlgorithm).toMatchObject({ name: 'ECDSA', hash: { name: 'SHA-256' } });

    // No basicConstraints: the profile lists none, and its absence means the certificate is not a CA.
    expect(extensionOids(ds)).toEqual([OID.subjectKeyIdentifier, OID.keyUsage, OID.issuerAltName, OID.cRLDistributionPoints, OID.authorityKeyIdentifier, OID.extKeyUsage].sort());
    expect(criticalOids(ds)).toEqual([OID.keyUsage, OID.extKeyUsage].sort());
    expect(extension(ds, OID.keyUsage).usages).toBe(x509.KeyUsageFlags.digitalSignature);
    expect(extension(ds, OID.extKeyUsage).usages).toEqual([MDOC_DS_EKU]);
    expect(extension(ds, OID.authorityKeyIdentifier).keyId).toBe(extension(iaca, OID.subjectKeyIdentifier).keyId);
    expect(extension(ds, OID.subjectKeyIdentifier).keyId).toBe(await keyIdentifier(ds));
    expect(generalNames(extension(ds, OID.issuerAltName))).toEqual(generalNames(extension(iaca, OID.issuerAltName)));
    expect(crlUrls(ds)).toEqual([pki.crlUrl]);
  });

  it('issues a CRL in the Annex B profile that revokes the Document Signer', async () => {
    const ca = await loadCa(pki.iaca);
    const revoking = await createCrl(ca, [pki.ds.serialNumber], { number: 258 });
    const crl = new x509.X509Crl(revoking);
    expect(der(crl.issuerName)).toBe(der(iaca.subjectName));
    expect(await crl.verify({ publicKey: iaca })).toBe(true);
    expect(crl.nextUpdate > crl.thisUpdate).toBe(true);
    expect(extension(crl, OID.authorityKeyIdentifier).keyId).toBe(extension(iaca, OID.subjectKeyIdentifier).keyId);
    // cRLNumber: a non-critical INTEGER, here 258 = 0x0102.
    expect(extension(crl, OID.cRLNumber).critical).toBe(false);
    expect(Buffer.from(extension(crl, OID.cRLNumber).value).toString('hex')).toBe('02020102');
    expect(crl.findRevoked(ds)?.reason).toBe(x509.X509CrlReason.keyCompromise);

    const serving = (bytes) => async () => new Response(bytes);
    expect(await isRevoked(derOf(pki.ds.pem), derOf(pki.iaca.pem), serving(revoking))).toBe(true);
    expect(await isRevoked(derOf(pki.ds.pem), derOf(pki.iaca.pem), serving(await createCrl(ca, [])))).toBe(false);
    // A CRL of another CA says nothing about this certificate.
    const foreign = await createCrl(await loadCa(pki.issuerCa), []);
    await expect(isRevoked(derOf(pki.ds.pem), derOf(pki.iaca.pem), serving(foreign))).rejects.toThrow(/not signed by the issuer/);
  });

  it('issues the SD-JWT VC signer and relying-party certificates under their own roots', async () => {
    const signer = new x509.X509Certificate(pki.issuerSigner.pem);
    const relyingParty = new x509.X509Certificate(pki.verifier.pem);
    expect(generalNames(extension(signer, OID.subjectAltName))).toEqual([`url:${names.issuerUrl}`]);
    expect(generalNames(extension(relyingParty, OID.subjectAltName))).toEqual([`dns:${names.verifierHost}`]);
    for (const leaf of [signer, relyingParty]) {
      expect(extension(leaf, OID.basicConstraints)).toBeUndefined();
      expect(extension(leaf, OID.keyUsage).usages).toBe(x509.KeyUsageFlags.digitalSignature);
    }
    expect(await validateChain([derOf(pki.issuerSigner.pem)], [derOf(pki.issuerCa.pem)])).toHaveLength(2);
    expect(await validateChain([derOf(pki.verifier.pem)], [derOf(pki.verifierCa.pem)])).toHaveLength(2);
    // Each root anchors its own leaves only, and an end-entity certificate cannot issue.
    await expect(validateChain([derOf(pki.ds.pem)], [derOf(pki.issuerCa.pem)])).rejects.toThrow();
    await expect(validateChain([derOf(pki.ds.pem), derOf(pki.issuerSigner.pem)], [derOf(pki.issuerSigner.pem)])).rejects.toThrow();
    await expect(validateChain([derOf(pki.ds.pem)], [derOf(pki.iaca.pem)], new Date(ds.notAfter.getTime() + DAY))).rejects.toThrow(/not valid/);
  });

  it('keeps the PKI of a data directory across restarts', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'reference-pki-'));
    try {
      const first = await loadOrCreatePki(dir, names);
      const second = await loadOrCreatePki(dir, names);
      expect(second).toEqual(first);
      expect(first.iaca.pem).not.toBe(pki.iaca.pem);
      await expect(loadOrCreatePki(dir, { ...names, issuerUrl: 'http://localhost:9999' })).rejects.toThrow(/was created for issuer/);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
