/**
 * The reference PKI. An IACA and a Document Signer following ISO/IEC 18013-5 Annex B (B.1.2 and B.1.4), the IACA CRL
 * of the same annex, an issuer CA with an SD-JWT VC signing certificate, and a verifier access CA with a relying-party certificate.
 * Keys are P-256. Path building, signatures and CRLs come from @peculiar/x509.
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { randomBytes, webcrypto } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

x509.cryptoProvider.set(webcrypto);

const KEY = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN = { name: 'ECDSA', hash: 'SHA-256' };
const DAY = 86_400_000;
const CERTIFICATES = ['iaca', 'ds', 'issuerCa', 'issuerSigner', 'verifierCa', 'verifier'];
/** ISO/IEC 18013-5 Annex B: the mdoc Document Signer extended key usage. */
export const MDOC_DS_EKU = '1.0.18013.5.1.2';

/** A positive, random serial number (RFC 5280: at most 20 octets; ISO 18013-5: at least 63 bits of entropy). */
const serial = () => { const b = randomBytes(16); b[0] = (b[0] & 0x7f) | 0x01; return b.toString('hex'); };
const generate = () => webcrypto.subtle.generateKey(KEY, true, ['sign', 'verify']);
const jwk = (k) => webcrypto.subtle.exportKey('jwk', k);
/** A distinguished name as Annex B.1.1 encodes it: countryName is a PrintableString, the other attributes are UTF8Strings. */
const dn = (commonName, organization) => new x509.Name([
  { C: [{ printableString: 'UT' }] }, { O: [{ utf8String: organization }] }, { CN: [{ utf8String: commonName }] }]);

async function root({ name, days, now, extensions = [] }) {
  const keys = await generate();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(), name, notBefore: new Date(now - DAY), notAfter: new Date(now + days * DAY), signingAlgorithm: SIGN, keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ...extensions,
    ],
  });
  return { cert, keys };
}

/** An end-entity certificate: no basicConstraints (absent means "not a CA"; Annex B lists none for a Document Signer). */
async function leaf({ subject, ca, days, now, extensions = [] }) {
  const keys = await generate();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(), subject, issuer: ca.cert.subjectName, notBefore: new Date(now - DAY), notAfter: new Date(now + days * DAY),
    signingAlgorithm: SIGN, publicKey: keys.publicKey, signingKey: ca.keys.privateKey,
    extensions: [
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(ca.cert),
      ...extensions,
    ],
  });
  return { cert, keys };
}

/**
 * A complete CRL of the CA (Annex B CRL profile: authorityKeyIdentifier and cRLNumber): the given serial numbers are revoked.
 * @param {{ cert: x509.X509Certificate, keys: { privateKey: CryptoKey } }} ca from loadCa
 * @param {string[]} revokedSerials hex serial numbers
 * @returns {Promise<Uint8Array>} DER
 */
export async function createCrl(ca, revokedSerials, { now = Date.now(), number = 1 } = {}) {
  const crl = await x509.X509CrlGenerator.create({
    issuer: ca.cert.subjectName, thisUpdate: new Date(now - 60_000), nextUpdate: new Date(now + 7 * DAY), signingAlgorithm: SIGN,
    signingKey: ca.keys.privateKey,
    entries: revokedSerials.map((serialNumber) => ({ serialNumber, revocationDate: new Date(now - 60_000), reason: x509.X509CrlReason.keyCompromise })),
    extensions: [await x509.AuthorityKeyIdentifierExtension.create(ca.cert), new x509.Extension('2.5.29.20', false, crlNumber(number))],
  });
  return new Uint8Array(crl.rawData);
}

/** DER INTEGER for the cRLNumber extension. */
function crlNumber(n) {
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  if (bytes.length === 0 || bytes[0] & 0x80) bytes.unshift(0);
  return new Uint8Array([0x02, bytes.length, ...bytes]);
}

/**
 * @typedef {{ pem: string, serialNumber: string, privateJwk: JsonWebKey, publicJwk: JsonWebKey }} PkiEntry
 * @typedef {{ issuerUrl: string, verifierHost: string, crlUrl: string, iaca: PkiEntry, ds: PkiEntry, issuerCa: PkiEntry,
 *   issuerSigner: PkiEntry, verifierCa: PkiEntry, verifier: PkiEntry }} Pki
 */

/**
 * @param {{ issuerUrl: string, verifierHost: string, now?: number }} opts issuerUrl hosts the CRL and names the issuer in
 *   the certificates; verifierHost is the relying party's DNS name (SAN dNSName)
 * @returns {Promise<Pki>}
 */
export async function generatePki({ issuerUrl, verifierHost, now = Date.now() }) {
  const crlUrl = `${issuerUrl}/pki/iaca.crl`;
  // Annex B.1.2 (IACA) and B.1.4 (DS): issuerAltName and a CRL distribution point are mandatory in both.
  const iacaExtras = () => [
    new x509.IssuerAlternativeNameExtension([{ type: 'url', value: issuerUrl }]),
    new x509.CRLDistributionPointsExtension([crlUrl]),
  ];
  const iaca = await root({ name: dn('Reference IACA', 'Reference DMV'), days: 3650, now, extensions: iacaExtras() });
  // Annex B.1.4: a Document Signer is valid for at most 457 days and carries the mdoc DS extended key usage.
  const ds = await leaf({ subject: dn('Reference Document Signer', 'Reference DMV'), ca: iaca, days: 400, now,
    extensions: [new x509.ExtendedKeyUsageExtension([MDOC_DS_EKU], true), ...iacaExtras()] });

  const issuerCa = await root({ name: dn('Reference Issuer CA', 'Reference Registry'), days: 3650, now });
  // SD-JWT VC, issuer key in x5c: the leaf names the issuer (SAN URI), which is what binds the `iss` claim to the certificate.
  const issuerSigner = await leaf({ subject: dn('Reference Credential Issuer', 'Reference Registry'), ca: issuerCa, days: 400, now,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'url', value: issuerUrl }])] });

  const verifierCa = await root({ name: dn('Reference Verifier Access CA', 'Reference Registrar'), days: 3650, now });
  const verifier = await leaf({ subject: dn(verifierHost, 'Reference Verifier'), ca: verifierCa, days: 400, now,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: verifierHost }])] });

  const pki = { issuerUrl, verifierHost, crlUrl };
  for (const [name, e] of Object.entries({ iaca, ds, issuerCa, issuerSigner, verifierCa, verifier })) {
    pki[name] = { pem: e.cert.toString('pem'), serialNumber: e.cert.serialNumber, privateJwk: await jwk(e.keys.privateKey), publicJwk: await jwk(e.keys.publicKey) };
  }
  return pki;
}

/**
 * The PKI of a data directory: created and written to `pki.json` on first use, read from it afterwards, so the trust
 * anchors stay the same across restarts. The certificates name the issuer URL, so a stored PKI serves that URL only.
 * @param {string} dataDir
 * @param {{ issuerUrl: string, verifierHost: string }} opts
 * @returns {Promise<Pki>}
 */
export async function loadOrCreatePki(dataDir, opts) {
  const file = join(dataDir, 'pki.json');
  if (!existsSync(file)) {
    const pki = await generatePki(opts);
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(file, JSON.stringify(pki, null, 2), { mode: 0o600 });
    return pki;
  }
  const pki = JSON.parse(readFileSync(file, 'utf8'));
  if (pki.issuerUrl !== opts.issuerUrl || pki.verifierHost !== opts.verifierHost) {
    throw new Error(`${file} was created for issuer ${pki.issuerUrl} and verifier host ${pki.verifierHost}; use those again or remove the file`);
  }
  const expired = CERTIFICATES.find((name) => new x509.X509Certificate(pki[name].pem).notAfter < new Date());
  if (expired) throw new Error(`The ${expired} certificate in ${file} has expired; remove the file to create a new PKI`);
  return pki;
}

/** Re-creates the signing material of a stored entry (for CRLs issued later). */
export async function loadCa(entry) {
  return { cert: new x509.X509Certificate(entry.pem), keys: { privateKey: await webcrypto.subtle.importKey('jwk', entry.privateJwk, KEY, false, ['sign']) } };
}

/**
 * Certification path validation as far as this ecosystem needs it (RFC 5280 section 6 without policies and name
 * constraints): a signature-verified path to a trust anchor, validity periods, and CA certificates as issuers.
 * @param {Uint8Array[]} chain DER certificates, the end-entity certificate first
 * @param {Uint8Array[]} trustAnchors DER
 * @returns {Promise<Uint8Array[]>} the validated path, end-entity certificate first, trust anchor last
 */
export async function validateChain(chain, trustAnchors, now = new Date()) {
  const [target, ...others] = chain.map((der) => new x509.X509Certificate(der));
  const path = await new x509.X509ChainBuilder({ certificates: others })
    .buildToAnchor(target, { trustAnchors: trustAnchors.map((der) => new x509.X509Certificate(der)) });
  path.forEach((cert, i) => {
    if (!(now >= cert.notBefore && now <= cert.notAfter)) throw new Error(`Certificate '${cert.subject}' is not valid at ${now.toISOString()}`);
    if (i === 0) return;
    const usage = cert.getExtension(x509.KeyUsagesExtension)?.usages ?? 0;
    if (!cert.getExtension(x509.BasicConstraintsExtension)?.ca || !(usage & x509.KeyUsageFlags.keyCertSign)) {
      throw new Error(`Certificate '${cert.subject}' may not issue certificates`);
    }
  });
  return path.map((cert) => new Uint8Array(cert.rawData));
}

/**
 * Whether the CRL at the certificate's distribution point lists it (RFC 5280 section 6.3, complete CRLs by the
 * certificate's own issuer only). A CRL that cannot be fetched, is not signed by the issuer or is past nextUpdate throws.
 * @param {Uint8Array} certificate DER
 * @param {Uint8Array} issuer DER, the certificate that issued it
 * @param {typeof fetch} [fetcher]
 */
export async function isRevoked(certificate, issuer, fetcher = fetch, now = new Date()) {
  const cert = new x509.X509Certificate(certificate);
  const url = cert.getExtension(x509.CRLDistributionPointsExtension)?.distributionPoints[0]?.distributionPoint?.fullName?.[0]?.uniformResourceIdentifier;
  if (!url) throw new Error(`Certificate '${cert.subject}' has no CRL distribution point`);
  const response = await fetcher(url);
  if (!response.ok) throw new Error(`CRL ${url} answered ${response.status}`);
  const crl = new x509.X509Crl(new Uint8Array(await response.arrayBuffer()));
  if (!(await crl.verify({ publicKey: new x509.X509Certificate(issuer) }))) throw new Error(`CRL ${url} is not signed by the issuer of '${cert.subject}'`);
  if (!crl.nextUpdate || crl.nextUpdate < now) throw new Error(`CRL ${url} is out of date`);
  return crl.findRevoked(cert) !== null;
}

export const derOf = (pem) => new Uint8Array(new x509.X509Certificate(pem).rawData);
export const b64Der = (pem) => pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
