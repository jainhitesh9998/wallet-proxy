/**
 * What an operator requires of a certificate chain on top of RFC 5280 and the built-in profile of the question: the
 * {@code x509.profile} of a trust mechanism (evaluation/mechanisms.ts). The service applies the same requirements
 * (CertificateRequirements.java); each member is one check, reported with a code of its own when it fails.
 *
 * Only what this parser and the service's read alike is a member: the basic constraints' CA flag, the first seven key
 * usage bits, the extended key usages as dotted OIDs, the subject's first text country, the two validity dates, the URIs
 * of the CRL distribution points, and the length of the path.
 */
import type { Certificate, KeyUsage } from './certificate.js';
import type { ValidationIssue } from '../types.js';

/** The key usage bits by their RFC 5280 names, in bit order: the ones this parser reads. */
export const KEY_USAGE_BITS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign'] as const;
export type KeyUsageBit = (typeof KEY_USAGE_BITS)[number];

export interface CertificateRequirements {
  leaf?: {
    /** the signing certificate is not a CA ({@code profile.leaf_is_ca}) */
    ca?: false;
    /** the key usage extension is present and asserts each of these bits ({@code profile.key_usage}) */
    keyUsage?: KeyUsageBit[];
    /** each of these OIDs is among the extended key usages ({@code profile.extended_key_usage}) */
    extendedKeyUsage?: string[];
    /** the leaf and the anchor both name a country, and the same one ({@code profile.country}) */
    sameCountryAsAnchor?: true;
    /** the leaf's notAfter is at most this many days after its notBefore ({@code profile.validity}) */
    maxValidityDays?: number;
    /** the leaf names an http(s) CRL distribution point ({@code profile.crl_distribution_point}) */
    crlDistributionPoint?: true;
  };
  /** at most this many CA certificates between the leaf and the anchor ({@code profile.path_length}) */
  maxIntermediates?: number;
}

const DAY_MS = 86_400_000;
/** ASCII only, as the service reads it: a CRL location is an IA5String. */
const HTTP_URL = /^https?:\/\//i;

/**
 * @param path   the validated path, leaf first, without the anchor
 * @param anchor the trust anchor's certificate
 */
export function requirementIssues(req: CertificateRequirements, path: Certificate[], anchor: Certificate): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (code: string, message: string) => issues.push({ code, message, severity: 'ERROR' });
  const leaf = path[0]!;
  const r = req.leaf ?? {};
  if (r.ca === false && leaf.basicConstraints?.ca === true) err('profile.leaf_is_ca', 'The signing certificate is a CA certificate');
  if (r.keyUsage?.length) {
    const ku: KeyUsage | undefined = leaf.keyUsage;
    const missing = r.keyUsage.filter((bit) => !ku || !ku[bit]);
    if (missing.length > 0) {
      err('profile.key_usage', ku ? `The signing certificate's key usage does not assert ${missing.join(', ')}`
        : `The signing certificate has no key usage extension; required: ${r.keyUsage.join(', ')}`);
    }
  }
  if (r.extendedKeyUsage?.length) {
    const missing = r.extendedKeyUsage.filter((oid) => !leaf.extendedKeyUsage.includes(oid));
    if (missing.length > 0) err('profile.extended_key_usage', `The signing certificate lacks extended key usage ${missing.join(', ')}`);
  }
  // Compared exactly: a case-insensitive comparison is not the same thing on every platform.
  if (r.sameCountryAsAnchor && (leaf.subjectCountry === undefined || anchor.subjectCountry === undefined || leaf.subjectCountry !== anchor.subjectCountry)) {
    err('profile.country', `The signing certificate's country (${leaf.subjectCountry ?? 'none'}) is not the trust anchor's (${anchor.subjectCountry ?? 'none'})`);
  }
  if (r.maxValidityDays !== undefined && leaf.notAfter.getTime() - leaf.notBefore.getTime() > r.maxValidityDays * DAY_MS) {
    err('profile.validity', `The signing certificate is valid for more than ${r.maxValidityDays} days`);
  }
  if (r.crlDistributionPoint && !leaf.crlDistributionPoints.some((u) => HTTP_URL.test(u))) {
    err('profile.crl_distribution_point', 'The signing certificate names no http(s) CRL distribution point');
  }
  if (req.maxIntermediates !== undefined && path.length - 1 > req.maxIntermediates) {
    err('profile.path_length', `The chain has ${path.length - 1} CA certificates between the signing certificate and the trust anchor; at most ${req.maxIntermediates} are allowed`);
  }
  return issues;
}
