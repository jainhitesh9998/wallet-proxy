/**
 * Local RFC 5280-style path validation for device-side trust decisions. Mirrors the server's
 * semantics: chains may include or omit the anchor, a pinned end-entity certificate is accepted directly,
 * profile checks per trust domain (and a trust mechanism's requirements on top), the {@code docTypes} anchor
 * constraint, and — when CRLs are supplied —
 * revocation of every certificate below the anchor.
 *
 * What it does not implement it refuses rather than ignores: a certificate with name constraints or policy
 * constraints (critical or not), or with a critical extension it does not know, fails validation. A trust anchor
 * is a certificate an operator listed, so its own limits hold too: it issues only as a CA, within its path length.
 */
import { OID, parseCertificate, type Certificate } from './certificate.js';
import { verifyX509Signature } from './signature.js';
import { anchorCrlUrls, checkRevocation, type RevocationOptions } from './revocation.js';
import { requirementIssues, type CertificateRequirements } from './requirements.js';
import { base64Encode, bytesEqual } from '../util/bytes.js';
import { rsaKeyProblem } from '../crypto/rsa.js';
import type { CertificateRevocation, CertificateSummary, PathValidationResult, ValidationIssue } from '../types.js';

export interface LocalAnchor {
  certificate: Certificate;
  domain: string;
  id?: string;
  frameworkId?: string;
  entityId?: string;
  status?: string;
  constraints?: Record<string, unknown>;
  /** where the anchor was published (matched by DCQL trusted_authorities of type etsi_tl / openid_federation) */
  provenance?: { sourceId?: string; sourceUri?: string };
}

export interface ValidateOptions {
  time?: Date;
  /** trust domain; selects the certificate profile unless {@link profileDomain} does */
  domain?: string;
  /**
   * The trust domain whose built-in certificate profile applies (default: {@link domain}). The evaluator passes the
   * question's own domain, so that the built-in profile follows the question when a trust mechanism counts the anchors
   * of another domain instead.
   */
  profileDomain?: string;
  /** A trust mechanism's requirements on the chain, checked on top of the built-in profile (x509/requirements.ts). */
  requirements?: CertificateRequirements;
  expectedDnsName?: string;
  docType?: string;
  /** check revocation against these CRLs (a directly pinned certificate is not checked: it is an anchor) */
  revocation?: RevocationOptions;
}

const KNOWN_CRITICAL = new Set<string>([OID.basicConstraints, OID.keyUsage, OID.extKeyUsage, OID.subjectAltName, OID.certificatePolicies, OID.issuerAltName]);
/** Constraints on the certificates below a CA that this validator does not evaluate: their presence fails the path. */
const UNSUPPORTED_CONSTRAINTS: Record<string, string> = { [OID.nameConstraints]: 'name constraints', [OID.policyConstraints]: 'policy constraints' };
/** An empty Name: SEQUENCE of nothing. */
const emptyName = (raw: Uint8Array) => raw.length === 2;

export function summarize(c: Certificate): CertificateSummary {
  return {
    subject: c.subject, issuer: c.issuer, serialNumber: c.serialNumber,
    notBefore: c.notBefore.toISOString(), notAfter: c.notAfter.toISOString(), sha256: c.sha256,
    subjectKeyIdentifier: c.subjectKeyIdentifier, authorityKeyIdentifier: c.authorityKeyIdentifier,
    dnsNames: c.dnsNames, ca: c.basicConstraints?.ca ?? false, certificate: base64Encode(c.der),
  };
}

export function isSignedBy(cert: Certificate, issuer: Certificate): boolean {
  return verifyX509Signature(cert, issuer.publicKey);
}

function issuedBy(cert: Certificate, issuer: Certificate): boolean {
  return bytesEqual(cert.issuerRaw, issuer.subjectRaw) || cert.issuer === issuer.subject;
}

/** The doctype ISO/IEC 18013-5 defines, and whose signer certificates its Annex B profiles. */
const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';

function profileName(domain?: string): string {
  switch (domain) {
    case 'mdoc-iaca': return 'iso18013-5-document-signer';
    case 'credential-issuer': return 'credential-issuer';
    case 'verifier-access': return 'verifier-access';
    default: return 'none';
  }
}

function profileIssues(domain: string | undefined, path: Certificate[], anchor: Certificate, opts: ValidateOptions): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const leaf = path[0]!;
  const err = (code: string, message: string) => issues.push({ code, message, severity: 'ERROR' });
  if (domain === 'mdoc-iaca') {
    // ISO 18013-5 Annex B profiles the signer of an mDL (its EKU, its country); other doctypes, an EUDI PID as mdoc
    // say, are issued under other certificate profiles. Applied to an mDL, and when the doctype is not known.
    const mdl = opts.docType === undefined || opts.docType === null || opts.docType === MDL_DOCTYPE;
    if (leaf.basicConstraints?.ca) err('mdoc.ds.is_ca', 'Document Signer certificate must not be a CA');
    if (mdl && !leaf.extendedKeyUsage.includes(OID.mdlDocumentSigner)) err('mdoc.ds.eku', `Document Signer certificate lacks extended key usage ${OID.mdlDocumentSigner}`);
    if (leaf.keyUsage && !leaf.keyUsage.digitalSignature) err('mdoc.ds.key_usage', 'Document Signer key usage must include digitalSignature');
    const c1 = leaf.subjectCountry;
    const c2 = anchor.subjectCountry;
    if (mdl && c1 && c2 && c1.toUpperCase() !== c2.toUpperCase()) err('mdoc.ds.country', `Document Signer country ${c1} differs from IACA country ${c2}`);
  } else if (domain === 'credential-issuer') {
    if (leaf.keyUsage && !leaf.keyUsage.digitalSignature) err('issuer.key_usage', 'Signing certificate key usage must include digitalSignature');
  } else if (domain === 'verifier-access') {
    if (leaf.basicConstraints?.ca && path.length > 1) err('verifier.leaf_is_ca', 'Request signing certificate must not be a CA');
    if (opts.expectedDnsName !== undefined && opts.expectedDnsName !== null && !leaf.dnsNames.some((d) => d.toLowerCase() === opts.expectedDnsName!.toLowerCase())) {
      err('verifier.san_dns', `Leaf certificate has no SAN dNSName matching ${opts.expectedDnsName}`);
    }
  }
  return issues;
}

export function validateCertificateChain(chainIn: (Certificate | Uint8Array | string)[], anchors: LocalAnchor[],
                                         opts: ValidateOptions = {}): PathValidationResult & { anchorRef?: LocalAnchor } {
  const time = opts.time ?? new Date();
  const profile = profileName(opts.profileDomain ?? opts.domain);
  const base = { profile, validationTime: time.toISOString() };
  const chain = chainIn.map((c) => (typeof c === 'string' || c instanceof Uint8Array ? parseCertificate(c) : c));
  if (chain.length === 0) {
    return { ...base, valid: false, anchorFound: false, path: [], issues: [{ code: 'x509.empty_chain', message: 'No certificates supplied', severity: 'ERROR' }] };
  }
  const byHash = new Map(anchors.map((a) => [a.certificate.sha256, a]));
  const path = [...chain];
  let included: LocalAnchor | undefined;
  while (path.length > 1 && byHash.has(path[path.length - 1]!.sha256)) included = byHash.get(path.pop()!.sha256);
  const summaries = path.map(summarize);

  const pinned = byHash.get(path[0]!.sha256);
  if (pinned && path.length === 1) {
    return finish([{ code: 'x509.pinned', message: 'Certificate is directly pinned as a trust anchor', severity: 'INFO' }], pinned, path, opts, time, base, false);
  }
  const top = path[path.length - 1]!;
  const candidates = [...(included ? [included] : []), ...anchors.filter((a) => a !== included && issuedBy(top, a.certificate) && isSignedBy(top, a.certificate))];
  if (candidates.length === 0) {
    return { ...base, valid: false, anchorFound: false, path: summaries,
      issues: [{ code: 'x509.no_anchor', message: `No trust anchor found for issuer ${top.issuer}`, severity: 'ERROR' }] };
  }
  let last: { issues: ValidationIssue[]; anchor: LocalAnchor } | undefined;
  for (const anchor of candidates) {
    const issues = checkPath(path, anchor, time);
    if (!issues.some((i) => i.severity === 'ERROR')) return finish(issues, anchor, path, opts, time, base, true);
    last = { issues, anchor };
  }
  return { ...base, valid: false, anchorFound: true, anchor: anchorSummary(last!.anchor), anchorRef: last!.anchor, path: summaries, issues: last!.issues };
}

/** Issuer and subject are the same name (RFC 5280 section 6.1): such a certificate does not count against a path length. */
function selfIssued(c: Certificate): boolean {
  return bytesEqual(c.issuerRaw, c.subjectRaw) || c.issuer === c.subject;
}

/** Non-self-issued intermediate certificates between the leaf and position {@code j} (the leaf itself never counts). */
function intermediatesBelow(path: Certificate[], j: number): number {
  let n = 0;
  for (let k = 1; k < j; k++) if (!selfIssued(path[k]!)) n++;
  return n;
}

/**
 * What a certificate says about itself that makes it unusable in a path, whoever issued it: critical extensions and
 * constraints this validator cannot honour, contradictory CA fields, names RFC 5280 does not allow, a weak key.
 */
function certificateIssues(c: Certificate, label: string, issues: ValidationIssue[]): void {
  const err = (code: string, message: string) => issues.push({ code, message, severity: 'ERROR' });
  for (const oid of c.extensions) {
    const constraint = UNSUPPORTED_CONSTRAINTS[oid];
    if (constraint) {
      err('x509.path.unsupported_constraints', `${label} carries ${constraint} (${oid}), which this validator does not evaluate: the chain is refused rather than the constraint ignored`);
    } else if (c.criticalExtensions.includes(oid) && !KNOWN_CRITICAL.has(oid)) {
      err('x509.path.unrecognized_crit_ext', `${label} has unsupported critical extension ${oid}`);
    }
  }
  const ca = c.basicConstraints?.ca === true;
  if (c.keyUsage?.keyCertSign && !ca) err('x509.path.inconsistent_ca', `${label} asserts keyCertSign without being a CA`);
  if (c.basicConstraints?.pathLen !== undefined && (!ca || (c.keyUsage && !c.keyUsage.keyCertSign))) {
    err('x509.path.inconsistent_ca', `${label} has a path length constraint without being a CA that signs certificates`);
  }
  if (emptyName(c.issuerRaw)) err('x509.path.invalid_name', `${label} has an empty issuer name`);
  if (emptyName(c.subjectRaw)) {
    if (ca) err('x509.path.invalid_name', `${label} is a CA with an empty subject name`);
    else if (!c.criticalExtensions.includes(OID.subjectAltName)) err('x509.path.invalid_name', `${label} has an empty subject and no critical subjectAltName`);
  }
  const weak = c.publicKey?.kty === 'RSA' ? rsaKeyProblem(c.publicKey) : null;
  if (weak) err('x509.path.algorithm_constrained', `${label} has an unacceptable RSA key: ${weak}`);
}

function checkPath(path: Certificate[], anchor: LocalAnchor, time: Date): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (code: string, message: string) => issues.push({ code, message, severity: 'ERROR' });
  const a = anchor.certificate;
  if (anchor.status && anchor.status !== 'ACTIVE') err('x509.anchor_status', `Trust anchor status is ${anchor.status}`);
  if (time < a.notBefore || time > a.notAfter) err('x509.anchor_expired', `Trust anchor certificate is not valid at ${time.toISOString()}`);
  // RFC 5280 section 6.1.1 takes a trust anchor as a name and a key. An anchor here is a certificate an operator
  // listed, so its own limits hold (as on the server): only a CA certificate with keyCertSign issues others, and no
  // deeper than its path length (an ISO 18013-5 IACA has 0).
  if (!a.basicConstraints?.ca || (a.keyUsage && !a.keyUsage.keyCertSign)) {
    err('x509.anchor_not_ca', 'The trust anchor is not a CA certificate allowed to sign certificates');
  } else if (a.basicConstraints.pathLen !== undefined && intermediatesBelow(path, path.length) > a.basicConstraints.pathLen) {
    err('x509.anchor_path_length', "The chain is longer than the trust anchor's path length allows");
  }
  certificateIssues(a, 'Trust anchor', issues);
  for (let j = 0; j < path.length; j++) {
    const c = path[j]!;
    const issuer = j + 1 < path.length ? path[j + 1]! : a;
    if (!issuedBy(c, issuer)) err('x509.path.name_chaining', `Issuer of certificate ${j} does not match subject of its issuer`);
    if (!isSignedBy(c, issuer)) err('x509.path.invalid_signature', `Signature of certificate ${j} does not verify`);
    if (time < c.notBefore) err('x509.path.not_yet_valid', `Certificate ${j} (${c.subject}) is not valid before ${c.notBefore.toISOString()}`);
    else if (time > c.notAfter) err('x509.path.expired', `Certificate ${j} (${c.subject}) is not valid after ${c.notAfter.toISOString()}`);
    certificateIssues(c, `Certificate ${j}`, issues);
    if (j >= 1) {
      if (!c.basicConstraints?.ca) err('x509.path.not_ca_cert', `Intermediate certificate ${j} is not a CA`);
      if (c.keyUsage && !c.keyUsage.keyCertSign) err('x509.path.invalid_key_usage', `Intermediate certificate ${j} cannot sign certificates`);
      const pl = c.basicConstraints?.pathLen;
      if (pl !== undefined && intermediatesBelow(path, j) > pl) err('x509.path.path_too_long', `Path length constraint of certificate ${j} exceeded`);
    }
  }
  return issues;
}

function finish(pathIssues: ValidationIssue[], anchor: LocalAnchor, path: Certificate[], opts: ValidateOptions, time: Date,
                base: { profile: string; validationTime: string }, revocable: boolean): PathValidationResult & { anchorRef?: LocalAnchor } {
  const issues = [...pathIssues];
  issues.push(...profileIssues(opts.profileDomain ?? opts.domain, path, anchor.certificate, opts));
  // A mechanism's requirements come on top of the built-in profile, never in its place (CertificateProfiles.withRequirements).
  if (opts.requirements) issues.push(...requirementIssues(opts.requirements, path, anchor.certificate));
  const docTypes = Array.isArray(anchor.constraints?.docTypes) ? (anchor.constraints!.docTypes as string[]) : [];
  if (docTypes.length > 0 && opts.docType && !docTypes.includes(opts.docType)) {
    issues.push({ code: 'x509.anchor_doctype', message: `Trust anchor is not authorized for doctype ${opts.docType}`, severity: 'ERROR' });
  }
  // As TrustAnchor.isUsableAt in Java: ACTIVE and within the certificate's validity, also for a directly pinned anchor.
  if ((anchor.status && anchor.status !== 'ACTIVE') || time < anchor.certificate.notBefore || time > anchor.certificate.notAfter) {
    if (!issues.some((i) => i.code.startsWith('x509.anchor'))) issues.push({ code: 'x509.anchor_unusable', message: 'Trust anchor is not usable now', severity: 'ERROR' });
  }
  let revocation: CertificateRevocation[] | undefined;
  if (opts.revocation && revocable) {
    const r = checkRevocation(path, anchor.certificate, time, { ...opts.revocation, anchorCrlUrls: anchorCrlUrls(anchor) });
    issues.push(...r.issues);
    revocation = r.statuses;
  }
  return { ...base, valid: !issues.some((i) => i.severity === 'ERROR'), anchorFound: true, anchor: anchorSummary(anchor), anchorRef: anchor,
    path: path.map(summarize), issues, ...(revocation ? { revocation } : {}) };
}

function anchorSummary(a: LocalAnchor): Record<string, unknown> {
  return { id: a.id ?? `${a.domain}:${a.certificate.sha256}`, domain: a.domain, frameworkId: a.frameworkId, entityId: a.entityId,
    status: a.status ?? 'ACTIVE', constraints: a.constraints ?? {}, certificate: summarize(a.certificate) };
}
