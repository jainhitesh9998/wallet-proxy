/**
 * Local RFC 5280-style path validation for device-side trust decisions. Mirrors the server's
 * semantics: chains may include or omit the anchor, a pinned end-entity certificate is accepted directly,
 * profile checks per trust domain, {@code relaxProfile} and {@code docTypes} anchor constraints, and — when CRLs are
 * supplied — revocation of every certificate below the anchor.
 */
import { OID, parseCertificate, subjectCountry, type Certificate } from './certificate.js';
import { verifyX509Signature } from './signature.js';
import { checkRevocation, type RevocationOptions } from './revocation.js';
import { base64Encode, bytesEqual } from '../util/bytes.js';
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
  /** trust domain; selects the certificate profile */
  domain?: string;
  expectedDnsName?: string;
  docType?: string;
  /** check revocation against these CRLs (a directly pinned certificate is not checked: it is an anchor) */
  revocation?: RevocationOptions;
  /** honour an anchor's relaxProfile constraint (default true); a strict client profile turns it off */
  allowRelaxedProfile?: boolean;
}

const KNOWN_CRITICAL = new Set([OID.basicConstraints, OID.keyUsage, OID.extKeyUsage, OID.subjectAltName, '2.5.29.32', OID.issuerAltName]);

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
    if (leaf.basicConstraints?.ca) err('mdoc.ds.is_ca', 'Document Signer certificate must not be a CA');
    if (!leaf.extendedKeyUsage.includes(OID.mdlDocumentSigner)) err('mdoc.ds.eku', `Document Signer certificate lacks extended key usage ${OID.mdlDocumentSigner}`);
    if (leaf.keyUsage && !leaf.keyUsage.digitalSignature) err('mdoc.ds.key_usage', 'Document Signer key usage must include digitalSignature');
    const c1 = subjectCountry(leaf.subject);
    const c2 = subjectCountry(anchor.subject);
    if (c1 && c2 && c1.toUpperCase() !== c2.toUpperCase()) err('mdoc.ds.country', `Document Signer country ${c1} differs from IACA country ${c2}`);
  } else if (domain === 'credential-issuer') {
    if (leaf.keyUsage && !leaf.keyUsage.digitalSignature) err('issuer.key_usage', 'Signing certificate key usage must include digitalSignature');
  } else if (domain === 'verifier-access') {
    if (leaf.basicConstraints?.ca && path.length > 1) err('verifier.leaf_is_ca', 'Request signing certificate must not be a CA');
    if (opts.expectedDnsName && !leaf.dnsNames.some((d) => d.toLowerCase() === opts.expectedDnsName!.toLowerCase())) {
      err('verifier.san_dns', `Leaf certificate has no SAN dNSName matching ${opts.expectedDnsName}`);
    }
  }
  return issues;
}

export function validateCertificateChain(chainIn: (Certificate | Uint8Array | string)[], anchors: LocalAnchor[],
                                         opts: ValidateOptions = {}): PathValidationResult & { anchorRef?: LocalAnchor } {
  const time = opts.time ?? new Date();
  const profile = profileName(opts.domain);
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

function checkPath(path: Certificate[], anchor: LocalAnchor, time: Date): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const err = (code: string, message: string) => issues.push({ code, message, severity: 'ERROR' });
  if (anchor.status && anchor.status !== 'ACTIVE') err('x509.anchor_status', `Trust anchor status is ${anchor.status}`);
  if (time < anchor.certificate.notBefore || time > anchor.certificate.notAfter) err('x509.anchor_expired', `Trust anchor certificate is not valid at ${time.toISOString()}`);
  for (let j = 0; j < path.length; j++) {
    const c = path[j]!;
    const issuer = j + 1 < path.length ? path[j + 1]! : anchor.certificate;
    if (!issuedBy(c, issuer)) err('x509.path.name_chaining', `Issuer of certificate ${j} does not match subject of its issuer`);
    if (!isSignedBy(c, issuer)) err('x509.path.invalid_signature', `Signature of certificate ${j} does not verify`);
    if (time < c.notBefore || time > c.notAfter) err('x509.path.expired', `Certificate ${j} (${c.subject}) is not valid at ${time.toISOString()}`);
    for (const crit of c.criticalExtensions) if (!KNOWN_CRITICAL.has(crit as never)) err('x509.path.unrecognized_critical_extension', `Certificate ${j} has unsupported critical extension ${crit}`);
    if (j >= 1) {
      if (!c.basicConstraints?.ca) err('x509.path.not_ca', `Intermediate certificate ${j} is not a CA`);
      if (c.keyUsage && !c.keyUsage.keyCertSign) err('x509.path.key_usage', `Intermediate certificate ${j} cannot sign certificates`);
      const pl = c.basicConstraints?.pathLen;
      if (pl !== undefined && j - 1 > pl) err('x509.path.path_length', `Path length constraint of certificate ${j} exceeded`);
    }
  }
  const apl = anchor.certificate.basicConstraints?.pathLen;
  if (apl !== undefined && path.length - 1 > apl) err('x509.path.path_length', 'Trust anchor path length constraint exceeded');
  return issues;
}

function finish(pathIssues: ValidationIssue[], anchor: LocalAnchor, path: Certificate[], opts: ValidateOptions, time: Date,
                base: { profile: string; validationTime: string }, revocable: boolean): PathValidationResult & { anchorRef?: LocalAnchor } {
  const issues = [...pathIssues];
  let prof = profileIssues(opts.domain, path, anchor.certificate, opts);
  if (anchor.constraints?.relaxProfile === true && opts.allowRelaxedProfile !== false && prof.length > 0) {
    prof = prof.map((i) => (i.severity === 'ERROR' ? { ...i, severity: 'WARNING' as const, message: `${i.message} (profile relaxed for this anchor)` } : i));
    issues.push({ code: 'x509.profile_relaxed', message: `Certificate profile '${base.profile}' is relaxed for this trust anchor`, severity: 'WARNING' });
  }
  issues.push(...prof);
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
    const r = checkRevocation(path, anchor.certificate, time, opts.revocation);
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
