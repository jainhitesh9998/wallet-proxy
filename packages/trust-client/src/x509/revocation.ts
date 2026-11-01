/**
 * Certificate revocation by CRL, with the service's semantics (RevocationChecker): every certificate of a validated
 * path below the trust anchor is looked up in a CRL its issuer signed, that is current and covers it. CRLs come
 * from the trust snapshot (the anchors' CRLs, compiled by the service) or are fetched by the caller. OCSP is never
 * used on the device: an OCSP request names the exact certificate being checked.
 */
import { bytesEqual } from '../util/bytes.js';
import type { Certificate } from './certificate.js';
import { CRL_REASONS, normalizeSerial, type Crl } from './crl.js';
import { verifyX509Signature } from './signature.js';
import type { CertificateRevocation, ValidationIssue } from '../types.js';

export interface HeldCrl {
  crl: Crl;
  /** where it was published; absent for CRLs pushed into the trust list */
  url?: string;
  /** 'snapshot', 'cache', 'direct', 'trust-service', … */
  source: string;
}

export interface RevocationOptions {
  /** candidate CRLs, in order of preference (snapshot first) */
  crls: HeldCrl[];
  /** CRL downloads that failed, by URL (reported as the reason a status is unknown) */
  failures?: Record<string, string>;
  /** policy: an unknown status is an error rather than a warning */
  require?: boolean;
}

/** Accepted clock skew for a CRL's thisUpdate. */
const SKEW_MS = 5 * 60_000;

export function checkRevocation(path: Certificate[], anchor: Certificate, time: Date, opts: RevocationOptions):
    { issues: ValidationIssue[]; statuses: CertificateRevocation[] } {
  const issues: ValidationIssue[] = [];
  const statuses: CertificateRevocation[] = [];
  path.forEach((cert, j) => {
    const issuer = j + 1 < path.length ? path[j + 1]! : anchor;
    const base = { index: j, serialNumber: normalizeSerial(cert.serialNumber), subject: cert.subject };
    const label = `Certificate ${j} (${cert.subject})`;
    let why: string | undefined;
    for (const held of opts.crls) {
      if (!bytesEqual(held.crl.issuerRaw, cert.issuerRaw) && held.crl.issuer !== cert.issuer) continue;
      const problem = unusable(held.crl, cert, issuer, time);
      if (problem === 'not-covering') continue;
      if (problem) { why ??= problem; continue; }
      const crl = held.crl;
      const ref = { method: 'crl' as const, crlUrl: held.url ?? null, source: held.source,
        thisUpdate: crl.thisUpdate.toISOString(), nextUpdate: crl.nextUpdate?.toISOString() ?? null };
      const entry = crl.entries.get(base.serialNumber);
      if (!entry || entry.reason === 8) {
        statuses.push({ ...base, ...ref, status: 'GOOD' });
        issues.push({ code: 'x509.not_revoked', severity: 'INFO', message: `${label} is not revoked (CRL ${held.url ?? 'from the trust list'}, `
          + `next update ${crl.nextUpdate?.toISOString() ?? 'not set'})` });
      } else if (entry.reason === 6) {
        statuses.push({ ...base, ...ref, status: 'ON_HOLD', reason: 'certificateHold', revokedAt: entry.revokedAt.toISOString() });
        issues.push({ code: 'x509.on_hold', severity: 'ERROR', message: `${label} is on hold (suspended) since ${entry.revokedAt.toISOString()}` });
      } else {
        const reason = CRL_REASONS[entry.reason ?? 0] ?? `reason ${entry.reason}`;
        statuses.push({ ...base, ...ref, status: 'REVOKED', reason, revokedAt: entry.revokedAt.toISOString() });
        issues.push({ code: 'x509.revoked', severity: 'ERROR', message: `${label} was revoked on ${entry.revokedAt.toISOString()} (${reason})` });
      }
      return;
    }
    const failed = cert.crlDistributionPoints.map((u) => opts.failures?.[u]).find(Boolean);
    why ??= failed ? `CRL unavailable: ${failed}`
      : cert.crlDistributionPoints.length > 0 ? 'its CRL has not been obtained'
        : cert.ocspUrls.length > 0 ? 'the issuer publishes only OCSP, which this device does not use (it would reveal the certificate)'
          : 'no CRL is published for it';
    statuses.push({ ...base, status: 'UNKNOWN', reason: why });
    issues.push({ code: 'x509.revocation_unknown', severity: opts.require ? 'ERROR' : 'WARNING',
      message: `Revocation status of ${label.charAt(0).toLowerCase()}${label.slice(1)} is unknown: ${why}` });
  });
  return { issues, statuses };
}

/** Why {@code crl} cannot decide for {@code cert}: a reason, 'not-covering', or null when usable. */
function unusable(crl: Crl, cert: Certificate, issuer: Certificate, time: Date): string | null {
  if (!verifyX509Signature(crl, issuer.publicKey)) return 'CRL signature does not verify';
  if (issuer.keyUsage && !issuer.keyUsage.cRLSign) return 'the issuer is not allowed to sign CRLs';
  if (crl.thisUpdate.getTime() > time.getTime() + SKEW_MS) return `CRL is not valid before ${crl.thisUpdate.toISOString()}`;
  if (crl.nextUpdate && crl.nextUpdate < time) return `CRL expired at ${crl.nextUpdate.toISOString()}`;
  if (crl.delta) return 'delta CRLs are not supported';
  if (crl.unsupportedCritical.length > 0) return `CRL has unsupported critical extension ${crl.unsupportedCritical[0]}`;
  const idp = crl.issuingDistributionPoint;
  if (idp?.indirectCRL || [...crl.entries.values()].some((e) => e.certificateIssuer)) return 'indirect CRLs are not supported';
  if (idp?.onlySomeReasons) return 'CRLs partitioned by reason are not supported';
  if (idp) {
    const ca = cert.basicConstraints?.ca === true;
    if (idp.onlyContainsAttributeCerts || (idp.onlyContainsUserCerts && ca) || (idp.onlyContainsCACerts && !ca)) return 'not-covering';
    if (idp.uris.length > 0 && !idp.uris.some((u) => cert.crlDistributionPoints.includes(u))) return 'not-covering';
  }
  return null;
}

/** http(s) CRL distribution points worth fetching for the certificates whose status is still unknown. */
export function crlUrlsToFetch(path: Certificate[], statuses: CertificateRevocation[] | undefined): string[] {
  const urls = new Set<string>();
  for (const s of statuses ?? []) {
    if (s.status !== 'UNKNOWN') continue;
    for (const u of path[s.index]?.crlDistributionPoints ?? []) if (/^https?:\/\//i.test(u)) urls.add(u);
  }
  return [...urls];
}
