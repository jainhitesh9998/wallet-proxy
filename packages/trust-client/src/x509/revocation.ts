/**
 * Certificate revocation by CRL, with the service's semantics (RevocationChecker): every certificate of a validated
 * path below the trust anchor is looked up in the CRLs its issuer signed, that are current and cover it. CRLs come
 * from the trust snapshot (the anchors' CRLs, compiled by the service) or are fetched by the caller. OCSP is never
 * used on the device: an OCSP request names the exact certificate being checked.
 *
 * A certificate is good only when a complete, current CRL whose scope this code can evaluate does not list it. When
 * several such CRLs are held, a revocation in any of them stands, and otherwise the most recent one decides; a CRL
 * that cannot be evaluated (delta, indirect, partitioned by reason, unknown critical extension, a scope named in a
 * way that is not compared here) never yields "good".
 */
import { bytesEqual } from '../util/bytes.js';
import type { Certificate } from './certificate.js';
import { CRL_REASONS, normalizeSerial, REASON_CERTIFICATE_HOLD, REASON_REMOVE_FROM_CRL, type Crl, type CrlEntry } from './crl.js';
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
  /**
   * Where the trust anchor's CA publishes its CRL ({@link anchorCrlUrls}): looked at, besides its own distribution
   * points, for the certificate the anchor issued, to report why its status is unknown.
   */
  anchorCrlUrls?: string[];
}

const HTTP_URL = /^https?:\/\//i;

/**
 * The most CRL locations a trust anchor counts with, and the most distribution points of one certificate of a chain
 * that are fetched (the first http(s) ones it names), as on the service (TrustAnchor.MAX_CRL_URLS): a list, an app's
 * pinned anchor or a certificate decides how many there are, and each one is a request the device makes.
 */
export const MAX_CRL_URLS = 8;

/**
 * The http(s) locations where a trust anchor's CA publishes its CRL, as the service finds them (CrlService): what the
 * anchor's record names ({@code constraints.crlUrls}: a list, or one URL); and when it names none, the distribution
 * points of the anchor certificate itself if it is self-issued (a root publishes its own CRL there; an intermediate
 * CA's certificate names where the CA above it publishes, which says nothing about the certificates it issues). At most
 * the first {@link MAX_CRL_URLS} of them.
 */
export function anchorCrlUrls(anchor: { constraints?: Record<string, unknown>; certificate: Certificate } | undefined): string[] {
  if (!anchor) return [];
  const v = anchor.constraints?.crlUrls;
  const named = (Array.isArray(v) ? v : typeof v === 'string' ? [v] : []).filter((u): u is string => typeof u === 'string' && HTTP_URL.test(u));
  if (named.length > 0) return named.slice(0, MAX_CRL_URLS);
  const c = anchor.certificate;
  return bytesEqual(c.issuerRaw, c.subjectRaw) ? fetchablePoints(c) : [];
}

/** The distribution points of a certificate that are fetched: the first {@link MAX_CRL_URLS} http(s) ones it names. */
function fetchablePoints(cert: Certificate): string[] {
  return cert.crlDistributionPoints.filter((u) => HTTP_URL.test(u)).slice(0, MAX_CRL_URLS);
}

/** Accepted clock skew for a CRL's thisUpdate. */
const SKEW_MS = 5 * 60_000;

/**
 * How long a CRL that states no nextUpdate is used after its thisUpdate. RFC 5280 requires nextUpdate; without it
 * nothing says when the CRL was superseded, so it must not stand in for the current one indefinitely.
 */
export const MAX_CRL_AGE_WITHOUT_NEXT_UPDATE_MS = 7 * 24 * 3600_000;

const DELTA = 'delta CRLs are not supported';

/** What one usable CRL says about one certificate. */
interface Statement {
  held: HeldCrl;
  /** the certificate's entry; absent when a complete CRL does not list it */
  entry?: CrlEntry;
}

export function checkRevocation(path: Certificate[], anchor: Certificate, time: Date, opts: RevocationOptions):
    { issues: ValidationIssue[]; statuses: CertificateRevocation[] } {
  const issues: ValidationIssue[] = [];
  const statuses: CertificateRevocation[] = [];
  path.forEach((cert, j) => {
    const issuer = j + 1 < path.length ? path[j + 1]! : anchor;
    const base = { index: j, serialNumber: normalizeSerial(cert.serialNumber), subject: cert.subject };
    const label = `Certificate ${j} (${cert.subject})`;
    let why: string | undefined;
    const statements: Statement[] = [];
    for (const held of opts.crls) {
      if (!bytesEqual(held.crl.issuerRaw, cert.issuerRaw) && held.crl.issuer !== cert.issuer) continue;
      const problem = unusable(held.crl, cert, issuer, time);
      if (problem === 'not-covering') continue;
      if (problem) { why ??= problem; continue; }
      const entry = held.crl.entries.get(base.serialNumber);
      // A delta CRL is not a complete list: it can show that a certificate was revoked, never that it was not.
      if (held.crl.delta && !entry) { why ??= DELTA; continue; }
      // Nor is a list that names a certificate twice a sound one: its entries stand, its silence is not relied on.
      if (held.crl.duplicateSerials && !entry) { why ??= 'the CRL lists a serial number more than once'; continue; }
      statements.push({ held, entry });
    }
    // A revocation (other than a hold, which can be lifted) in any current CRL stands; otherwise the newest decides.
    const decisive = newest(statements.filter((s) => s.entry && s.entry.reason !== REASON_CERTIFICATE_HOLD && s.entry.reason !== REASON_REMOVE_FROM_CRL))
      ?? newest(statements);
    if (decisive) {
      const { held, entry } = decisive;
      const crl = held.crl;
      const ref = { method: 'crl' as const, crlUrl: held.url ?? null, source: held.source,
        thisUpdate: crl.thisUpdate.toISOString(), nextUpdate: crl.nextUpdate?.toISOString() ?? null };
      if (!entry) {
        statuses.push({ ...base, ...ref, status: 'GOOD' });
        issues.push({ code: 'x509.not_revoked', severity: 'INFO', message: `${label} is not revoked (CRL ${held.url ?? 'from the trust list'}, `
          + `next update ${crl.nextUpdate?.toISOString() ?? 'not set'})` });
        return;
      }
      if (entry.reason === REASON_CERTIFICATE_HOLD) {
        statuses.push({ ...base, ...ref, status: 'ON_HOLD', reason: 'certificateHold', revokedAt: entry.revokedAt.toISOString() });
        issues.push({ code: 'x509.on_hold', severity: 'ERROR', message: `${label} is on hold (suspended) since ${entry.revokedAt.toISOString()}` });
        return;
      }
      if (entry.reason !== REASON_REMOVE_FROM_CRL) {
        const reason = CRL_REASONS[entry.reason ?? 0] ?? `reason ${entry.reason}`;
        statuses.push({ ...base, ...ref, status: 'REVOKED', reason, revokedAt: entry.revokedAt.toISOString() });
        issues.push({ code: 'x509.revoked', severity: 'ERROR', message: `${label} was revoked on ${entry.revokedAt.toISOString()} (${reason})` });
        return;
      }
      // removeFromCRL lifts a hold in a delta CRL, read together with its base. Alone it proves nothing: not in a
      // delta (deltas are not combined here), and in a complete CRL it should not appear at all.
      why = crl.delta ? DELTA : 'the CRL lists the certificate with reason removeFromCRL, which only a delta CRL may use';
    }
    // Where its CRL could be had: its own distribution points, and for the certificate the anchor issued, the anchor's.
    const where = j === path.length - 1 ? [...cert.crlDistributionPoints, ...(opts.anchorCrlUrls ?? [])] : cert.crlDistributionPoints;
    const failed = where.map((u) => opts.failures?.[u]).find(Boolean);
    why ??= failed ? `CRL unavailable: ${failed}`
      : where.length > 0 ? 'its CRL has not been obtained'
        : cert.ocspUrls.length > 0 ? 'the issuer publishes only OCSP, which this device does not use (it would reveal the certificate)'
          : 'no CRL is published for it';
    statuses.push({ ...base, status: 'UNKNOWN', reason: why });
    issues.push({ code: 'x509.revocation_unknown', severity: opts.require ? 'ERROR' : 'WARNING',
      message: `Revocation status of ${label.charAt(0).toLowerCase()}${label.slice(1)} is unknown: ${why}` });
  });
  return { issues, statuses };
}

/** The most recently issued of the statements: by thisUpdate, then CRL number; the caller's order breaks a tie. */
function newest(statements: Statement[]): Statement | undefined {
  let best: Statement | undefined;
  for (const s of statements) {
    if (!best) { best = s; continue; }
    const [a, b] = [s.held.crl, best.held.crl];
    const dt = a.thisUpdate.getTime() - b.thisUpdate.getTime();
    if (dt > 0 || (dt === 0 && a.crlNumber !== undefined && b.crlNumber !== undefined && BigInt(a.crlNumber) > BigInt(b.crlNumber))) best = s;
  }
  return best;
}

/** Why {@code crl} cannot decide for {@code cert}: a reason, 'not-covering', or null when usable. */
function unusable(crl: Crl, cert: Certificate, issuer: Certificate, time: Date): string | null {
  if (!verifyX509Signature(crl, issuer.publicKey)) return 'CRL signature does not verify';
  if (issuer.keyUsage && !issuer.keyUsage.cRLSign) return 'the issuer is not allowed to sign CRLs';
  if (crl.thisUpdate.getTime() > time.getTime() + SKEW_MS) return `CRL is not valid before ${crl.thisUpdate.toISOString()}`;
  if (crl.nextUpdate) {
    if (crl.nextUpdate < time) return `CRL expired at ${crl.nextUpdate.toISOString()}`;
  } else if (time.getTime() - crl.thisUpdate.getTime() > MAX_CRL_AGE_WITHOUT_NEXT_UPDATE_MS) {
    return `CRL states no next update and was issued more than ${MAX_CRL_AGE_WITHOUT_NEXT_UPDATE_MS / (24 * 3600_000)} days ago (${crl.thisUpdate.toISOString()})`;
  }
  if (crl.unsupportedCritical.length > 0) return `CRL has unsupported critical extension ${crl.unsupportedCritical[0]}`;
  const idp = crl.issuingDistributionPoint;
  if (idp?.indirectCRL || [...crl.entries.values()].some((e) => e.certificateIssuer)) return 'indirect CRLs are not supported';
  if (idp?.onlySomeReasons) return 'CRLs partitioned by reason are not supported';
  if (idp) {
    const ca = cert.basicConstraints?.ca === true;
    if (idp.onlyContainsAttributeCerts || (idp.onlyContainsUserCerts && ca) || (idp.onlyContainsCACerts && !ca)) return 'not-covering';
    // A CRL for one distribution point covers a certificate only when the certificate names that point (by URI,
    // in a distribution point that is not limited to some reasons or to another CRL issuer). A point named any other
    // way (a directoryName, a name relative to the issuer) is a partition this code cannot match: not covering.
    if ((idp.uris.length > 0 || idp.unsupportedName) && !idp.uris.some((u) => cert.crlFullScopeUris.includes(u))) return 'not-covering';
  }
  return null;
}

/**
 * http(s) CRL locations worth fetching for the certificates whose status is still unknown: each one's own
 * distribution points (at most the first {@link MAX_CRL_URLS} http(s) ones it names: the certificate decides how many
 * there are, and each is a request), and for the certificate the trust anchor issued (the last of the validated path,
 * which {@code statuses} covers one by one), where the anchor's CA publishes ({@code anchorUrls}, see
 * {@link anchorCrlUrls}). As on the service (RevocationChecker).
 */
export function crlUrlsToFetch(path: Certificate[], statuses: CertificateRevocation[] | undefined, anchorUrls: string[] = []): string[] {
  const urls = new Set<string>();
  const issuedByAnchor = (statuses?.length ?? 0) - 1;
  for (const s of statuses ?? []) {
    if (s.status !== 'UNKNOWN') continue;
    const cert = path[s.index];
    const candidates = [...(cert ? fetchablePoints(cert) : []), ...(s.index === issuedByAnchor ? anchorUrls : [])];
    for (const u of candidates) if (HTTP_URL.test(u)) urls.add(u);
  }
  return [...urls];
}
