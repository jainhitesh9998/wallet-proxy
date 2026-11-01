/**
 * Device-side trust evaluation with the service's semantics (TrustEvaluator), over the verified trust snapshot plus
 * app-provided anchors and entities. Used for every decision in 'local' mode, and when the service is unreachable
 * in 'service' mode. A decision can only be TRUSTED when backed by a verified snapshot or a pinned anchor;
 * otherwise it is UNKNOWN — missing data never upgrades an unknown party.
 */
import { parseCertificate, type Certificate } from '../x509/certificate.js';
import { validateCertificateChain, type LocalAnchor, type ValidateOptions } from '../x509/validate.js';
import { crlUrlsToFetch, type HeldCrl } from '../x509/revocation.js';
import type { Crl } from '../x509/crl.js';
import { verifyX509Signature } from '../x509/signature.js';
import { findVerificationMethod, hasRelationship, didError, parseDid } from '../did/did.js';
import { jwkThumbprint } from '../crypto/keys.js';
import type { DidEvidence, DidResolutionResult, EntityView, PathValidationResult, Reason, SnapshotRef, TrustDecision, TrustFramework,
  TrustQuery, TrustedAuthorityMatch } from '../types.js';

export interface LocalTrustData {
  entities: EntityView[];
  anchors: LocalAnchor[];
  /** CRLs held for revocation checks (the snapshot's anchor CRLs) */
  crls?: HeldCrl[];
  frameworks: TrustFramework[];
  /** 'snapshot' when a verified snapshot backs the data; 'fallback' when only app-bundled anchors/entities exist */
  source: 'snapshot' | 'fallback';
  /** 'local': device-side decisions are the normal path; 'outage': the service (normally deciding) is unreachable */
  mode: 'local' | 'outage';
  policy?: { strictAuthorization?: boolean; requireRevocationStatus?: boolean; allowRelaxedProfiles?: boolean };
  snapshot?: SnapshotRef | null;
  stale?: boolean;
}

export function normalizeIdentifier(type: string, value: string): string {
  if (type === 'URL' || type === 'FEDERATION_ENTITY') {
    try {
      const u = new URL(value);
      return `${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/$/, '')}${u.search}`;
    } catch {
      return value;
    }
  }
  if (type === 'DID') return value.split('#')[0]!;
  if (type === 'DNS') return value.toLowerCase();
  return value;
}

export function domainFor(role: TrustQuery['role'], format?: string): string {
  if (role === 'verifier') return 'verifier-access';
  if (role === 'wallet_provider') return 'wallet-provider';
  if (role === 'status_list_provider') return 'status-list';
  return format === 'mso_mdoc' ? 'mdoc-iaca' : 'credential-issuer';
}

function roleName(role: TrustQuery['role']): string | undefined {
  switch (role) {
    case 'issuer': return 'CREDENTIAL_ISSUER';
    case 'verifier': return 'VERIFIER';
    case 'wallet_provider': return 'WALLET_PROVIDER';
    case 'authorization_server': return 'AUTHORIZATION_SERVER';
    case 'status_list_provider': return 'STATUS_LIST_PROVIDER';
    default: return undefined;
  }
}

const canonicalFormat = (f?: string | null) => (f === 'vc+sd-jwt' ? 'dc+sd-jwt' : f);
/** OpenID4VP 1.0 §5.9.3 client identifier prefixes; anything else is a pre-registered client_id. */
const CLIENT_ID_PREFIXES = new Set(['redirect_uri', 'x509_san_dns', 'x509_hash', 'decentralized_identifier', 'verifier_attestation', 'openid_federation', 'origin']);
const pickName = (e: EntityView) => (e.display.find((d) => d.locale?.startsWith('en')) ?? e.display[0])?.name ?? e.id;

export interface CrlFetchResult {
  crls: HeldCrl[];
  /** error per CRL URL that could not be obtained */
  failures: Record<string, string>;
}
/** Fetches CRLs; {@code accept} tells whether a CRL is signed by the CA it is for, so only such CRLs are cached. */
export type CrlFetcher = (urls: string[], accept?: (url: string, crl: Crl) => boolean) => Promise<CrlFetchResult>;

/**
 * Path validation with revocation: first against the CRLs already held (the snapshot's), then — only for
 * certificates whose status is still unknown and that name a CRL distribution point — against CRLs fetched by
 * {@code fetchCrls}. Certificates under unknown anchors never trigger a download.
 */
export async function validateChainOnDevice(chain: Certificate[], anchors: LocalAnchor[], opts: ValidateOptions,
                                            data: Pick<LocalTrustData, 'crls' | 'policy'>, fetchCrls?: CrlFetcher) {
  const revocation = { crls: data.crls ?? [], require: data.policy?.requireRevocationStatus === true };
  opts = { ...opts, allowRelaxedProfile: data.policy?.allowRelaxedProfiles !== false };
  const r = validateCertificateChain(chain, anchors, { ...opts, revocation });
  const urls = fetchCrls && r.anchorFound ? crlUrlsToFetch(chain, r.revocation) : [];
  if (urls.length === 0) return r;
  // A CRL counts (and is cached) only when the issuer of a certificate naming its URL signed it.
  const issuerOf = (j: number) => chain[j + 1] ?? r.anchorRef?.certificate;
  const accept = (url: string, crl: Crl) => chain.some((c, j) => c.crlDistributionPoints.includes(url) && !!issuerOf(j)
    && verifyX509Signature(crl, issuerOf(j)!.publicKey));
  const got = await fetchCrls!(urls, accept);
  return validateCertificateChain(chain, anchors, { ...opts, revocation: { ...revocation, crls: [...revocation.crls, ...got.crls], failures: got.failures } });
}

export class LocalEvaluator {
  constructor(private readonly resolveDid: (did: string) => Promise<DidResolutionResult>, private readonly now: () => Date = () => new Date(),
              private readonly fetchCrls?: CrlFetcher) {}

  async evaluate(q: TrustQuery, data: LocalTrustData): Promise<TrustDecision> {
    const time = q.context?.time ? new Date(q.context.time) : this.now();
    const reasons: Reason[] = [];
    // ids: proven by the presented key material; identIds: only claimed by the identifier (see the matching rules below)
    const ids: Array<{ type: string; value: string }> = [];
    const identIds: Array<{ type: string; value: string }> = [];
    const role = q.role;
    const format = canonicalFormat(q.context?.credentialFormat) ?? undefined;
    const type = q.context?.credentialType;
    let expectedDns: string | undefined;
    let expectedHash: string | undefined;
    const ident = q.subject.identifier;
    if (ident) {
      if (role === 'verifier') {
        const i = ident.indexOf(':');
        const known = i > 0 && CLIENT_ID_PREFIXES.has(ident.slice(0, i));
        const prefix = known ? ident.slice(0, i) : 'pre-registered';
        const val = known ? ident.slice(i + 1) : ident;
        identIds.push({ type: 'CLIENT_ID', value: ident });
        if (prefix === 'x509_san_dns') { expectedDns = val; identIds.push({ type: 'DNS', value: val }); }
        else if (prefix === 'x509_hash') { expectedHash = val; identIds.push({ type: 'X509_SHA256', value: val }); }
        else if (prefix === 'decentralized_identifier') identIds.push({ type: 'DID', value: val });
        else if (prefix === 'redirect_uri' || prefix === 'origin') identIds.push({ type: 'URL', value: val });
        else if (prefix === 'openid_federation') identIds.push({ type: 'FEDERATION_ENTITY', value: val }, { type: 'URL', value: val });
        else if (prefix === 'verifier_attestation') reasons.push({ code: 'client_id.verifier_attestation',
          message: 'Verifier attestation JWT must be validated by the wallet; matching registry by client_id only', severity: 'INFO' });
        if ((prefix === 'x509_san_dns' || prefix === 'x509_hash') && !q.subject.x5c?.length) {
          reasons.push({ code: 'client_id.x5c_required', message: `Client identifier prefix ${prefix} requires the request object's x5c chain`, severity: 'ERROR' });
        }
      } else if (ident.startsWith('did:')) identIds.push({ type: 'DID', value: ident });
      else if (/^https?:\/\//.test(ident)) identIds.push({ type: 'URL', value: ident }, { type: 'FEDERATION_ENTITY', value: ident });
      else identIds.push({ type: 'CLIENT_ID', value: ident }, { type: 'OTHER', value: ident });
    }
    // A query names one key: the certificate's or the DID's. With both, the evaluator cannot tell which one the caller
    // verified the signature with, and the other may be copied from anyone (callers pass only the key they checked).
    if ((q.subject.x5c?.length ?? 0) > 0 && q.subject.kid?.startsWith('did:')) {
      reasons.push({ code: 'key.ambiguous', message: 'The query presents both an x5c chain and a DID key; pass only the key the signature was verified with', severity: 'ERROR' });
    }
    let did: string | undefined;
    if (q.subject.kid?.startsWith('did:')) {
      try { did = parseDid(q.subject.kid).did; ids.push({ type: 'DID', value: did }); } catch { reasons.push({ code: 'did.invalid', message: 'kid is not a valid DID URL', severity: 'ERROR' }); }
    } else if (ident?.startsWith('did:')) did = ident.split('#')[0];
    if (Object.keys(q.subject.jwk ?? {}).length > 0) {
      try { ids.push({ type: 'JWK_THUMBPRINT', value: jwkThumbprint(q.subject.jwk!) }); } catch (e) {
        reasons.push({ code: 'jwk.invalid', message: `Unparseable JWK: ${(e as Error).message}`, severity: 'WARNING' });
      }
    }

    let chain: Certificate[] = [];
    try {
      chain = (q.subject.x5c ?? []).map((c) => parseCertificate(c));
    } catch (e) {
      reasons.push({ code: 'x509.parse', message: (e as Error).message, severity: 'ERROR' });
    }
    let x509: PathValidationResult | null = null;
    let anchor: LocalAnchor | undefined;
    if (chain.length > 0) {
      const leaf = chain[0]!;
      // The leaf's hash is a pin (the caller verifies with the leaf's key); its other names count only once the chain validates.
      ids.push({ type: 'X509_SHA256', value: leaf.sha256 });
      if (expectedHash && expectedHash !== leaf.sha256) {
        reasons.push({ code: 'client_id.x509_hash_mismatch', message: 'x509_hash client_id does not match the SHA-256 hash of the leaf certificate', severity: 'ERROR' });
      }
      const domain = domainFor(role, format);
      const anchors = data.anchors.filter((a) => a.domain === domain);
      const r = await validateChainOnDevice(chain, anchors, { time, domain, expectedDnsName: expectedDns, docType: format === 'mso_mdoc' ? type : undefined },
        data, this.fetchCrls);
      const { anchorRef, ...result } = r;
      x509 = result;
      if (r.valid) {
        anchor = anchorRef;
        ids.push({ type: 'X509_SUBJECT', value: leaf.subject });
        if (leaf.subjectKeyIdentifier) ids.push({ type: 'X509_SKI', value: leaf.subjectKeyIdentifier });
        leaf.dnsNames.forEach((n) => ids.push({ type: 'DNS', value: n }));
        leaf.uriNames.forEach((u) => ids.push({ type: 'URL', value: u }));
        reasons.push({ code: 'x509.valid', message: `Certificate chain validates to trust anchor ${anchorRef?.certificate.subject ?? ''} in domain ${domain}`, severity: 'INFO' });
        reasons.push(...r.issues.filter((i) => i.code.startsWith('x509.revocation') && i.severity === 'WARNING'));
      } else if (!r.anchorFound) {
        reasons.push({ code: 'x509.no_anchor', message: anchors.length === 0 ? `No trust anchors configured for domain '${domain}' in accepted frameworks`
          : `Certificate chain does not lead to any trust anchor in domain '${domain}'`, severity: 'WARNING' });
        if (expectedDns && !leaf.dnsNames.some((d) => d.toLowerCase() === expectedDns!.toLowerCase())) {
          reasons.push({ code: 'client_id.san_dns_mismatch', message: 'Leaf certificate has no SAN dNSName equal to the x509_san_dns client_id', severity: 'ERROR' });
        }
      } else {
        reasons.push(...r.issues.filter((i) => i.severity === 'ERROR'));
      }
    }

    // Matching. With key material (x5c, DID kid, JWK) the entity must be bound to that key: by the key's own identifiers,
    // a pinned leaf certificate or the anchor's entity. The identifier alone is only a claim then; it counts when the
    // validated anchor is not tied to one entity and belongs to the identified entity's framework. Without key material
    // the identifier is a registry lookup (issuer metadata, or a key the caller fetched from that identifier).
    const matched: string[] = [];
    const lookup = (list: Array<{ type: string; value: string }>) => {
      const keys = new Set(list.map((i) => `${i.type}|${normalizeIdentifier(i.type, i.value)}`));
      const hits: Array<{ e: EntityView; how: string }> = [];
      for (const e of data.entities) {
        const i = e.identifiers.find((x) => keys.has(`${x.type}|${normalizeIdentifier(x.type, x.value)}`));
        if (i) hits.push({ e, how: `${i.type}:${i.value}` });
      }
      return hits;
    };
    const take = (e: EntityView, how: string, into: EntityView[]) => { if (!into.includes(e)) { into.push(e); matched.push(how); } };
    const keyMaterial = chain.length > 0 || !!q.subject.kid?.startsWith('did:') || Object.keys(q.subject.jwk ?? {}).length > 0;
    const wantRole = roleName(role);
    const hasRole = (e: EntityView) => !wantRole || e.roles.includes(wantRole);
    const byIdentifier = lookup(identIds);
    let candidates: EntityView[] = [];
    if (!keyMaterial) byIdentifier.forEach((h) => take(h.e, h.how, candidates));
    else {
      lookup(ids).forEach((h) => take(h.e, h.how, candidates));
      const leaf = chain[0];
      if (leaf) data.entities.filter((e) => e.certificates?.some((c) => c.sha256 === leaf.sha256)).forEach((e) => take(e, `X509_CERT:${leaf.sha256}`, candidates));
      if (anchor?.entityId) {
        const e = data.entities.find((x) => x.id === anchor!.entityId);
        if (e) take(e, `ANCHOR:${e.id}`, candidates);
      } else if (anchor?.frameworkId && !candidates.some(hasRole)) {
        // Only when the key's own names bind no entity in this role: a key bound to one entity is never another's.
        byIdentifier.filter((h) => h.e.frameworkId === anchor!.frameworkId).forEach((h) => take(h.e, `${h.how} (anchor framework)`, candidates));
      }
    }
    if (keyMaterial) {
      // Refused when the identifier names entities in this role and the key is bound to none of them.
      const named = byIdentifier.filter((h) => hasRole(h.e));
      if (named.length && !named.some((h) => candidates.includes(h.e))) {
        reasons.push({ code: 'identifier.unbound', message: `The identifier names '${pickName(named[0]!.e)}', but the presented `
          + `${chain.length ? 'certificate' : 'key'} is not bound to it`, severity: 'ERROR' });
      }
    }
    if (wantRole) {
      const withRole = candidates.filter((e) => e.roles.includes(wantRole));
      if (candidates.length > 0 && withRole.length === 0) reasons.push({ code: 'entity.role_mismatch', message: `Matching entity is registered, but not as ${wantRole}`, severity: 'WARNING' });
      candidates = withRole;
    }
    const entity = (anchor?.entityId ? candidates.find((e) => e.id === anchor!.entityId) : undefined)
      ?? candidates.find((e) => e.status === 'ACTIVE') ?? candidates[0];

    let didEv: DidEvidence | null = null;
    if (did && q.subject.kid) {
      // The DID URL lets the resolver skip a snapshot document that lacks this (e.g. rotated) key.
      const res = await this.resolveDid(q.subject.kid.includes('#') ? q.subject.kid : did);
      const err = didError(res);
      if (err || !res.didDocument) {
        reasons.push({ code: 'did.unresolved', message: `DID ${did} could not be resolved: ${err ?? 'no document'}`, severity: 'WARNING' });
        didEv = { did, resolved: false, error: err };
      } else if (q.subject.kid.includes('#')) {
        const vm = findVerificationMethod(res.didDocument, q.subject.kid);
        if (!vm) {
          reasons.push({ code: 'did.vm_not_found', message: `Verification method ${q.subject.kid} is not in the DID document`, severity: 'ERROR' });
          didEv = { did, resolved: true, verificationMethod: q.subject.kid, verificationMethodFound: false };
        } else {
          const relationship = role === 'verifier' || role === 'wallet_provider' ? 'authentication' : 'assertionMethod';
          const rel = hasRelationship(res.didDocument, relationship, q.subject.kid, true);
          if (rel === 'lenient') reasons.push({ code: 'did.relationship_lenient', message: `${relationship} lists the DID itself rather than the verification method; accepted leniently`, severity: 'WARNING' });
          if (rel === 'no') reasons.push({ code: 'did.relationship', message: `Verification method is not authorized for ${relationship}`, severity: 'ERROR' });
          didEv = { did, resolved: true, verificationMethod: q.subject.kid, verificationMethodFound: true, relationship, relationshipValid: rel !== 'no' };
        }
      } else {
        didEv = { did, resolved: true };
      }
    }

    let authorization: { format?: string | null; type?: string | null; authorized: boolean; rule?: string } | null = null;
    const strict = data.policy?.strictAuthorization === true;
    if (entity) {
      const from = entity.validFrom ? new Date(entity.validFrom) : undefined;
      const until = entity.validUntil ? new Date(entity.validUntil) : undefined;
      if (entity.status !== 'ACTIVE' || (until && time > until) || (from && time < from)) {
        reasons.push({ code: 'entity.status', message: `Entity '${entity.id}' is ${entity.status}${until && time > until ? ' (expired)' : ''}`, severity: 'ERROR' });
      }
      if (format || type) {
        // Every type the credential asserts must be authorized (a W3C VC may carry several).
        const types = [...new Set([type, ...(q.context?.credentialTypes ?? [])].filter((t): t is string => !!t))];
        const allowed = (t?: string) => entity.authorizations.some((a) =>
          (!a.format || !format || canonicalFormat(a.format) === format) && (!a.type || !t || a.type === t));
        const denied = entity.authorizations.length === 0 ? undefined : (types.length ? types.find((t) => !allowed(t)) : (allowed() ? undefined : ''));
        const ok = entity.authorizations.length === 0 ? !strict : denied === undefined;
        authorization = { format, type, authorized: ok, rule: entity.authorizations.length === 0
          ? (strict ? 'strict: no authorizations registered' : 'unconstrained') : 'registered authorizations' };
        if (!ok) reasons.push({ code: 'entity.not_authorized', message: `Entity '${entity.id}' is not authorized for ${format ?? ''} ${denied || type || ''}`.trim(), severity: 'ERROR' });
      }
    }
    if (anchor?.frameworkId && entity && anchor.frameworkId !== entity.frameworkId) {
      reasons.push({ code: 'framework.mixed', message: `Chain anchor framework '${anchor.frameworkId}' differs from entity framework '${entity.frameworkId}'`, severity: 'INFO' });
    }
    if (expectedDns && q.context?.responseUri) {
      try {
        const host = new URL(q.context.responseUri).host.split(':')[0]!;
        if (host.toLowerCase() !== expectedDns.toLowerCase()) {
          reasons.push({ code: 'client_id.response_uri_host', message: `response_uri host '${host}' does not match x509_san_dns '${expectedDns}'`,
            severity: entity ? 'WARNING' : 'ERROR' });
        }
      } catch { /* ignore */ }
    }
    const taMatches: TrustedAuthorityMatch[] = (q.context?.trustedAuthorities ?? []).map((ta) => {
      if (ta.type === 'aki') {
        const akis = new Set(chain.map((c) => c.authorityKeyIdentifier).filter(Boolean) as string[]);
        if (anchor?.certificate.subjectKeyIdentifier) akis.add(anchor.certificate.subjectKeyIdentifier);
        const hit = ta.values.find((v) => akis.has(v));
        return { type: ta.type, values: ta.values, matched: !!hit, matchedValue: hit ?? null };
      }
      if (ta.type !== 'etsi_tl' && ta.type !== 'openid_federation') return { type: ta.type, values: ta.values, matched: false, matchedValue: null };
      const attr = ta.type === 'etsi_tl' ? 'trustedListUri' : 'trustAnchor';
      const have = [anchor?.constraints?.[attr], anchor?.provenance?.sourceUri, entity?.attributes?.[attr], entity?.provenance?.sourceUri]
        .filter(Boolean).map(String);
      const hit = ta.values.find((v) => have.includes(v));
      return { type: ta.type, values: ta.values, matched: !!hit, matchedValue: hit ?? null };
    });

    const errors = reasons.filter((r) => r.severity === 'ERROR');
    const snap = data.snapshot;
    const basis = data.source === 'snapshot' ? `trust snapshot v${snap?.version ?? '?'}` : 'app-bundled trust anchors only (no trust snapshot)';
    if (data.mode === 'outage') {
      reasons.push({ code: `fallback.${data.source}`, message: `Trust service unavailable; evaluated on this device from ${basis}`, severity: 'WARNING' });
    } else {
      reasons.push({ code: `local.${data.source}`, message: `Evaluated on this device from ${basis}`, severity: data.source === 'snapshot' ? 'INFO' : 'WARNING' });
    }
    if (data.stale) reasons.push({ code: 'snapshot.stale', message: `Trust snapshot expired at ${snap?.expiresAt ?? '?'} and could not be refreshed`, severity: 'WARNING' });
    let decision: TrustDecision['decision'];
    let summary: string;
    if (errors.length > 0) { decision = 'NOT_TRUSTED'; summary = errors[0]!.message; }
    else if (entity || anchor) {
      decision = 'TRUSTED';
      summary = entity ? `Trusted ${wantRole?.toLowerCase().replace('_', ' ') ?? 'entity'} '${pickName(entity)}'${entity.frameworkId ? ` in framework '${entity.frameworkId}'` : ''}`
        : `Certificate chain validates to trusted anchor in framework '${anchor!.frameworkId ?? 'local'}'`;
    } else {
      decision = 'UNKNOWN';
      summary = data.source === 'snapshot' ? 'No trust information found for the subject in accepted frameworks' : 'No trust information available on this device';
    }
    const frameworkId = entity?.frameworkId ?? anchor?.frameworkId;
    // Valid until the earliest of: the decision TTL, the snapshot's expiry, the entity's validity, the leaf certificate.
    let validUntil = time.getTime() + 3600_000;
    if (snap && !data.stale) validUntil = Math.min(validUntil, new Date(snap.expiresAt).getTime());
    if (entity?.validUntil) validUntil = Math.min(validUntil, new Date(entity.validUntil).getTime());
    if (chain[0]) validUntil = Math.min(validUntil, chain[0].notAfter.getTime());
    if (data.stale) validUntil = Math.min(validUntil, time.getTime() + 5 * 60_000);
    return {
      decision, summary, reasons, entity: entity ?? null,
      framework: data.frameworks.find((f) => f.id === frameworkId) ?? null,
      evidence: { x509, did: didEv, authorization, trustedAuthorities: taMatches, matchedIdentifiers: matched },
      evaluatedAt: time.toISOString(), validUntil: new Date(validUntil).toISOString(), source: data.source, snapshot: snap ?? null,
    };
  }
}
