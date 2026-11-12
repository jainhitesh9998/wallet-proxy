/**
 * Trust evaluation on the device, with the service's semantics (TrustEvaluator.java): the same rules over the same
 * data give the same decision. The data is the verified trust snapshot, or, when no snapshot is usable, the trust
 * pinned in the app; the rules are those in force (evaluation/rules.ts), the operator's trust mechanisms among them. A
 * decision can only be TRUSTED when the data vouches for the party; missing data yields UNKNOWN, never trust.
 *
 * The steps, in the order {@link LocalEvaluator.evaluate} takes them, are the service's, by the same names: begin (which
 * also selects the governing mechanism, selectMechanism), claim, keyProof (with validateChain), acceptKey, findEntity,
 * checkDid, checkStanding, checkResponseUri, matchAuthorities, decide.
 */
import { parseCertificate, type Certificate } from '../x509/certificate.js';
import { validateCertificateChain, type LocalAnchor, type ValidateOptions } from '../x509/validate.js';
import { anchorCrlUrls, crlUrlsToFetch, type HeldCrl } from '../x509/revocation.js';
import type { Crl } from '../x509/crl.js';
import { verifyX509Signature } from '../x509/signature.js';
import { bytesEqual } from '../util/bytes.js';
import { findVerificationMethod, hasRelationship, didError, parseDid } from '../did/did.js';
import { jwkThumbprint } from '../crypto/keys.js';
import type { TrustRules } from './rules.js';
import { selectMechanism, type KeyKind, type TrustMechanism } from './mechanisms.js';
import type { DidEvidence, DidResolutionResult, EntityView, Evidence, Identifier, PathValidationResult, Reason, SnapshotRef, TrustDecision,
  TrustFramework, TrustQuery, TrustedAuthorityMatch, TrustedAuthorityQuery } from '../types.js';

export interface LocalTrustData {
  entities: EntityView[];
  anchors: LocalAnchor[];
  /** CRLs held for revocation checks (the snapshot's anchor CRLs) */
  crls?: HeldCrl[];
  frameworks: TrustFramework[];
  /** 'snapshot' when a verified snapshot backs the data; 'pinned' when only the trust bundled with the app does */
  source: 'snapshot' | 'pinned';
  /**
   * The rule flags in force (evaluation/rules.ts): also with pinned trust, which has no client profile of its own.
   * Absent: none.
   */
  policy?: Partial<TrustRules>;
  /** The trust mechanisms in force, in the order they are tried (evaluation/rules.ts), also with pinned trust. Absent: none. */
  mechanisms?: readonly TrustMechanism[];
  snapshot?: SnapshotRef | null;
  stale?: boolean;
  /**
   * Asks the service's on-demand registries (OpenID Federation, EBSI) about a party absent from the snapshot. Called
   * where the service's evaluator asks, when no registry entry matched, with the same identifiers in the same order:
   * the key's own identifiers, or the identifier when no key is presented (only URLs and DIDs, never key material).
   */
  onDemand?: (identifiers: Array<{ type: string; value: string }>) => Promise<{ entity: EntityView; identifier: { type: string; value: string } } | undefined>;
}

/**
 * The key an identifier is matched by. Identifiers are compared as the specifications compare them: URLs (credential
 * issuer identifiers, client identifiers, federation entity identifiers) byte for byte, with no normalization
 * (RFC 8414 section 3.3, OpenID4VCI 1.0 section 12.2.1); DNS names without regard to case; DIDs without a fragment.
 * The service applies the same rule (Identifier.java), so a port in any language matches with a string comparison.
 */
export function identifierKey(type: string, value: string): string {
  if (type === 'DID') return value.split('#')[0]!;
  if (type === 'DNS') return value.toLowerCase();
  return value;
}

/** A plain https URL: lower-case host of letters, digits, '-' and '.', optional port, then path, query or nothing. */
const PLAIN_HTTPS = /^https:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?(?:[/?#].*)?$/;

/**
 * The host of a plain https URL, or undefined for anything else (another scheme, upper-case or non-ASCII host,
 * userinfo). Used where a host is compared with a certificate's dNSName; a URL this rule does not read is refused
 * there, so every implementation reads the same host without a URL parser (Identifier.httpsHost on the service).
 */
export function httpsHost(url: string): string | undefined {
  return PLAIN_HTTPS.exec(url)?.[1];
}

/**
 * Identifiers an on-demand registry can resolve (OpenID Federation entity ids, registry DIDs such as did:ebsi). Key
 * material is never sent: no fingerprints, and no DIDs that are a public key themselves.
 */
function onDemandIdentifier(i: { type: string; value: string }): boolean {
  if (i.type === 'DID') return !/^did:(key|jwk|peer):/.test(i.value);
  return (i.type === 'URL' || i.type === 'FEDERATION_ENTITY') && i.value.startsWith('https://');
}

/** The roles a query can name, in the form this library writes them; the service reads the same ones (EntityRole). */
export type QueryRole = NonNullable<TrustQuery['role']> | 'accreditation_authority' | 'other';

/**
 * The spellings of a role the service's API reads, and the registry's name of the role each names (Dtos.ROLES on the
 * service). conformance/evaluation/roles.json holds both to the same list: a spelling one side reads and the other does
 * not would decide a question under one mechanism on one side and under another, or none, on the other.
 */
export const ROLE_SPELLINGS: Readonly<Record<string, string>> = Object.freeze({
  issuer: 'CREDENTIAL_ISSUER', credential_issuer: 'CREDENTIAL_ISSUER',
  verifier: 'VERIFIER', relying_party: 'VERIFIER', rp: 'VERIFIER',
  wallet: 'WALLET_PROVIDER', wallet_provider: 'WALLET_PROVIDER',
  authorization_server: 'AUTHORIZATION_SERVER', as: 'AUTHORIZATION_SERVER',
  accreditation_authority: 'ACCREDITATION_AUTHORITY',
  status_list_provider: 'STATUS_LIST_PROVIDER',
  other: 'OTHER',
});
const SPELLINGS = new Map(Object.entries(ROLE_SPELLINGS));
const QUERY_ROLES = new Map<string, QueryRole>([['CREDENTIAL_ISSUER', 'issuer'], ['VERIFIER', 'verifier'], ['WALLET_PROVIDER', 'wallet_provider'],
  ['AUTHORIZATION_SERVER', 'authorization_server'], ['ACCREDITATION_AUTHORITY', 'accreditation_authority'],
  ['STATUS_LIST_PROVIDER', 'status_list_provider'], ['OTHER', 'other']]);

/**
 * A query's role, read as the service's API reads it (Dtos.parseRole): none when it is absent, empty or only spaces, tabs
 * or line breaks; otherwise, without those around it, with ASCII letters in lower case and '-' read as '_', one of
 * {@link ROLE_SPELLINGS}. Anything else is refused with an error, as the service refuses the request: read as no role,
 * it would be decided under no mechanism here and under one there. Only ASCII is folded, so that the rule is the same in
 * every language.
 */
export function readRole(role: unknown): QueryRole | undefined {
  if (role === undefined || role === null || (typeof role === 'string' && /^[ \t\r\n]*$/.test(role))) return undefined;
  const spelling = typeof role === 'string'
    ? role.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '').replace(/[A-Z]/g, (c) => c.toLowerCase()).replace(/-/g, '_') : undefined;
  const registry = spelling === undefined ? undefined : SPELLINGS.get(spelling);
  if (registry === undefined) {
    const shown = typeof role === 'string' ? (role.length <= 40 ? role : `${role.slice(0, 40)}…`) : String(role);
    throw new Error(`Unknown role '${shown}': the roles are ${[...SPELLINGS.keys()].join(', ')}`);
  }
  return QUERY_ROLES.get(registry);
}

export function domainFor(role: QueryRole | undefined, format?: string): string {
  if (role === 'verifier') return 'verifier-access';
  if (role === 'wallet_provider') return 'wallet-provider';
  if (role === 'status_list_provider') return 'status-list';
  return format === 'mso_mdoc' ? 'mdoc-iaca' : 'credential-issuer';
}

/** The registry's name of a role. */
function roleName(role: QueryRole | undefined): string | undefined {
  switch (role) {
    case 'issuer': return 'CREDENTIAL_ISSUER';
    case 'verifier': return 'VERIFIER';
    case 'wallet_provider': return 'WALLET_PROVIDER';
    case 'authorization_server': return 'AUTHORIZATION_SERVER';
    case 'status_list_provider': return 'STATUS_LIST_PROVIDER';
    case 'accreditation_authority': return 'ACCREDITATION_AUTHORITY';
    case 'other': return 'OTHER';
    default: return undefined;
  }
}

const canonicalFormat = (f?: string | null) => (f === 'vc+sd-jwt' ? 'dc+sd-jwt' : f);
/** A format or type that is empty or only spaces, tabs or line breaks is absent, on the service too. */
const present = (s?: string | null): string | undefined => (typeof s === 'string' && !/^[ \t\r\n]*$/.test(s) ? s : undefined);
/** OpenID4VP 1.0 §5.9.3 client identifier prefixes; anything else is a pre-registered client_id. */
const CLIENT_ID_PREFIXES = new Set(['redirect_uri', 'x509_san_dns', 'x509_hash', 'decentralized_identifier', 'verifier_attestation', 'openid_federation', 'origin']);
const pickName = (e: EntityView) => (e.display.find((d) => d.locale?.startsWith('en')) ?? e.display[0])?.name ?? e.id;
const goodStanding = (e: EntityView, now: Date) => e.status === 'ACTIVE' && !(e.validUntil && now > new Date(e.validUntil)) && !(e.validFrom && now < new Date(e.validFrom));
const error = (code: string, message: string): Reason => ({ code, message, severity: 'ERROR' });
const warning = (code: string, message: string): Reason => ({ code, message, severity: 'WARNING' });
const info = (code: string, message: string): Reason => ({ code, message, severity: 'INFO' });

interface ClientId { raw: string; prefix: string; value: string }

function parseClientId(raw: string): ClientId {
  const i = raw.indexOf(':');
  if (i > 0 && CLIENT_ID_PREFIXES.has(raw.slice(0, i))) return { raw, prefix: raw.slice(0, i), value: raw.slice(i + 1) };
  return { raw, prefix: 'pre-registered', value: raw };
}

function identifiersFor(identifier: string): Identifier[] {
  if (identifier.startsWith('did:')) return [{ type: 'DID', value: identifier }];
  if (identifier.startsWith('https://') || identifier.startsWith('http://')) return [{ type: 'URL', value: identifier }, { type: 'FEDERATION_ENTITY', value: identifier }];
  return [{ type: 'CLIENT_ID', value: identifier }, { type: 'OTHER', value: identifier }];
}

export interface CrlFetchResult {
  crls: HeldCrl[];
  /** error per CRL URL that could not be obtained */
  failures: Record<string, string>;
}
/** Fetches CRLs; {@code accept} tells whether a CRL is signed by the CA it is for, so only such CRLs are cached. */
export type CrlFetcher = (urls: string[], accept?: (url: string, crl: Crl) => boolean) => Promise<CrlFetchResult>;

/**
 * Path validation with revocation: first against the CRLs already held (the snapshot's), then — only for
 * certificates whose status is still unknown — against CRLs fetched by {@code fetchCrls}: from the distribution
 * points a certificate names, and for the certificate the trust anchor issued, from where the anchor's record says
 * its CA publishes ({@code constraints.crlUrls}; the service ships that CRL in the snapshot unless it is too large or
 * could not be loaded). Certificates under unknown anchors never trigger a download.
 */
export async function validateChainOnDevice(chain: Certificate[], anchors: LocalAnchor[], opts: ValidateOptions,
                                            data: Pick<LocalTrustData, 'crls' | 'policy'>, fetchCrls?: CrlFetcher) {
  const revocation = { crls: data.crls ?? [], require: data.policy?.requireRevocationStatus === true };
  const r = validateCertificateChain(chain, anchors, { ...opts, revocation });
  const anchor = r.anchorRef?.certificate;
  const anchorUrls = anchorCrlUrls(r.anchorRef);
  const urls = fetchCrls && r.anchorFound ? crlUrlsToFetch(chain, r.revocation, anchorUrls) : [];
  if (urls.length === 0) return r;
  // A CRL counts (and is cached) only when it is the CRL of a CA of this chain for that URL: signed by the issuer of a
  // certificate that names the URL as its distribution point, or, at a location the anchor lists, issued (by name)
  // and signed by the anchor itself, as the service accepts an anchor's CRL (CrlService).
  const issuerOf = (j: number) => chain[j + 1] ?? anchor;
  const byAnchor = (crl: Crl) => !!anchor && (bytesEqual(crl.issuerRaw, anchor.subjectRaw) || crl.issuer === anchor.subject)
    && verifyX509Signature(crl, anchor.publicKey);
  const accept = (url: string, crl: Crl) => (anchorUrls.includes(url) && byAnchor(crl))
    || chain.some((c, j) => c.crlDistributionPoints.includes(url) && !!issuerOf(j) && verifyX509Signature(crl, issuerOf(j)!.publicKey));
  const got = await fetchCrls!(urls, accept);
  return validateCertificateChain(chain, anchors, { ...opts, revocation: { ...revocation, crls: [...revocation.crls, ...got.crls], failures: got.failures } });
}

/** One evaluation: the query as the steps read it, and the reasons they give. */
interface Evaluation {
  query: TrustQuery;
  data: LocalTrustData;
  now: Date;
  /** the query's role as readRole reads it; undefined when it names none */
  role: QueryRole | undefined;
  /** the role as the registry names it */
  wantRole: string | undefined;
  format: string | undefined;
  type: string | undefined;
  types: string[];
  strict: boolean;
  /** the operator's mechanism that governs the question; undefined when none does: it is then decided by the built-in rules alone */
  mechanism: TrustMechanism | undefined;
  reasons: Reason[];
}
const hasDidKey = (ev: Evaluation) => !!ev.query.subject.kid?.startsWith('did:');
const hasJwk = (ev: Evaluation) => Object.keys(ev.query.subject.jwk ?? {}).length > 0;
/** The domain whose anchors count: the question's own, unless the governing mechanism names another in its x509 block. */
const governingDomain = (ev: Evaluation) => ev.mechanism?.x509?.domain ?? domainFor(ev.role, ev.format);

/** The method of a DID; undefined when it is not a DID. */
function didMethod(did: string): string | undefined {
  try {
    return parseDid(did).method;
  } catch {
    return undefined;
  }
}

/**
 * What the query claims. Its identifiers are only claimed by the identifier; those of the KeyProof are proven by the
 * presented key material (see the matching rules of findEntity).
 */
interface Claim {
  identifiers: Identifier[];
  clientId?: ClientId;
  expectedDns?: string;
  expectedHash?: string;
}

/** What the presented key proves. */
interface KeyProof {
  identifiers: Identifier[];
  /** the DID of a DID key, else the DID the identifier names */
  did: string | undefined;
  chain: Certificate[];
  x509: PathValidationResult | null;
  /** the trust anchor a valid chain leads to */
  anchor: LocalAnchor | undefined;
}

/** Registry entries the query may be about, each with what it was found through. */
class Candidates {
  entities: EntityView[] = [];
  readonly matched: string[] = [];

  take(entity: EntityView, how: string): void {
    if (!this.entities.includes(entity)) {
      this.entities.push(entity);
      this.matched.push(how);
    }
  }

  takeAll(found: Map<EntityView, string>): void {
    found.forEach((how, entity) => this.take(entity, how));
  }
}

interface Found { entity: EntityView | undefined; matched: string[] }

type Authorization = NonNullable<Evidence['authorization']>;

/** Certificates read from one x5c: a real chain has a few, and each one costs parsing and path building. As on the service. */
export const MAX_CHAIN = 10;

export class LocalEvaluator {
  constructor(private readonly resolveDid: (did: string) => Promise<DidResolutionResult>, private readonly now: () => Date = () => new Date(),
              private readonly fetchCrls?: CrlFetcher) {}

  async evaluate(q: TrustQuery, data: LocalTrustData): Promise<TrustDecision> {
    const ev = this.begin(q, data);
    const claim = this.claim(ev);
    const key = await this.keyProof(ev, claim);
    this.acceptKey(ev, key);
    const found = await this.findEntity(ev, claim, key);
    const entity = found.entity;
    const did = await this.checkDid(ev, key);
    const authorization = this.checkStanding(ev, key, entity);
    this.checkResponseUri(ev, claim, entity);
    const authorities = this.matchAuthorities(ev, key, entity);
    const evidence: Evidence = { x509: key.x509, did, authorization, trustedAuthorities: authorities, matchedIdentifiers: found.matched,
      ...(ev.mechanism ? { mechanism: ev.mechanism.id } : {}) };
    return this.decide(ev, key, entity, evidence);
  }

  private begin(query: TrustQuery, data: LocalTrustData): Evaluation {
    const now = query.context?.time ? new Date(query.context.time) : this.now();
    // An empty format or type is no format or type: the two evaluators must not read "" differently.
    const format = canonicalFormat(present(query.context?.credentialFormat)) ?? undefined;
    const type = present(query.context?.credentialType);
    // Every type the credential asserts must be authorized (a W3C VC may carry several). Each is read by the one rule of
    // present(), as the primary type is: what else counts as blank differs between platforms (String.trim here,
    // Character.isWhitespace on the service), and a type one evaluator drops and the other checks is decided differently.
    const listed = query.context?.credentialTypes ?? [];
    if (!Array.isArray(listed) || listed.some((t) => typeof t !== 'string')) {
      // As the service refuses such a request: something that is not a type is neither a type nor the absence of one.
      throw new Error('context.credentialTypes must be a list of types (strings)');
    }
    const types = [...new Set([type, ...listed.map(present)].filter((t): t is string => t !== undefined))];
    const role = readRole(query.role);
    return { query, data, now, role, wantRole: roleName(role), format, type, types,
      strict: data.policy?.strictAuthorization === true, mechanism: this.selectMechanism(data, role, format, types), reasons: [] };
  }

  /**
   * The operator's mechanism that governs the question: the first of those in force whose {@code for} matches its role,
   * its format and any of the types it asserts. None: the question is decided exactly as without mechanisms. A question
   * that names no role is an issuer question here, as it is for the rest of the evaluation (its chain is validated in the
   * issuer domains, see domainFor): otherwise leaving the role out would be a way around every issuer mechanism.
   */
  private selectMechanism(data: LocalTrustData, role: QueryRole | undefined, format: string | undefined, types: string[]): TrustMechanism | undefined {
    return selectMechanism(data.mechanisms ?? [], role ?? 'issuer', format, types);
  }

  private claim(ev: Evaluation): Claim {
    const identifier = ev.query.subject.identifier;
    if (!identifier) return { identifiers: [] };
    if (ev.role !== 'verifier') return { identifiers: identifiersFor(identifier) };
    return this.clientIdClaim(ev, parseClientId(identifier));
  }

  private clientIdClaim(ev: Evaluation, clientId: ClientId): Claim {
    const { prefix, value } = clientId;
    const identifiers: Identifier[] = [{ type: 'CLIENT_ID', value: clientId.raw }];
    let expectedDns: string | undefined;
    let expectedHash: string | undefined;
    switch (prefix) {
      case 'x509_san_dns':
        expectedDns = value;
        identifiers.push({ type: 'DNS', value });
        break;
      case 'x509_hash':
        expectedHash = value;
        identifiers.push({ type: 'X509_SHA256', value });
        break;
      case 'decentralized_identifier': identifiers.push({ type: 'DID', value }); break;
      case 'redirect_uri': case 'origin': identifiers.push({ type: 'URL', value }); break;
      case 'openid_federation': identifiers.push({ type: 'FEDERATION_ENTITY', value }, { type: 'URL', value }); break;
      case 'verifier_attestation':
        ev.reasons.push(info('client_id.verifier_attestation', 'Verifier attestation JWT must be validated by the wallet; matching registry by client_id only'));
        break;
    }
    if ((prefix === 'x509_san_dns' || prefix === 'x509_hash') && !ev.query.subject.x5c?.length) {
      ev.reasons.push(error('client_id.x5c_required', `Client identifier prefix ${prefix} requires the request object's x5c chain`));
    }
    return { identifiers, clientId, expectedDns, expectedHash };
  }

  private async keyProof(ev: Evaluation, claim: Claim): Promise<KeyProof> {
    const proven: Identifier[] = [];
    const did = this.keyDid(ev, proven);
    this.keyThumbprint(ev, proven);
    const chain = this.parseChain(ev);
    const validated = chain.length > 0 ? await this.validateChain(ev, claim, chain, proven) : undefined;
    const x509 = validated?.x509 ?? null;
    // A client identifier the presented key itself proves is one of the key's identifiers, so a verifier registered by
    // its client_id is found: x509_hash of the leaf certificate, x509_san_dns naming a dNSName of a validated leaf,
    // decentralized_identifier of the key's DID.
    if (claim.clientId && this.provesClientId(claim.clientId, chain, x509, hasDidKey(ev) ? did : undefined)) {
      proven.push({ type: 'CLIENT_ID', value: claim.clientId.raw });
    }
    return { identifiers: proven, did, chain, x509, anchor: validated?.anchor };
  }

  /**
   * A query names one key: the certificate's or the DID's. With both, the evaluator cannot tell which one the caller
   * verified the signature with, and the other may be copied from anyone (callers pass only the key they checked).
   */
  private keyDid(ev: Evaluation, proven: Identifier[]): string | undefined {
    const { subject } = ev.query;
    if ((subject.x5c?.length ?? 0) > 0 && hasDidKey(ev)) {
      ev.reasons.push(error('key.ambiguous', 'The query presents both an x5c chain and a DID key; pass only the key the signature was verified with'));
    }
    let did: string | undefined;
    if (hasDidKey(ev)) {
      try {
        did = parseDid(subject.kid!).did;
        proven.push({ type: 'DID', value: did });
      } catch {
        ev.reasons.push(error('did.invalid', 'kid is not a valid DID URL'));
      }
    } else if (subject.identifier?.startsWith('did:')) {
      did = subject.identifier.split('#')[0];
    }
    return did;
  }

  private keyThumbprint(ev: Evaluation, proven: Identifier[]): void {
    if (hasJwk(ev)) {
      try {
        proven.push({ type: 'JWK_THUMBPRINT', value: jwkThumbprint(ev.query.subject.jwk!) });
      } catch (e) {
        ev.reasons.push(warning('jwk.invalid', `Unparseable JWK: ${(e as Error).message}`));
      }
    }
  }

  private parseChain(ev: Evaluation): Certificate[] {
    const x5c = ev.query.subject.x5c ?? [];
    if (x5c.length > MAX_CHAIN) {
      ev.reasons.push(error('x509.chain_too_long', `x5c holds ${x5c.length} certificates; a chain of more than ${MAX_CHAIN} is not read`));
      return [];
    }
    try {
      return (ev.query.subject.x5c ?? []).map((c) => parseCertificate(c));
    } catch (e) {
      ev.reasons.push(error('x509.parse', (e as Error).message));
      return [];
    }
  }

  private async validateChain(ev: Evaluation, claim: Claim, chain: Certificate[], proven: Identifier[]): Promise<{ x509: PathValidationResult; anchor: LocalAnchor | undefined }> {
    const { reasons } = ev;
    const leaf = chain[0]!;
    // The leaf's hash is a pin (the caller verifies with the leaf's key); its other names count only once the chain validates.
    proven.push({ type: 'X509_SHA256', value: leaf.sha256 });
    if (claim.expectedHash !== undefined && claim.expectedHash !== leaf.sha256) {
      reasons.push(error('client_id.x509_hash_mismatch', 'x509_hash client_id does not match the SHA-256 hash of the leaf certificate'));
    }
    const questionDomain = domainFor(ev.role, ev.format);
    const rule = ev.mechanism?.x509;
    const domain = governingDomain(ev);
    const anchors = ev.data.anchors.filter((a) => a.domain === domain);
    // The built-in profile follows the question (profileDomain), also when its anchors are another domain's: a mechanism
    // adds requirements on top of it and never takes one away.
    const revocationRequired = ev.data.policy?.requireRevocationStatus === true || rule?.revocation === 'required';
    const r = await validateChainOnDevice(chain, anchors, { time: ev.now, domain, profileDomain: questionDomain, requirements: rule?.profile,
      expectedDnsName: claim.expectedDns, docType: ev.format === 'mso_mdoc' ? ev.type : undefined },
    { crls: ev.data.crls, policy: { requireRevocationStatus: revocationRequired } }, this.fetchCrls);
    const { anchorRef, ...x509 } = r;
    if (r.valid) {
      if (leaf.subjectKeyIdentifier) proven.push({ type: 'X509_SKI', value: leaf.subjectKeyIdentifier });
      proven.push({ type: 'X509_SUBJECT', value: leaf.subject });
      leaf.dnsNames.forEach((n) => proven.push({ type: 'DNS', value: n }));
      leaf.uriNames.forEach((u) => proven.push({ type: 'URL', value: u }));
      reasons.push(info('x509.valid', `Certificate chain validates to trust anchor ${anchorRef?.certificate.subject ?? ''} in domain ${domain}`));
      reasons.push(...r.issues.filter((i) => i.code.startsWith('x509.revocation') && i.severity === 'WARNING'));
    } else if (!r.anchorFound) {
      reasons.push(warning('x509.no_anchor', anchors.length === 0 ? `No trust anchors configured for domain '${domain}' in accepted frameworks`
        : `Certificate chain does not lead to any trust anchor in domain '${domain}'`));
    } else {
      reasons.push(...r.issues.filter((i) => i.severity === 'ERROR'));
    }
    const { expectedDns } = claim;
    if (expectedDns !== undefined && !r.anchorFound && !leaf.dnsNames.some((d) => d.toLowerCase() === expectedDns.toLowerCase())) {
      reasons.push(error('client_id.san_dns_mismatch', 'Leaf certificate has no SAN dNSName equal to the x509_san_dns client_id'));
    }
    return { x509, anchor: r.valid ? anchorRef : undefined };
  }

  /**
   * The proofs of key the governing mechanism accepts: a key presented another way (an x5c chain, a DID key, a bare JWK)
   * is refused, and so is a DID key of a method it does not list. A question without key material is a registry lookup,
   * and nothing here refuses it.
   */
  private acceptKey(ev: Evaluation, key: KeyProof): void {
    const m = ev.mechanism;
    if (!m) return;
    // A kid relative to a DID identifier ("#key-1") names a key of that DID, as checkDid reads it: here it is a DID key
    // like an absolute one, or it would be a way around keys and did.methods.
    const { subject } = ev.query;
    const relativeDidKey = !hasDidKey(ev) && !!subject.kid?.startsWith('#') && !!subject.identifier?.startsWith('did:');
    const didKey = hasDidKey(ev) || relativeDidKey;
    const presented: Array<[KeyKind, boolean]> = [['x5c', (subject.x5c?.length ?? 0) > 0], ['did', didKey], ['jwk', hasJwk(ev)]];
    for (const [kind, present] of presented) {
      if (present && m.keys && !m.keys.includes(kind)) {
        ev.reasons.push(error('mechanism.key_not_accepted', `Trust mechanism '${m.id}' does not accept a key presented as ${kind}; it accepts ${m.keys.join(', ')}`));
      }
    }
    // key.did is the DID of an absolute DID key only when it parsed (one that did not is refused as did.invalid already),
    // and for a relative one the identifier's DID as written: a DID whose method cannot be read is no DID of a method the
    // mechanism accepts.
    if (m.did && didKey && key.did !== undefined) {
      const method = didMethod(key.did);
      if (method === undefined || !m.did.methods.includes(method)) {
        ev.reasons.push(error('mechanism.did_method_not_accepted', `Trust mechanism '${m.id}' does not accept a key of `
          + `${method === undefined ? 'a DID whose method cannot be read' : `DID method '${method}'`}; it accepts ${m.did.methods.join(', ')}`));
      }
    }
  }

  private provesClientId(clientId: ClientId, chain: Certificate[], x509: PathValidationResult | null, keyDid: string | undefined): boolean {
    const leaf = chain[0];
    switch (clientId.prefix) {
      case 'x509_hash': return !!leaf && leaf.sha256 === clientId.value;
      case 'x509_san_dns': return !!leaf && x509?.valid === true && leaf.dnsNames.some((d) => d.toLowerCase() === clientId.value.toLowerCase());
      case 'decentralized_identifier': return keyDid !== undefined && keyDid === identifierKey('DID', clientId.value);
      default: return false;
    }
  }

  /**
   * Matching. With key material (x5c, DID kid, JWK) an entity is found only through what that key proves: the key's
   * own identifiers (a validated certificate's names, the DID of a DID key, a JWK thumbprint), a pinned leaf
   * certificate, or the entity the validated anchor belongs to. The identifier in the query is then only a claim.
   * Without key material the identifier is a registry lookup (issuer metadata, or a key the caller fetched from it).
   */
  private async findEntity(ev: Evaluation, claim: Claim, key: KeyProof): Promise<Found> {
    const keyMaterial = key.chain.length > 0 || hasDidKey(ev) || hasJwk(ev);
    const claimed = this.registered(ev, claim.identifiers);
    const candidates = new Candidates();
    if (!keyMaterial) {
      candidates.takeAll(claimed);
    } else {
      this.takeBoundToKey(ev, key, candidates);
      this.checkPinnedCertificate(ev, key, candidates);
      this.checkClaimBound(ev, key, [...claimed.keys()], candidates);
    }
    if (candidates.entities.length === 0 && ev.data.onDemand) {
      // On-demand discovery follows the same rule: the key's identifiers, or the identifier without key material.
      await this.lookUpOnDemand(ev, keyMaterial ? key.identifiers : claim.identifiers, candidates);
    }
    this.keepRole(ev, candidates);
    const entity = this.pick(candidates.entities, key.anchor, ev.now, (e) => this.denied(e, ev.format, ev.types, ev.strict) === undefined);
    return { entity, matched: candidates.matched };
  }

  /** In the order of the identifiers asked about, as the service does: what is reported as matched is then the same. */
  private registered(ev: Evaluation, identifiers: Identifier[]): Map<EntityView, string> {
    const found = new Map<EntityView, string>();
    for (const id of identifiers) {
      const key = identifierKey(id.type, id.value);
      for (const e of ev.data.entities) {
        if (!found.has(e) && e.identifiers.some((x) => x.type === id.type && identifierKey(x.type, x.value) === key)) found.set(e, `${id.type}:${key}`);
      }
    }
    return found;
  }

  private takeBoundToKey(ev: Evaluation, key: KeyProof, candidates: Candidates): void {
    candidates.takeAll(this.registered(ev, key.identifiers));
    const leaf = key.chain[0];
    if (leaf) {
      ev.data.entities.filter((e) => e.certificates?.some((c) => c.sha256 === leaf.sha256))
        .forEach((e) => candidates.take(e, `X509_CERT:${leaf.sha256}`));
    }
    const { anchor } = key;
    if (anchor?.entityId) {
      const e = ev.data.entities.find((x) => x.id === anchor.entityId);
      if (e) candidates.take(e, `ANCHOR:${e.id}`);
    }
  }

  private checkPinnedCertificate(ev: Evaluation, key: KeyProof, candidates: Candidates): void {
    const leaf = key.chain[0];
    if (leaf && !key.anchor && candidates.entities.length > 0) {
      // No anchor vouches for this certificate: it stands only as a registered pin, and then only while valid.
      const { now } = ev;
      if (now < leaf.notBefore || now > leaf.notAfter) {
        ev.reasons.push(error('x509.pinned_expired', `The pinned certificate is not valid at ${now.toISOString()}`));
      }
      // A mechanism with an x509 block says which anchors count and what their chains must satisfy. A pin is no such
      // anchor: accepted, it would bring the certificate past every one of those requirements, so that the mechanism
      // would loosen what it is there to tighten. Certificate material binds an entity under such a mechanism only through
      // a chain that validated to an anchor of the governing domain.
      const m = ev.mechanism;
      if (m?.x509) {
        ev.reasons.push(error('mechanism.anchor_required', `Trust mechanism '${m.id}' accepts a certificate only through a chain to an anchor of `
          + `domain '${governingDomain(ev)}'; a pinned certificate does not replace the anchor`));
      }
    }
  }

  private checkClaimBound(ev: Evaluation, key: KeyProof, claimed: EntityView[], candidates: Candidates): void {
    // Refused when the identifier names entities in this role and the key is bound to none of them.
    const { wantRole } = ev;
    const named = claimed.filter((e) => !wantRole || e.roles.includes(wantRole));
    if (named.length && !named.some((e) => candidates.entities.includes(e))) {
      ev.reasons.push(error('identifier.unbound', `The identifier names '${pickName(named[0]!)}', but the presented `
        + `${key.chain.length ? 'certificate' : 'key'} is not bound to it`));
    }
  }

  private async lookUpOnDemand(ev: Evaluation, identifiers: Identifier[], candidates: Candidates): Promise<void> {
    const found = await ev.data.onDemand?.(identifiers.filter(onDemandIdentifier));
    if (found) {
      candidates.take(found.entity, `${found.identifier.type}:${identifierKey(found.identifier.type, found.identifier.value)} (on-demand)`);
      ev.reasons.push(info('lookup.on_demand', 'Not in the trust snapshot; registry entry obtained by an on-demand lookup at the trust service'));
    }
  }

  private keepRole(ev: Evaluation, candidates: Candidates): void {
    const { wantRole } = ev;
    if (wantRole) {
      const withRole = candidates.entities.filter((e) => e.roles.includes(wantRole));
      if (candidates.entities.length > 0 && withRole.length === 0) {
        ev.reasons.push(warning('entity.role_mismatch', `Matching entity is registered, but not as ${wantRole}`));
      }
      candidates.entities = withRole;
    }
  }

  /**
   * The entity the decision is about. When the key is bound to several registered parties, which one is meant must not
   * depend on the order a snapshot lists them in: the entity the anchor belongs to; else, in order of entity id, the
   * first in good standing that is authorized for what is asked; else the first in good standing; else the first.
   */
  private pick(candidates: EntityView[], anchor: LocalAnchor | undefined, now: Date, authorized: (e: EntityView) => boolean): EntityView | undefined {
    const ordered = [...candidates].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return (anchor?.entityId ? ordered.find((e) => e.id === anchor.entityId) : undefined)
      ?? ordered.find((e) => goodStanding(e, now) && authorized(e)) ?? ordered.find((e) => goodStanding(e, now)) ?? ordered[0];
  }

  /** the type the entity is not authorized for ('' when no type is asked and the format is refused); undefined when it is authorized */
  private denied(e: EntityView, format: string | undefined, types: string[], strict: boolean): string | undefined {
    if (!format && types.length === 0) return undefined;
    if (e.authorizations.length === 0) return strict ? (types[0] ?? '') : undefined;
    const allowed = (t?: string) => e.authorizations.some((a) => (!a.format || !format || canonicalFormat(a.format) === format) && (!a.type || !t || a.type === t));
    return types.length ? types.find((t) => !allowed(t)) : (allowed() ? undefined : '');
  }

  private async checkDid(ev: Evaluation, key: KeyProof): Promise<DidEvidence | null> {
    const { did } = key;
    const ref = ev.query.subject.kid;
    if (!did || !ref) return null;
    const { reasons } = ev;
    // The DID URL lets the resolver skip a snapshot document that lacks this (e.g. rotated) key.
    // A relative reference ("#key-1") names a key of the DID.
    const kid = ref.startsWith('#') ? `${did}${ref}` : ref;
    const res = await this.resolveDid(kid.includes('#') ? kid : did);
    const err = didError(res);
    if (err || !res.didDocument) {
      reasons.push(warning('did.unresolved', `DID ${did} could not be resolved: ${err ?? 'no document'}`));
      return { did, resolved: false, error: err };
    }
    if (!ref.includes('#')) {
      return { did, resolved: true };
    }
    const vm = findVerificationMethod(res.didDocument, ref);
    if (!vm) {
      reasons.push(error('did.vm_not_found', `Verification method ${ref} is not in the DID document`));
      return { did, resolved: true, verificationMethod: ref, verificationMethodFound: false };
    }
    const relationship = ev.role === 'verifier' || ev.role === 'wallet_provider' ? 'authentication' : 'assertionMethod';
    // DID Core: a relationship lists verification methods (by reference or embedded), never the DID itself.
    const rel = hasRelationship(res.didDocument, relationship, ref);
    if (!rel) {
      reasons.push(error('did.relationship', `Verification method ${ref} is not authorized for ${relationship}`));
    }
    return { did, resolved: true, verificationMethod: ref, verificationMethodFound: true, relationship, relationshipValid: rel };
  }

  private checkStanding(ev: Evaluation, key: KeyProof, entity: EntityView | undefined): Authorization | null {
    if (!entity) return null;
    const { now } = ev;
    if (!goodStanding(entity, now)) {
      const expired = !!entity.validUntil && now > new Date(entity.validUntil);
      ev.reasons.push(error('entity.status', `Entity '${entity.id}' is ${entity.status}${expired ? ' (expired)' : ''}`));
    }
    const authorization = ev.format || ev.type ? this.checkAuthorization(ev, entity) : null;
    const { anchor } = key;
    if (anchor?.frameworkId && anchor.frameworkId !== entity.frameworkId) {
      ev.reasons.push(info('framework.mixed', `Chain anchor framework '${anchor.frameworkId}' differs from entity framework '${entity.frameworkId}'`));
    }
    return authorization;
  }

  private checkAuthorization(ev: Evaluation, entity: EntityView): Authorization {
    const { format, type } = ev;
    const denied = this.denied(entity, format, ev.types, ev.strict);
    if (denied !== undefined) {
      ev.reasons.push(error('entity.not_authorized', `Entity '${entity.id}' is not authorized for ${format ?? ''} ${denied || type || ''}`.trim()));
    }
    return { format, type, authorized: denied === undefined, rule: entity.authorizations.length === 0
      ? (ev.strict ? 'strict: no authorizations registered' : 'unconstrained') : 'registered authorizations' };
  }

  private checkResponseUri(ev: Evaluation, claim: Claim, entity: EntityView | undefined): void {
    const { expectedDns } = claim;
    const responseUri = ev.query.context?.responseUri;
    if (expectedDns === undefined || responseUri === undefined || responseUri === null) return;
    // A response_uri that is not a plain https URL has no host to compare, and is refused like a mismatch.
    const host = httpsHost(responseUri);
    if (host === undefined) {
      ev.reasons.push(error('client_id.response_uri_host', 'response_uri is not a plain https URL'));
    } else if (host !== expectedDns.toLowerCase()) {
      ev.reasons.push(entity
        ? warning('client_id.response_uri_host', 'response_uri host differs from x509_san_dns; accepted because the verifier is registered')
        : error('client_id.response_uri_host', `response_uri host '${host}' does not match x509_san_dns '${expectedDns}'`));
    }
  }

  private matchAuthorities(ev: Evaluation, key: KeyProof, entity: EntityView | undefined): TrustedAuthorityMatch[] {
    return (ev.query.context?.trustedAuthorities ?? []).map((ta) => this.matchAuthority(ta, key.chain, key.anchor, entity));
  }

  private matchAuthority(ta: TrustedAuthorityQuery, chain: Certificate[], anchor: LocalAnchor | undefined, entity: EntityView | undefined): TrustedAuthorityMatch {
    if (ta.type === 'aki') {
      // The first of the chain's key identifiers (leaf first, then the anchor's own) that the query lists.
      const akis = new Set(chain.map((c) => c.authorityKeyIdentifier).filter(Boolean) as string[]);
      if (anchor?.certificate.subjectKeyIdentifier) akis.add(anchor.certificate.subjectKeyIdentifier);
      const hit = [...akis].find((v) => ta.values.includes(v));
      return { type: ta.type, values: ta.values, matched: !!hit, matchedValue: hit ?? null };
    }
    if (ta.type !== 'etsi_tl' && ta.type !== 'openid_federation') return { type: ta.type, values: ta.values, matched: false, matchedValue: null };
    const attr = ta.type === 'etsi_tl' ? 'trustedListUri' : 'trustAnchor';
    const have = [anchor?.constraints?.[attr], anchor?.provenance?.sourceUri, entity?.attributes?.[attr], entity?.provenance?.sourceUri]
      .filter((v) => v !== undefined && v !== null).map(String);
    const hit = have.find((v) => ta.values.includes(v));
    return { type: ta.type, values: ta.values, matched: !!hit, matchedValue: hit ?? null };
  }

  private decide(ev: Evaluation, key: KeyProof, entity: EntityView | undefined, evidence: Evidence): TrustDecision {
    const { data, reasons } = ev;
    const { anchor } = key;
    const errors = reasons.filter((r) => r.severity === 'ERROR');
    const snap = data.snapshot;
    reasons.push(data.source === 'snapshot'
      ? info('local.snapshot', `Evaluated on this device from the trust snapshot issued ${snap?.issuedAt ?? '?'}`)
      : warning('local.pinned', 'No trust snapshot is available: evaluated on this device from the trust pinned in the app'));
    if (data.stale) reasons.push(warning('snapshot.stale', `Trust snapshot expired at ${snap?.expiresAt ?? '?'} and could not be refreshed`));
    let decision: TrustDecision['decision'];
    let summary: string;
    if (errors.length > 0) {
      decision = 'NOT_TRUSTED';
      summary = errors[0]!.message;
    } else if (entity || anchor) {
      decision = 'TRUSTED';
      summary = entity ? `Trusted ${ev.wantRole?.toLowerCase().replace(/_/g, ' ') ?? 'entity'} '${pickName(entity)}'${entity.frameworkId ? ` in framework '${entity.frameworkId}'` : ''}`
        : `Certificate chain validates to trusted anchor in framework '${anchor!.frameworkId ?? 'local'}'`;
    } else {
      decision = 'UNKNOWN';
      summary = data.source === 'snapshot' ? 'No trust information found for the subject in accepted frameworks' : 'No trust information available on this device';
    }
    const frameworkId = entity ? entity.frameworkId : anchor?.frameworkId;
    return {
      decision, summary, reasons, entity: entity ?? null,
      framework: data.frameworks.find((f) => f.id === frameworkId) ?? null,
      evidence,
      evaluatedAt: ev.now.toISOString(), validUntil: this.validUntil(ev, key, entity).toISOString(), source: data.source, snapshot: snap ?? null,
    };
  }

  private validUntil(ev: Evaluation, key: KeyProof, entity: EntityView | undefined): Date {
    const { data, now } = ev;
    const snap = data.snapshot;
    // Valid until the earliest of: the decision TTL, the snapshot's expiry, the entity's validity, the leaf certificate.
    let validUntil = now.getTime() + 3600_000;
    if (snap && !data.stale) validUntil = Math.min(validUntil, new Date(snap.expiresAt).getTime());
    if (entity?.validUntil) validUntil = Math.min(validUntil, new Date(entity.validUntil).getTime());
    if (key.chain[0]) validUntil = Math.min(validUntil, key.chain[0].notAfter.getTime());
    if (data.stale) validUntil = Math.min(validUntil, now.getTime() + 5 * 60_000);
    return new Date(validUntil);
  }
}
