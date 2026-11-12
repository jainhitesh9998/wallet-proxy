/** Wire types of the trust service API (camelCase JSON) plus client-side provenance. */
import type { Jwk } from './crypto/keys.js';

export type Decision = 'TRUSTED' | 'NOT_TRUSTED' | 'UNKNOWN';
export type Severity = 'ERROR' | 'WARNING' | 'INFO';
/**
 * What a trust decision rests on. Decisions are always made on this device: from the verified trust snapshot
 * ('snapshot'), or from the trust pinned in the app because no usable snapshot exists ('pinned').
 */
export type DecisionSource = 'snapshot' | 'pinned';
/**
 * Where a document (metadata, DID document, CRL, status list, JSON-LD context) came from: the trust snapshot, the
 * service's proxy, the party itself by the standard mechanism as the configured path ('direct') or because the
 * proxy could not serve it ('fallback'), or this device's cache.
 */
export type DataSource = 'snapshot' | 'proxy' | 'direct' | 'fallback' | 'cache';
export type Role = 'issuer' | 'verifier' | 'wallet_provider' | 'authorization_server' | 'status_list_provider';

export interface ValidationIssue {
  code: string;
  message: string;
  severity: Severity;
}
export type Reason = ValidationIssue;

export interface CertificateSummary {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  sha256: string;
  subjectKeyIdentifier?: string;
  authorityKeyIdentifier?: string;
  dnsNames: string[];
  ca: boolean;
  certificate: string;
}

export interface PathValidationResult {
  valid: boolean;
  anchorFound: boolean;
  anchor?: Record<string, unknown> | null;
  path: CertificateSummary[];
  issues: ValidationIssue[];
  profile: string;
  validationTime: string;
  /** revocation status of each certificate below the anchor (absent or empty when not checked) */
  revocation?: CertificateRevocation[];
}

/** Revocation status of one certificate of a validated path (issue codes x509.not_revoked / revoked / on_hold / revocation_unknown). */
export interface CertificateRevocation {
  /** position in the validated path, leaf = 0 */
  index: number;
  /** lowercase hex, no leading zeros */
  serialNumber: string;
  subject: string;
  status: 'GOOD' | 'REVOKED' | 'ON_HOLD' | 'UNKNOWN';
  /** CRL reason name when revoked; why, when unknown */
  reason?: string | null;
  revokedAt?: string | null;
  /** 'crl' (device and service) or 'ocsp' (service only, when enabled there) */
  method?: 'crl' | 'ocsp' | null;
  crlUrl?: string | null;
  /** where the CRL came from: 'snapshot', 'cache', 'direct', 'trust-service' */
  source?: string | null;
  thisUpdate?: string | null;
  nextUpdate?: string | null;
}

export interface Identifier {
  type: string;
  value: string;
}

export interface LocalizedDisplay {
  locale?: string;
  name?: string;
  description?: string;
  logoUri?: string;
}

export interface CredentialAuthorization {
  format?: string | null;
  type?: string | null;
  constraints?: Record<string, unknown>;
}

export interface EntityView {
  id: string;
  frameworkId?: string;
  roles: string[];
  identifiers: Identifier[];
  display: LocalizedDisplay[];
  authorizations: CredentialAuthorization[];
  status: string;
  validFrom?: string;
  validUntil?: string;
  certificates?: CertificateSummary[];
  attributes?: Record<string, unknown>;
  provenance?: { sourceId?: string; sourceType?: string; frameworkId?: string; sourceUri?: string; retrievedAt?: string };
  metadataTypes?: string[];
  /** Registry metadata policy (snapshot only), applied to directly fetched metadata. */
  metadataPolicy?: Record<string, Record<string, unknown>>;
}

export interface TrustFramework {
  id: string;
  name: string;
  description?: string;
  governanceUri?: string;
  attributes?: Record<string, string>;
}

export interface DidEvidence {
  did: string;
  resolved: boolean;
  error?: string | null;
  verificationMethod?: string | null;
  verificationMethodFound?: boolean | null;
  relationship?: string | null;
  relationshipValid?: boolean | null;
}

export interface TrustedAuthorityMatch {
  type: string;
  values: string[];
  matched: boolean;
  matchedValue?: string | null;
}

export interface Evidence {
  x509?: PathValidationResult | null;
  did?: DidEvidence | null;
  authorization?: { format?: string | null; type?: string | null; authorized: boolean; rule?: string } | null;
  trustedAuthorities?: TrustedAuthorityMatch[];
  matchedIdentifiers?: string[];
  clientId?: Record<string, unknown> | null;
  /** The id of the operator's trust mechanism that governed the question; absent when none did. */
  mechanism?: string;
}

export interface TrustDecision {
  decision: Decision;
  summary: string;
  reasons: Reason[];
  entity?: EntityView | null;
  framework?: TrustFramework | null;
  evidence?: Evidence;
  evaluatedAt: string;
  validUntil: string;
  source: DecisionSource;
  /** The trust snapshot a device-side decision was made from. */
  snapshot?: SnapshotRef | null;
}

export interface SnapshotRef {
  /** identifies the snapshot's content (the service's ETag digest) */
  id: string;
  issuedAt: string;
  expiresAt: string;
  /** past its expiry, within the allowed grace period */
  stale: boolean;
}

export interface TrustedAuthorityQuery {
  type: 'aki' | 'etsi_tl' | 'openid_federation' | string;
  values: string[];
}

export interface TrustQuery {
  role?: Role;
  subject: {
    /** credential_issuer URL, DID, OpenID4VP client_id (with prefix), federation entity id */
    identifier?: string;
    /** certificate chain, leaf first, base64 DER */
    x5c?: string[];
    jwk?: Jwk;
    /** key reference, typically a DID URL */
    kid?: string;
  };
  context?: {
    protocol?: 'oid4vci' | 'oid4vp' | string;
    credentialFormat?: string;
    credentialType?: string;
    /** every specific type a W3C VC asserts (beyond VerifiableCredential); each must be authorized */
    credentialTypes?: string[];
    time?: string;
    responseUri?: string;
    trustedAuthorities?: TrustedAuthorityQuery[];
  };
}

export interface IssuerMetadataResult {
  credentialIssuer: string;
  credentialIssuerMetadata: Record<string, unknown>;
  authorizationServers: Record<string, Record<string, unknown>>;
  signedMetadata?: string | null;
  signedMetadataVerified?: boolean | null;
  policyApplied: boolean;
  fetchedAt: string;
  expiresAt: string;
  stale: boolean;
  warnings: string[];
  entityId?: string | null;
  trust: TrustDecision;
  /** client-side: where the metadata came from */
  source: DataSource;
}

export interface DidDocument {
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  [k: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller?: string;
  publicKeyJwk?: Jwk;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  [k: string]: unknown;
}

export interface DidResolutionResult {
  didDocument: DidDocument | null;
  didResolutionMetadata: Record<string, unknown> & { error?: unknown; source?: DataSource };
  didDocumentMetadata: Record<string, unknown>;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export interface ServiceDiscovery {
  issuer: string;
  jwks_uri: string;
  signing_key_thumbprint: string;
  endpoints: Record<string, string>;
  did_methods: string[];
  trust_domains: string[];
  credential_formats: string[];
  [k: string]: unknown;
}

export interface EntityFilter {
  framework?: string;
  format?: string;
  type?: string;
  q?: string;
  page?: number;
  size?: number;
}

export interface ServiceStatusEvent {
  status: ServiceStatus;
  reason?: string;
}

/** 'unconfigured': no trust service; 'unknown': not contacted yet. */
export type ServiceStatus = 'unconfigured' | 'unknown' | 'online' | 'offline';
