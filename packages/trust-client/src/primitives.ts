/**
 * Building blocks of the trust client, for code that verifies credentials next to it (a wallet's or a verifier's
 * credential verification): CBOR/COSE, JOSE, X.509 and CRL parsing, DID documents, status lists, and the device-side
 * evaluator itself. They change with the client; only the main entry is a stable interface.
 */
export { LocalEvaluator, validateChainOnDevice, identifierKey, httpsHost } from './evaluation/local.js';
export type { LocalTrustData, CrlFetchResult, CrlFetcher } from './evaluation/local.js';
export { SNAPSHOT_FORMAT, snapshotRef } from './snapshot/snapshot.js';
export type { SnapshotData, SnapshotPolicy, SnapshotContext } from './snapshot/snapshot.js';
export { extractIssuerInfo, issuerTrustQuery, decodeIssuerSigned, parseCoseSign1, coseX5chain } from './credential/extract.js';
export type { IssuerInfo, CoseSign1 } from './credential/extract.js';
export { parseCertificate } from './x509/certificate.js';
export type { Certificate } from './x509/certificate.js';
export { validateCertificateChain } from './x509/validate.js';
export type { LocalAnchor, ValidateOptions } from './x509/validate.js';
export { parseCrl, normalizeSerial, CRL_REASONS } from './x509/crl.js';
export type { Crl, CrlEntry } from './x509/crl.js';
export { checkRevocation, crlUrlsToFetch } from './x509/revocation.js';
export type { HeldCrl, RevocationOptions } from './x509/revocation.js';
export { verifyX509Signature } from './x509/signature.js';
export { checkTokenStatus, checkBitstringStatus } from './status/status.js';
export type { StatusContext, StatusListFetcher } from './status/status.js';
export { decodeJws, verifyJws, x5cFromHeader, toPublicKey } from './jose/jws.js';
export type { DecodedJws } from './jose/jws.js';
export { verifySignature, coseAlgToJose } from './crypto/verify.js';
export type { JoseAlg } from './crypto/verify.js';
export { publicKeyFromJwk, publicKeyToJwk, jwkThumbprint, jwkThumbprintBytes, publicJwk, CURVES } from './crypto/keys.js';
export type { Jwk, PublicKey } from './crypto/keys.js';
export { digest, sha256 } from './crypto/hash.js';
export { parseDid, findVerificationMethod, hasRelationship, didError } from './did/did.js';
export { verificationMethodPublicKey, verificationMethodJwk, samePublicKey, publicKeyFromMulticodec, decodeMultibase } from './did/keys.js';
export { base58Encode, base58Decode, writeVarint, MULTICODEC } from './did/multibase.js';
export { resolveDidLocally } from './did/resolver.js';
export { fetchIssuerMetadata, fetchAuthorizationServerMetadata, wellKnownInserted, verifySignedMetadata } from './metadata/issuer.js';
export type { RegistryMetadataPolicy, SignedMetadataCheck } from './metadata/issuer.js';
export { applyMetadataPolicy, MetadataPolicyError } from './metadata/policy.js';
export { ExpiringCache } from './cache/store.js';
export { CircuitBreaker } from './transport/circuit.js';
export { InsecureUrlError, isSecureUrl, requireSecureUrl, httpUrlHost, redirectAllowed } from './util/url.js';
export * as cbor from './encoding/cbor.js';
export * as bytes from './util/bytes.js';
