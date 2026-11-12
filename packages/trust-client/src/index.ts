/**
 * @vctrust/trust-client: the library a wallet or verifier consumes the trust service through.
 *
 * This entry is the supported surface: the client, its configuration, the decision types and the storage
 * interfaces. The parsers and cryptographic building blocks the client is made of are exported from
 * `@vctrust/trust-client/primitives`, without a stability promise.
 */
export { TrustClient, createTrustClient } from './client.js';
export type { TrustClientConfig, PinnedAnchor, Logger, LookupPolicy, LookupVia, SnapshotInfo, TrustStatus, ContextDocument,
  StatusCheckOptions, MinimumRules, TrustRules, TrustMechanism } from './client.js';
export * from './types.js';
export { TrustServiceError, TrustServiceUnavailableError, TrustIntegrityError } from './errors.js';
export { MemoryCacheStore, KeyValueCacheStore } from './cache/store.js';
export type { CacheStore, KeyValueStorage } from './cache/store.js';
export type { ServiceKeyPolicy } from './snapshot/snapshot.js';
export type { StatusResult, TokenStatusReference, ListCredentialVerifier } from './status/status.js';
export type { Jwk } from './crypto/keys.js';
