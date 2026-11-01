# @vctrust/trust-client

A TypeScript client for the VC Trust Service, for wallets and verifiers. It runs in Node 20+, browsers and React Native (Hermes).
There are no platform crypto dependencies: it uses noble curves/hashes plus built-in CBOR, DER and X.509 code.

## The service compiles, the client decides

By default (`decisions: 'local'`) every trust decision is made **on the device**:
- The service compiles a signed **trust snapshot** for this client (`GET /api/v1/snapshot`, `typ: trust-snapshot+jwt`). It contains:
  - the frameworks, entities and trust anchors the client's profile accepts;
  - the profile's evaluation policy;
  - the DID documents of registered DID identifiers;
  - the registry's metadata policies;
  - the trust anchors' current CRLs.
- The client verifies the snapshot with a pinned service key and evaluates locally, with the same rules as the service's `TrustEvaluator`. A parity test compares the two.
- In the default configuration, the service receives only snapshot (and JWKS) requests. It never learns which issuers a user receives credentials from, which verifiers they present to, or any certificate or credential data.

### Revocation
Every certificate below the trust anchor is checked against a CRL that its issuer signed:
- **Anchor CRLs** (for example an IACA's CRL, which covers its Document Signers) come in the snapshot. The service fetches them and refreshes them, but the device verifies each one again against the anchor: signature, issuer, `thisUpdate`/`nextUpdate`, and scope (issuing distribution point).
- **CRLs of CAs below an anchor** are fetched per `lookups.crl` and cached until their `nextUpdate`. Fetching is skipped for chains that don't reach an anchor.
- **Outcome**, recorded in `evidence.x509.revocation` with one entry per certificate:
  - `x509.not_revoked` (INFO);
  - `x509.revoked` or `x509.on_hold` (ERROR, so the decision is `NOT_TRUSTED`);
  - `x509.revocation_unknown`: a WARNING, or an ERROR when the client profile sets `requireRevocationStatus` (carried in the snapshot policy).
- **No OCSP on the device.** An OCSP request names the exact certificate being checked. A certificate that publishes only OCSP is reported as unknown. A verifier backend can enable OCSP on the service (`trust.revocation.ocsp`).
- **Credential status lists** are checked here, for wallets and verifiers alike:
  - `checkTokenStatus(ref, { form })`: IETF Token Status List, `statuslist+jwt` (SD-JWT VC) or `statuslist+cwt` (ISO mdoc MSO `status`). Checked: `typ`, signature, signer (the credential's signer, a certificate under the credential's anchor, or a trusted `status-list` provider), `sub`, `iat`, `exp`, `bits`.
  - `checkBitstringStatus(entry, { issuer, verifyListCredential })`: W3C Bitstring Status List; the list credential's proof (verified by the caller's JSON-LD verifier), issuer, purpose and validity.
  - Lists are fetched per `lookups.statusLists` and reused for their `ttl` (5 min without one, at most 1 h, never past expiry). A relay or cache can withhold a list, which leaves the status unknown, but cannot forge it.

```ts
import { createTrustClient, KeyValueCacheStore } from '@vctrust/trust-client';

const trust = createTrustClient({
  baseUrl: 'https://trust.example',       // omit to run on standards + local configuration only
  apiKey: process.env.TRUST_API_KEY,
  clientId: 'my-wallet',                  // expected audience of the snapshot
  serviceKeys: { thumbprints: ['WwQ91FCwRpJsBxzWtk3QaYTY62lIHT6WLd1Mox-3TL4'] },   // pin the service key (required)
  cache: new KeyValueCacheStore(localStorage),                                      // or AsyncStorage; persists the snapshot
  // decisions: 'local',                                    // default; 'service' for verifier backends / thin clients
  // lookups: { metadata: 'direct', did: 'direct', unknownParties: false },   // local-mode defaults
  // issuerMetadata: { signed: 'off' },                     // 'verify' | 'require': signed issuer metadata (OID4VCI §12.2.3)
  fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },   // optional app-pinned anchors
});
const { decision } = await trust.evaluateCredential(credential, 'mso_mdoc');   // decided on this device
```

### Snapshot lifecycle (local mode)
- **First decision without a usable snapshot:** waits for a download, bounded by `timeoutMs`.
- **Usable snapshot:** decisions never wait on the network. A refresh runs in the background once it is older than `snapshotRefreshMs` (1 h). After a failure it retries every `snapshotRetryMs` (30 s).
- **Integrity:**
  - Verified against `serviceKeys` (thumbprints, JWKs, or `trustOnFirstUse` for demos).
  - Bound to `clientId`.
  - Re-verified when loaded from storage.
  - An older snapshot (`iat`) never replaces a newer one, which prevents rollback. An already-expired snapshot is refused.
- **Past its expiry:** usable for `fallback.snapshotGraceMs` (7 days). Decisions then carry a `snapshot.stale` warning and a short `validUntil`. After that, decisions are `UNKNOWN`.
- **No snapshot and no pinned anchor:** decisions are `UNKNOWN` (source `fallback`), never `TRUSTED`.

### Lookups: what may tell the service about the user
| `lookups` | `'direct'` (local default) | `'service'` |
| --- | --- | --- |
| `metadata` | OpenID4VCI discovery at the issuer, with the snapshot's metadata policy applied | Metadata proxy (`/api/v1/issuers/metadata`) |
| `did` | Snapshot document first, then did:web / did:key / did:jwk on the device | Snapshot document first (local mode), then `/api/v1/did/{did}` |
| `unknownParties: true` | — | Parties absent from the snapshot are looked up on demand (OpenID Federation, EBSI). Only the identifier is sent. The signed answer is verified and evaluated on the device. |
| `crl` (also `'none'`) | CRLs not in the snapshot come from the CA's CRL distribution point (the CA learns only which CA's CRL is wanted) | Through the CRL relay (`/api/v1/revocation/crl`); direct while it is unreachable. Default in `service` mode. |
| `statusLists` | Status lists come from the issuer (default in both modes) | Through the status list relay (`/api/v1/revocation/status-list`): the issuer no longer sees the device, but the service sees which list is checked |

## API

| Method | `decisions: 'local'` (default) | `decisions: 'service'` |
| --- | --- | --- |
| `evaluate(query)` and `evaluateIssuer` / `evaluateVerifier` / `evaluateCredential` | Device-side evaluation over the snapshot (+ opt-in on-demand lookup) | `POST /api/v1/evaluate`; device-side while unreachable |
| `validateChain(x5c, domain)` | Local RFC 5280 validation with ISO 18013-5 / verifier profiles | `POST /api/v1/x509/validate`; local while unreachable |
| `issuers()`, `verifiers()`, `lookup()`, `frameworks()` | Snapshot contents | Registry API; snapshot while unreachable |
| `getIssuerMetadata(issuer)` | per `lookups.metadata` | per `lookups.metadata` (default proxy, direct while unreachable) |
| `resolveDid(didUrl)` | per `lookups.did` | per `lookups.did` |
| `syncSnapshot()`, `snapshotInfo()` | Download / describe the snapshot | Same |
| `checkTokenStatus(ref)`, `checkBitstringStatus(entry)` | Fetched per `lookups.statusLists`, verified on the device, cached for the list's `ttl` | Same |
| `fetchCrls(urls)`, `fetchStatusList(uri, accept)` | per `lookups.crl` / `lookups.statusLists`; the caller verifies what comes back | Same |

Every `TrustDecision` says who decided:
- `source`:
  - `trust-service`: the service decided.
  - `snapshot`: this device decided from the snapshot; `decision.snapshot` gives its version and age.
  - `fallback`: this device decided with app-pinned anchors only.
- `reasons`: includes `local.snapshot` (INFO) or, in service mode, `fallback.snapshot` (WARNING).
- In service mode, fallback happens only on `TrustServiceUnavailableError` (network failure, timeout, 5xx, open circuit). `TrustServiceError` (for example a 403 policy denial) and `TrustIntegrityError` (for example a bad snapshot signature) are thrown, never bypassed.

### Signed issuer metadata
`issuerMetadata.signed` (or a client profile with `requireSignedIssuerMetadata`, from the snapshot policy):
- `'verify'` asks issuers for `application/jwt` and uses signed metadata when served; `'require'` refuses issuers without it.
- The JWT must have `typ: openidvci-issuer-metadata+jwt`, an asymmetric `alg`, an `x5c` whose leaf is not self-signed and chains to a `credential-issuer` anchor, `sub` equal to the Credential Issuer, `iat`, and no past `exp`.
- Signed metadata that arrives through the service's proxy is verified again on the device; the registry's metadata policy is then applied locally.

### Client policy from the snapshot
| Policy | Effect on the device |
| --- | --- |
| `strictAuthorization` | entities without explicit authorizations are not authorized |
| `requireRevocationStatus` | an undeterminable certificate status is an error |
| `requireSignedIssuerMetadata` | unsigned issuer metadata is refused |
| `allowRelaxedProfiles` (default true) | anchors' `relaxProfile` turns certificate-profile errors into warnings; false enforces the profile |

## Verifier example: trust the issuer of a presented mdoc

```ts
import { createTrustClient } from '@vctrust/trust-client';
const trust = createTrustClient({ baseUrl, apiKey: 'demo-verifier-key', clientId: 'demo-verifier', serviceKeys });

// documents[i].issuerSigned from a DeviceResponse you have already signature-checked
const { decision } = await trust.evaluateCredential(issuerSignedB64, 'mso_mdoc');
if (decision.decision !== 'TRUSTED') reject(decision.summary, decision.reasons);

// DCQL trusted_authorities matching (aki / etsi_tl / openid_federation)
const r = await trust.evaluateCredential(sdJwt, 'dc+sd-jwt', { trustedAuthorities: [{ type: 'aki', values: [aki] }] });
const matched = r.decision.evidence?.trustedAuthorities?.some((m) => m.matched);

// The credential's status (MSO status.status_list), against the decision's anchor
const status = await trust.checkTokenStatus({ idx, uri }, { form: 'cwt', signerX5c: x5chain, decision });
if (status.status === 'revoked' || status.status === 'suspended') reject(status.detail);
```

Building blocks are exported for reuse:
- `LocalEvaluator`, `parseCertificate`, `validateCertificateChain`, `validateChainOnDevice`
- `parseCrl`, `checkRevocation`, `verifyX509Signature`
- `checkTokenStatus`, `checkBitstringStatus` (standalone, with your own fetcher)
- `fetchIssuerMetadata`, `verifySignedMetadata`
- `decodeJws`, `verifyJws`, `verifySignature`, `coseAlgToJose`
- `resolveDidLocally`, `verificationMethodPublicKey`
- `applyMetadataPolicy`
- the `cbor` codec

Tests: `npx vitest run` (66 tests). `npm run test:live` adds the parity test against a running trust service. It runs 29 queries, including revoked, on-hold and covered Document Signers and a relaxed sandbox anchor, under a lenient profile and a strict one (strict authorization, revocation status required, relaxed anchors refused), and compares `/evaluate` with the device for each.
