# VC Trust Service — Design

Nov 1, 2026 · Living version: https://claude.ai/artifact/RViVpaEWce3S8yctArPdvk

## Overview and goals

The VC Trust Service gives OpenID4VCI/OpenID4VP wallets and verifiers one place to ask "should I trust this party?" and to fetch the material they need to check it. That material is issuer lists and metadata, X.509 chains (mdoc IACA, SD-JWT VC issuers, verifier access certificates) and DID documents. It is a Java 21 / Spring Boot server plus a TypeScript client library. A demo React Native wallet exercises both against live public issuers.

**Problems it solves**

- Every wallet re-implements trust: it hard-codes IACA roots and issuer allowlists, and parses a different list format per ecosystem.
- Trust information is scattered across incompatible formats: ETSI TS 119 612 / 119 602 lists, ISO 18013-5 VICALs, OpenID Federation, EBSI TIR, plain PEM bundles and DID methods.
- Mobile wallets pay for repeated metadata and DID fetches. They also leak which issuers and verifiers the user talks to.

**Goals**

1. **Spec-agnostic core.** Ingest any trust-list format through adapters into one normalized model, and answer through one decision API, plus standard bindings such as ToIP TRQP and the Universal Resolver path.
2. **Proxy and cache.** Serve validated OID4VCI issuer metadata, X.509 path validation and DID resolution with caching, SSRF protection and signed responses.
3. **Per-client policy.** Each configured wallet or verifier sees only the frameworks and trust anchors its profile accepts.
4. **Fail-safe, private decisions.** Wallets decide trust on the device from a signed snapshot, so an outage only delays refreshes and the service never sees whom the user deals with. Standard mechanisms (direct `.well-known` fetches, local DID resolution, local path validation) cover what the snapshot does not. Nothing silently upgrades an unknown party to trusted.
5. **First-class formats.** W3C VCDM 2.0 JSON-LD (`ldp_vc`) and ISO mDL (`mso_mdoc`) are primary. SD-JWT VC and JWT VC are supported where needed.

**Non-goals**

- Issuing credentials. The demo uses public online issuers.
- Being a production wallet. The demo wallet is protocol-compliant but throwaway.
- Revocation-status hosting. The service resolves status where a source provides it, but runs no status lists of its own.

**Design principles**

- The service compiles, the client decides. The service turns every trust list into one signed, per-client trust snapshot; wallets evaluate trust on the device with the same rules, so the service never learns which issuers or verifiers a user deals with.
- Decisions carry evidence: chain, anchor, source list, framework and expiry. A client can show *why* a party is trusted, and who decided (the device, from which snapshot version, or the service).
- Three-valued outcome: `TRUSTED`, `NOT_TRUSTED`, `UNKNOWN`. Without a verified snapshot or a locally pinned anchor, nothing reaches `TRUSTED`.
- Pluggable everywhere: sources, DID drivers, certificate profiles, HTTP, crypto and storage.

## Standards landscape and compatibility

Every trust-list format enters through an adapter, and every protocol touchpoint maps onto one decision API. Versions are the ones in force on 2026-11-01.

| Standard | Version | Role in the service | Where |
| --- | --- | --- | --- |
| [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | 1.0 Final (Sep 2025) | Issuer metadata proxy: well-known insertion rule, `credential_issuer`/AS `issuer` checks, `oid4vci-discovery` source | Server, client, wallet |
| [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | 1.0 Final (Jul 2025) | Verifier trust: all client\_id prefixes; DCQL `trusted_authorities` (`aki`, `etsi_tl`, `openid_federation`) | Server, client, wallet |
| [HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) | 1.0 Final (Dec 2025) | Wallet profile: PAR, PKCE, DPoP nonces, wallet and key attestation, credential encryption, signed issuer metadata (`x5c`), `x509_hash` with enforced verifier trust, `direct_post.jwt`, minimal disclosure. Signed metadata can be required per client profile | Wallet, client, server |
| ISO/IEC 18013-5 | 1st ed. + VICAL | IACA trust domain, Document Signer profile (EKU 1.0.18013.5.1.2, country match), `vical` source | Server, client |
| W3C VCDM 2.0 + Data Integrity | REC | JSON-LD credential verification; issuer DID trust | Wallet, client |
| SD-JWT VC | draft-13 (HAIP pin) | `x5c` issuer chains (`credential-issuer` domain) | Server, client |
| W3C DID Resolution | CR Draft (Oct 2026) | Proxy and Universal-Resolver-compatible API; did:web, did:key, did:jwk native; RFC 9457 error types | Server, client |
| [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) | 1.0 Final (Feb 2026) | `openid-federation` source: chain validation, metadata policy, trust marks, on-demand resolution | Server |
| ETSI TS 119 612 | v2.4.1 | `etsi-tl` source: EU LOTL and national TLs, XMLDSig/XAdES signer check | Server |
| ETSI TS 119 602 (LoTE) | v1.1.1 | `etsi-lote` source: PID, wallet, WRPAC, WRPRC and Pub-EAA lists, JAdES signer check | Server |
| EBSI TIR | v5 | `ebsi-tir` source: crawl or on-demand by DID; accreditation types become authorizations | Server |
| [ToIP TRQP](https://trustoverip.github.io/tswg-trust-registry-protocol/approved/) | v2.0 approved | Standard query binding: `POST /trqp/authorization`, `/trqp/recognition` | Server |

Two live ecosystems shape the defaults. **Animo's playground** (Credo) is fully OpenID4VCI 1.0 / HAIP shaped and anchors mdoc trust in a published root. **MOSIP collab (Inji Certify)** issues VCDM 2.0 JSON-LD with `Ed25519Signature2020`. Its deviations are handled explicitly rather than papered over:

- the signing key's DID differs from the `issuer` DID;
- `assertionMethod` lists the bare DID;
- the mDL is non-ISO (non-standard wrapping, no DS EKU). It is trusted only through a `relaxProfile` anchor, and only by client profiles that allow relaxed anchors;
- the Land credential's signature does not verify, so wallets refuse it.

Draft defect reports for MOSIP are in `docs/upstream-reports.md` in the repository.

## System architecture

![Architecture: the service compiles a signed trust snapshot; wallets decide trust on the device](architecture.png)

The service ingests trust lists and compiles a signed snapshot per client. Wallets embed the client library, decide trust on the device from that snapshot, and talk to issuers and verifiers directly. Verifier backends and thin clients can ask the service instead (`/evaluate`, metadata and DID proxies), which then fetches live data on their behalf.

**Request flows**

1. **Stay current.** The client downloads its signed trust snapshot (`GET /api/v1/snapshot`, conditional), verifies it (pinned service key, audience, expiry, never older than the one held) and refreshes it in the background. This is the only call a wallet makes to the service by default.
2. **Receive a credential.** The wallet fetches issuer metadata from the issuer itself, with the registry's metadata policy from the snapshot applied, and runs OpenID4VCI. It verifies each credential and decides issuer trust on the device: x5c chain to a snapshot anchor, DID key against the snapshot's DID document, registry entry and authorizations.
3. **Present.** The wallet verifies the request object signature and `client_id` binding, then decides on the device whether the verifier is trusted (x5c chain to a verifier-access CA, registry entry, `response_uri` rule). It shows the decision before the user consents.
4. **Outage.** Decisions do not change; only the snapshot refresh fails. A snapshot past its expiry is used for up to 7 days with a warning; with no snapshot, decisions are `UNKNOWN`.
5. **Service mode.** Verifier backends and thin clients can let the service decide (`/evaluate`, metadata and DID proxies); the device then decides only while the service is unreachable.

**Deployment.** The server is one stateless jar plus a small database (H2 by default, PostgreSQL mode) holding admin-managed entries. Replicas share nothing but configuration; each loads sources independently. The demo runs everything on one laptop, against the public Animo and MOSIP sandboxes.

## Normalized trust model

All sources reduce to two record types, **trusted entities** and **trust anchors**, grouped by framework and served to clients through per-client profiles. Everything else is evidence.

| Concept | What it holds | Notes |
| --- | --- | --- |
| `TrustFramework` | id, name, governance URI | One per ecosystem, e.g. `animo-playground`, `mosip-collab`, `eu-lotl` |
| `TrustedEntity` | id, framework, roles, identifiers, display, authorizations, status, validity, certificates, metadata, metadata policy, provenance | Entities sharing an id across sources are merged; the most restrictive status wins |
| `EntityRole` | `CREDENTIAL_ISSUER`, `VERIFIER`, `WALLET_PROVIDER`, `AUTHORIZATION_SERVER`, `ACCREDITATION_AUTHORITY`, `STATUS_LIST_PROVIDER` | Protocol neutral |
| `Identifier` | typed, normalized value: `DID`, `URL`, `CLIENT_ID`, `DNS`, `X509_SHA256`, `X509_SKI`, `X509_SUBJECT`, `JWK_THUMBPRINT`, `FEDERATION_ENTITY` | Indexed for O(1) lookup |
| `CredentialAuthorization` | format + type (doctype, vct or VC type) | What an issuer may issue or a verifier may request |
| `TrustAnchor` | X.509 certificate in a `TrustDomain`, optional entity link, constraints (`docTypes`, `serviceType`, `trustedListUri`) | Validating a chain to an anchor identifies the entity |
| `TrustDomain` | `mdoc-iaca`, `credential-issuer`, `verifier-access`, `wallet-provider`, `status-list`, `list-signer`, ... | Purpose isolation, each with its own certificate profile |
| `ClientProfile` | accepted frameworks, strict authorization, metadata-proxy openness, `requireRevocationStatus`, `requireSignedIssuerMetadata`, `allowRelaxedProfiles` | Each configured wallet or verifier sees only its frameworks; the policy travels in its snapshot so the device applies it too |
| `Provenance` | source id and type, list URI, retrieval time | Carried into every decision |

**Metadata policy.** The OpenID Federation operators (`value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, `essential`) are the one way to curate metadata. Federation chains use them, and so can a registry entry. For example, it can declare the pre-authorized token endpoint an issuer forgets to advertise.

**Registry snapshots.** Sources load independently on their own refresh interval or the list's `nextUpdate`. A failing source keeps its last good result. Every load publishes a new immutable, fully indexed snapshot; lookups never see a partial registry, and the snapshot version doubles as the HTTP ETag.

**Decision semantics.** A query is `role + subject + context`:

- **Subject:** identifier, `x5c`, JWK and/or kid.
- **Context:** protocol, format, type, `response_uri`, `trusted_authorities`.

Each supplied element is checked independently:

- **Contradicting evidence gives `NOT_TRUSTED`:** an invalid chain, a revoked entity, an unauthorized type (every type a W3C VC asserts must be authorized), a key missing from the DID document, an `x509_hash` mismatch, or an identifier that names a registered entity the presented key is not bound to (`identifier.unbound`).
- **Otherwise, a registry match or a validated anchor gives `TRUSTED`.**
- **Otherwise the result is `UNKNOWN`.**

**Identifiers are bound to keys.** An identifier in a query (a `client_id`, `iss`, an issuer DID) is a claim made by whoever presents it. When the query carries key material, only identifiers proven by that key find the entity:

- the DID of a DID `kid`;
- a JWK thumbprint;
- the leaf certificate's hash (a pinned certificate);
- once the chain validates to an anchor: the leaf's subject, SKI and SAN names, and the anchor's entity.

The claimed identifier counts only when the key also matches that entity, or when the validated anchor is not tied to one entity and belongs to the identified entity's framework. A shared IACA, such as Animo's, vouches for the issuers of its framework this way.

Without key material, the identifier is a registry lookup. Issuer metadata uses this, as does a key the caller fetched from the identifier itself, such as `jwt-vc-issuer`.

A self-signed certificate claiming a registered DNS name, or a foreign DID key claiming a registered DID, is therefore `NOT_TRUSTED`, never `TRUSTED`.

## Server design (Java 21, Spring Boot 4.1)

The server is three Maven modules with a strict dependency direction: `trust-core` (no Spring) ← `trust-adapters` ← `trust-server`. Core and adapters can be embedded in other JVM services.

| Module | Responsibility | Key types |
| --- | --- | --- |
| `trust-core` | Domain model, SPIs, evaluation engine, X.509, DID, metadata | `TrustEvaluator`, `X509PathValidator`, `CertificateProfiles`, `DidResolver`, `IssuerMetadataResolver`, `MetadataPolicy`, `TrustSourceManager`, `RegistrySnapshot` |
| `trust-adapters` | One adapter per list format, discovered via `ServiceLoader` | `static`, `x509-bundle`, `oid4vci-discovery`, `etsi-tl`, `etsi-lote`, `vical`, `openid-federation`, `ebsi-tir` |
| `trust-server` | HTTP API, client authentication, rate limits, caching, signing, SSRF-safe fetching, managed (JDBC) source | controllers, `ClientAuthenticator`, `AccessTokenVerifier`, `SafeHttpFetcher`, `TtlCache`, `ServiceKeyManager`, `SigningKeySource`, `ManagedSourceFactory` |

**Extension points (SPIs)**

- `TrustSourceFactory` / `TrustSource`: a new list format is one class plus a `META-INF/services` line. Sources return entities, anchors and `ListInfo` (sequence, `nextUpdate`, signature status).
- `OnDemandResolver`: optional, for registries too large to enumerate (OpenID Federation bottom-up chain resolution, EBSI lookup by DID).
- `DidMethodDriver`: did:key, did:jwk and did:web are native. A generic `http-registry` driver takes a URL template (EBSI is configured this way). A Universal Resolver driver covers the rest.
- `CertificateProfile`: purpose checks on top of RFC 5280 PKIX (ISO 18013-5 Document Signer, credential issuer, verifier access). Anchors can carry `relaxProfile` for known-deviant sandboxes, which turns errors into visible warnings. A client profile with `allow-relaxed-profiles: false` ignores it, so a strict verifier refuses what a demo wallet shows with warnings.
- `HttpFetcher` / `ResourceLoader`: all I/O goes through these, so adapters never open sockets.

**Evaluation pipeline** (`TrustEvaluator`):

1. Derive identifiers. This parses OpenID4VP client\_id prefixes and DIDs from kid, and computes JWK and certificate thumbprints.
2. Validate the chain against the role/format trust domain, filtered to the client's frameworks.
3. Match the registry; validated SAN names count only after the chain validates.
4. Fall back to on-demand sources.
5. Run DID document checks (verification method present, relationship).
6. Check status, validity and authorization.
7. Apply the OpenID4VP `response_uri` host rule, then DCQL `trusted_authorities` matching.
8. Combine into `TRUSTED`, `NOT_TRUSTED` or `UNKNOWN` with reasons and evidence.

**Operational qualities**

- *Caching:* a TTL cache honours upstream `max-age`, collapses concurrent loads, caches negative DID results for 1 minute and serves stale data for up to 24 hours when an upstream is down. Registry changes invalidate curated metadata.
- *SSRF:* https only, except allow-listed dev hosts and CRL and OCSP fetches (signed objects, published over http). Private, loopback, link-local, CGNAT and ULA targets (also inside NAT64 and 6to4 addresses) are refused. Each host is resolved once per connection and the socket connects only to the addresses that passed, so DNS rebinding has no window. Redirects are re-validated hop by hop; bodies are capped at 8 MiB and a total deadline stops slow bodies. Proxy settings and cookies are ignored.
- *Hardened parsing:* XML forbids DOCTYPE and entities. XMLDSig uses secure validation. JWS and COSE algorithms are explicit.
- *Integrity:* an ES256 service key (JWKS published, thumbprints in discovery) signs snapshots and, on `Accept: application/jwt`, any response. Signed output is audience-bound to the client. The key comes from a JWK file, a PKCS#12/JKS keystore or a PKCS#11 HSM (the key never leaves the token). Previous keys stay in the JWKS during rotation, and discovery lists every thumbprint clients may pin.
- *Request paths:* authentication applies to every path but the public ones (`/.well-known/**`, health, OpenAPI). The filter judges the path the way Spring MVC routes it: decoded, without `;` parameters, within the application. Spellings that decoders could disagree on are refused with `400`: `;`, encoded `/`, `\\` and `.`, `.` or `..` segments, and doubled slashes. `X-Forwarded-*` headers are not trusted (`forward-headers-strategy: none`). Client addresses for rate limiting come from the TCP peer, or from `X-Forwarded-For` only when the peer is a configured trusted proxy.
- *Client authentication:* API keys (stored as SHA-256 if wanted), OAuth 2.0 JWT access tokens (RFC 9068, client from `client_id`/`azp`, required scope), and mTLS client certificates (from the TLS connector, or a proxy header believed only from trusted proxy addresses), including certificate-bound tokens (RFC 8705). Per-client token-bucket rate limits answer `429` with `Retry-After`.
- *Availability:* sources load off the startup thread, and `/actuator/health` reports per-source state. A failing source keeps serving its last good data.

Test coverage: 112 tests (core 53, adapters 16, server 43). They use generated PKIs, a signed federation and VICAL, an XMLDSig-signed TL, a JAdES LoTE and the live EU LOTL as a fixture.

## Server API

All endpoints are discoverable from `/.well-known/trust-service`, which also lists the accepted authentication methods. Clients authenticate with an API key, an OAuth 2.0 access token or a TLS client certificate, and the credential selects a client profile; anonymous access is configurable. Errors are RFC 9457 problem details with a stable `code`. Registry reads carry ETags (`304` on `If-None-Match`). Any JSON endpoint returns a service-signed JWT on `Accept: application/jwt`.

| Method and path | Purpose | Notes |
| --- | --- | --- |
| `GET /.well-known/trust-service`, `/.well-known/jwks.json` | Discovery, service keys | Thumbprint for pinning |
| `GET /api/v1/frameworks` | Accepted frameworks with counts |  |
| `GET /api/v1/issuers`, `/verifiers`, `/entities` | Paged lists; filter by `framework`, `format`, `type`, `q` | `format=mso_mdoc&type=org.iso.18013.5.1.mDL` |
| `GET /api/v1/entities/lookup?identifier=` | Find entities by URL, DID or client\_id |  |
| `GET /api/v1/entities/{id}` | Entity, metadata, policy, linked anchors |  |
| `GET /api/v1/issuers/metadata?credential_issuer=` | OpenID4VCI metadata proxy | Validated, policy-curated, cached; trust decision embedded; `X-Trust-Decision` header |
| `POST /api/v1/evaluate`, `/evaluate/batch` | Trust decision for any role, subject and context | Batch max 50 |
| `POST /api/v1/x509/validate` | Chain validation in a trust domain | Optional `docType`, `expectedDnsName` |
| `GET /api/v1/x509/anchors?domain=&format=pem` | Anchor export | JSON or PEM bundle |
| `GET /api/v1/did/{did}` | W3C DID resolution result | Raw-path parsing keeps `%3A`; cache info in metadata |
| `GET /1.0/identifiers/{did}` | Universal Resolver / DID Resolution HTTP binding | `Accept` picks result or document; spec status codes |
| `GET /api/v1/snapshot` | Signed per-client trust snapshot (`trust-snapshot+jwt`): frameworks, entities, anchors with provenance, client policy, DID documents, metadata policies, the anchors' CRLs; re-signed after half its TTL. The only call a wallet makes by default; `GET /api/v1/entities/lookup?onDemand=true` (signed) serves opt-in lookups of unlisted parties | Per-client scope, ETag, 24 h TTL |
| `GET /api/v1/revocation/crl?url=`, `/revocation/status-list?uri=`, `/revocation/crls` | CRL relay and status list relay; the anchor CRLs the service holds | Opt-in on the client. Signed objects pass through unchanged and are cached briefly; fetches are SSRF-guarded and size-capped |
| `POST /trqp/authorization`, `/trqp/recognition` | ToIP TRQP v2.0 | `authority_id` names a framework; `resource` may be `format:type` |
| `/admin/v1/sources`, `/sources/{id}/refresh`, `/registry`, `/managed/{entities,anchors}/{id}`, `/cache/clear` | Operator API | Admin client only |

A decision response looks like this, abridged:

```json
{"decision":"TRUSTED","summary":"Trusted credential issuer 'MOSIP Land Registry (collab)' in framework 'mosip-collab'",
 "reasons":[{"code":"did.relationship_lenient","severity":"WARNING"}],
 "entity":{"id":"mosip-land","frameworkId":"mosip-collab","roles":["CREDENTIAL_ISSUER"]},
 "evidence":{"x509":null,"did":{"did":"did:web:inji.github.io:...","verificationMethodFound":true,"relationshipValid":true},
             "authorization":{"format":"ldp_vc","type":"LandStatementCredential","authorized":true}},
 "validUntil":"...","source":"trust-service"}
```

## Client library (TypeScript)

`@vctrust/trust-client` gives wallets and verifiers one API, `TrustClient`, in two decision modes. In `local` mode (the default, for wallets) every decision is made on the device from the signed snapshot, by a local evaluator with the server's rules; the service only distributes the snapshot. In `service` mode (verifier backends, thin clients) the service decides and the device takes over only while it is unreachable. The library has no Node-only dependencies (noble crypto plus its own CBOR, DER and X.509 code), so the same build runs in Node, browsers and React Native/Hermes.

| Layer | Responsibility |
| --- | --- |
| `TrustClient` facade | `evaluate`, `evaluateIssuer`, `evaluateVerifier`, `evaluateCredential`, `getIssuerMetadata`, `resolveDid`, `validateChain`, `checkTokenStatus`, `checkBitstringStatus`, `issuers`, `verifiers`, `lookup`, `syncSnapshot`, `snapshotInfo`, `status` events; `decisions: 'local' \| 'service'` |
| Snapshot manager | Fetches `trust-snapshot+jwt` (conditional GET, one request shared by concurrent callers), verifies it against service keys pinned by RFC 7638 thumbprint (TOFU optional), checks audience and expiry, refuses rollback to an older `iat`, persists it and re-verifies on load; usable 7 days past expiry with a warning |
| Local evaluator | The server's `TrustEvaluator` rules over the snapshot (client policy, anchors with provenance, entities, DID documents, anchor CRLs) plus app-bundled anchors and entities; kept equal to the server by a live parity test |
| Lookups | What may disclose a counterparty, opt-in per kind: issuer metadata and DIDs `direct` (default) or via the service; on-demand registry lookups of unlisted parties (signed, identifier only) |
| Standards mechanisms | OpenID4VCI 1.0 discovery (insertion rule, `credential_issuer` and AS `issuer` checks, registry metadata policy applied, signed metadata verified on the device even when proxied); did:key, did:jwk and did:web; RFC 5280 path validation with the same profiles (EC, Ed25519, RSA PKCS#1 and PSS); CRLs |
| Credential status | Token Status List (JWT and CWT) and Bitstring Status List checks shared by wallets and verifiers: the list's signature, signer, subject and freshness; verified lists reused for their `ttl` |
| Transport | Timeouts, retries with jittered backoff (idempotent calls only), a circuit breaker, RFC 9457 errors, online/offline status |
| Cache | Pluggable `CacheStore` (memory, or a localStorage/AsyncStorage adapter): the snapshot, pinned keys, metadata and DID documents |
| Credential helpers | Issuer material per format: mdoc IssuerSigned (including MOSIP's wrapper), SD-JWT VC, JWT VC, JSON-LD VC |

**Who decides, and failure handling**

- Every decision carries `source`: `trust-service`, `snapshot` (this device, from the verified snapshot, with its version in `decision.snapshot`) or `fallback` (this device, app-pinned anchors only). Only a verified snapshot or a pinned anchor can make a decision `TRUSTED`; otherwise it is `UNKNOWN`.
- Local mode: the first decision without a usable snapshot waits for one (bounded by the timeout); afterwards decisions never wait on the network and the snapshot refreshes in the background (hourly, 30 s retries).
- Service mode: only `TrustServiceUnavailableError` (network failure, timeout, 5xx, open circuit) triggers device-side evaluation. Policy answers such as a `403` for an unregistered issuer are never bypassed.
- Integrity failures throw: a bad snapshot signature, a wrong audience or an expired snapshot from the service is never silently accepted, and never replaces the snapshot held.

```ts
const trust = createTrustClient({
  baseUrl: 'https://trust.example', apiKey, clientId: 'demo-wallet',
  serviceKeys: { thumbprints: ['WwQ91FCw...'] },        // required: snapshots are accepted only from this key
  cache: new KeyValueCacheStore(AsyncStorage),          // persists the snapshot across restarts
  // decisions: 'local' (default) | 'service'
  // lookups: { metadata: 'direct', did: 'direct', unknownParties: false }
  fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },
});
const { decision } = await trust.evaluateCredential(mdocB64, 'mso_mdoc', { credentialIssuer });   // decided on the device
```

Test coverage: 83 unit tests (real MOSIP and Animo artefacts, generated EC and RSA PKI, Node-generated JWS/EdDSA/RSA-PSS, RFC 7638 vector, both decision modes: snapshot-only traffic, rollback and expiry, strict policy, snapshot DID documents with key rotation, metadata policy, signed metadata, signed on-demand lookups, CRL parsing and revocation rules, CRL sources and relays, status lists and their caching, key binding of identifiers, and the hardening regressions: malformed DER, decompression and body caps, service-key un-pinning, CRL and DID cache rules). A live parity test runs 33 queries under a lenient and a strict client profile through `/evaluate` and on the device, and requires identical decisions, error reasons, entities and revocation status.

## Revocation and credential status

Two kinds of revocation reach a wallet:

- a CA revokes a certificate in an issuer's or verifier's chain;
- an issuer revokes or suspends a credential.

Both are checked on the device, against data whose signature the device verifies itself. So a relay or a cache can delay revocation information, but it cannot forge it.

**Certificates: CRLs.** Every certificate below the trust anchor is looked up in a CRL that its issuer signed.

- **Anchor CRLs come from the service.**
  - Each anchor's CRL is fetched from one of three places:
    - the anchor's `crlUrls`;
    - a CRL pushed through the admin API;
    - for a self-issued anchor, its own CRL distribution point. Animo's IACA publishes [one](https://playground.animo.id/crl).
  - The service verifies each CRL against its anchor and refreshes it before `nextUpdate`.
  - Current anchor CRLs ship in the snapshot (`crls`). An IACA's complete CRL covers all of its Document Signers, so checking an mDL needs no extra request.
- **The device verifies every CRL again:**
  - signed by the issuing CA, and the issuer name matches;
  - the CA's key usage includes `cRLSign`;
  - within `thisUpdate` and `nextUpdate`;
  - in scope per the issuing distribution point;
  - not a delta CRL and not an indirect CRL.
- **CRLs of CAs below an anchor** are fetched per `lookups.crl`: from the CA (the default), through the service's CRL relay, or not at all. A chain that does not reach an anchor never triggers a download.
- **Each certificate's result** is in `evidence.x509.revocation`, with one of four reasons:
  - `x509.not_revoked`;
  - `x509.revoked`;
  - `x509.on_hold`;
  - `x509.revocation_unknown`: a warning, or an error when the client profile sets `requireRevocationStatus` (carried in the snapshot policy).

**Why not OCSP.** An OCSP request names the exact certificate being checked, which tells the responder who is presenting what.

- Devices never use OCSP. A certificate that publishes only OCSP gets the status *unknown*.
- Verifier backends that let the service decide can turn on `trust.revocation.ocsp`. The service then checks signed responses, accepts delegated responders, and caches answers until `nextUpdate`.

**Credential status.** The checks live in the client library (`checkTokenStatus`, `checkBitstringStatus`), so verifiers get them as well as wallets. A verified list is reused for its `ttl`: 5 minutes when it states none, at most 1 hour, never past its expiry. Only the list URI leaves the device, never the index.

| Format | Mechanism | Verified on the device |
| --- | --- | --- |
| SD-JWT VC | IETF Token Status List, `statuslist+jwt` | `typ`, signature and signer, `sub` = the referenced URI, `iat`, `exp`, the 1, 2, 4 or 8-bit value |
| ISO mdoc | MSO `status.status_list`, which references a Token Status List as `statuslist+cwt` (COSE_Sign1) | The same checks, plus the `certificate` the MSO names |
| W3C VCDM 2.0 | Bitstring Status List credential | The list credential's Data Integrity proof, same issuer, status purpose, validity |

A status list may be signed by one of:

- the credential's own signer (by certificate, or by the same key when the list carries no certificate);
- a certificate under the same trust anchor;
- a trusted status list provider.

**Relays.** These are opt-in.

- With `lookups.statusLists: 'service'`, status lists come through `/api/v1/revocation/status-list`. The issuer no longer sees the wallet's address or timing; the service sees which list was checked.
- `lookups.crl: 'service'` does the same for CRLs, through `/api/v1/revocation/crl`.
- Relayed bytes pass through unchanged and are cached briefly. The device verifies them exactly as if it had fetched them directly.

**Live findings.**

- The Animo playground's Document Signer validates as *not revoked* against Animo's real IACA CRL, taken from the snapshot.
- MOSIP's Land status list credential is signed with a key that is missing from its DID document, so its status is reported as unknown instead of trusted.

## Demo wallet

The wallet is a throwaway Expo app over `@vctrust/wallet-core`, a platform-neutral holder library. All protocol logic and verification live in wallet-core and are tested against live issuers and verifiers. The app is only UI.

| Area | Implemented (spec) |
| --- | --- |
| Issuance flows | Pre-authorized code with `tx_code`; authorization code with PKCE S256, PAR when offered (FAPI2: only `client_id` + `request_uri` at `/authorize`), RFC 9207 `iss` check; wallet-initiated issuance (OID4VCI 1.0) |
| HAIP issuance | DPoP (RFC 9449) with per-server nonces and `use_dpop_nonce` retries at AS and issuer; wallet attestation (ABCA-07, -12 compatible) at every endpoint whose AS supports it, with a separate instance key per authorization server (no cross-issuer correlation), the challenge endpoint, `OAuth-Client-Attestation-Challenge` and `use_attestation_challenge` / `use_fresh_attestation` retries; key attestation (`key-attestation+jwt`), with a precheck that refuses when the issuer demands stronger key storage than the wallet attests; `locations` in `authorization_details` |
| Credential request | Nonce endpoint and `invalid_nonce` retry; `credential_identifier` vs `credential_configuration_id`; `proofs.jwt` (ES256 checked against the issuer's algorithms) or `proofs.attestation` when the issuer accepts only key attestations; request and response encryption (JWE ECDH-ES P-256, A128GCM/A256GCM) when the issuer requires it, also at the deferred endpoint; holder binding by `jwk`/`cose_key`, `did:jwk` or `did:key`; deferred issuance, waited for briefly and otherwise stored as pending with what is needed to ask again later (§9) |
| Batch issuance | Up to the issuer's `batch_size` instances in one request (HAIP §4), each bound to its own key: one `jwt` proof per key, or one key attestation listing every key (HAIP §4.5.1); the response is paired with the keys by the bound key, not by position; every instance is verified and one bad instance refuses the batch; presentations take the least-presented instance, so each verifier sees a fresh one until the batch is used up (OID4VCI §15.4), and the app warns before reusing one |
| Acceptance | A credential that fails verification, or an SD-JWT VC whose `x5c` issuer is not trusted, is refused and the issuer is notified (`credential_failure`); `credential_accepted` is sent only once stored, `credential_deleted` when the user discards it |
| Verification: mdoc | COSE\_Sign1 with the DS key; every IssuerSignedItem digest; `validityInfo`; docType; `deviceKey` = holder key; DS chain to IACA via the trust client. Non-standard encodings become explicit warnings |
| Verification: VCDM 2.0 JSON-LD | `Ed25519Signature2020`, `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` over RDFC-1.0 with bundled contexts; safe mode (undefined terms are reported as unsigned); issuer key control, including key equivalence across DIDs; `assertionMethod`; validity; holder `did:jwk`; Bitstring Status List |
| Verification: SD-JWT VC | `typ` `dc+sd-jwt`; x5c, DID kid or `jwt-vc-issuer` key resolution; disclosure digests and rejection of unreferenced disclosures; `cnf`; Token Status List |
| Presentation (OID4VP 1.0 / HAIP) | `request_uri` (GET, or POST with `wallet_metadata` and `wallet_nonce`) with `client_id` required alongside; JAR `typ`, signature, `exp`/`nbf`; `x509_hash`, `x509_san_dns`, `decentralized_identifier`, `redirect_uri`; verifier trust enforced (an `x509_*` verifier must be TRUSTED, a NOT\_TRUSTED one is always refused); DCQL (`credential_sets`, `claim_sets` per candidate, `values`, `trusted_authorities`, holder binding required by default); minimal disclosure by claim path (nothing selectively disclosable when no claims are requested); SD-JWT+KB; mdoc DeviceResponse with OpenID4VPHandover; ldp\_vp; `direct_post` and `direct_post.jwt` (ECDH-ES to a JWK with `alg`, A128GCM/A256GCM); `invalid_request` / `invalid_transaction_data` returned to an authenticated verifier once the user has seen the error |
| Display | Issuer, credential and verifier logos as PNG or SVG, from https or `data:` URIs (react-native-svg on devices) |

**Use of the client library.**

- Issuer metadata always comes through `trust.getIssuerMetadata`: fetched from the issuer with the registry's metadata policy applied (through the proxy only in service mode), with the trust decision attached.
- DID documents (JSON-LD verification methods, SD-JWT DID kids) go through `trust.resolveDid`.
- Each received credential's issuer is evaluated on the device with its x5c, kid and type.
- Verifiers are evaluated with client\_id, x5c and `response_uri`.

The app shows the decision and its source next to every credential and request.

**Issuer quirks are configuration, not code.** MOSIP collab needs a pre-registered client and Mimoto's token proxy. Those are expressed as an `IssuerClientRegistration` (client\_id, redirect\_uri, token endpoint override).

## Security considerations

The service is a policy decision point that wallets act on, so its answers must be authentic, scoped, and never fail open.

| Threat | Mitigation |
| --- | --- |
| Forged or replayed trust answers | Snapshots and opt-in responses are ES256 JWTs from the service key, audience-bound to the client. Clients pin the key by RFC 7638 thumbprint, re-verify the stored snapshot on load, and never replace it with an older (`iat`) or expired one; TLS in transit |
| Fallback that fails open | Only a verified snapshot or a pinned anchor yields `TRUSTED`; otherwise `UNKNOWN`. In service mode the device takes over only on unavailability, never on policy errors. Every decision carries `source` and its snapshot version |
| Device and service decide differently | One rule set in two implementations, held equal by a live parity test (33 queries under a lenient and a strict profile: same decision, error reasons, entity and revocation status). The snapshot carries the client policy so both apply the same profile |
| Impersonation by claimed identifiers | Entities are found only through identifiers the presented key proves (see *Identifiers are bound to keys*); a claimed identifier of another registered entity is `NOT_TRUSTED`. Pinned certificates match only as the leaf, never as extra certificates appended to a chain |
| Unauthenticated access through path tricks | Paths are judged as the router sees them, and ambiguous spellings are refused; forwarded headers are not trusted unless they come from configured proxies |
| Tampered or stale trust lists | XMLDSig/XAdES (ETSI TL), JAdES (LoTE), COSE (VICAL) and federation chains are verified against pinned anchors. Expired LoTEs are rejected; `nextUpdate` drives refresh; a failing source keeps its last good data and the failure shows in health |
| SSRF through the metadata or DID proxy | https only; private, loopback, link-local, CGNAT and ULA targets refused; each host resolved once per connection and connected only at vetted addresses (no DNS-rebinding window), re-checked per redirect hop; 8 MiB cap; timeouts and a total deadline; strict clients can forbid proxying unregistered issuers |
| Stolen or guessed API credentials | OAuth 2.0 access tokens and mTLS for production, certificate-bound tokens, hashed API keys in configuration, per-client rate limits; the admin API needs an admin client |
| Service signing key compromise | Key in a PKCS#11 HSM or a keystore; rotation keeps previous keys in the JWKS while clients move their pinned thumbprints; a key whose thumbprint is removed from the client configuration is no longer trusted, even if it was stored earlier |
| Cross-purpose trust | Anchors are partitioned by trust domain (IACA, credential issuer, verifier access, wallet provider, status list), each with its own certificate profile |
| Malicious XML / CBOR / JSON / DER, oversized or slow bodies | DOCTYPE and external entities disabled, XMLDSig secure validation; DER lengths bounds-checked (no wrap to negative); response bodies capped (8 MiB service, 10 MiB device) under a deadline that covers the body; status lists inflated with a 16 MiB cap; explicit algorithm allow-lists (no `alg: none`) |
| Verifier impersonation | JAR `typ`, signature and expiry checks, `x509_hash` / SAN binding, `response_uri` host rule for `x509_san_dns`, `client_id` equality between query and request object; the wallet refuses to present unless the `x509_*` verifier chains to a trusted verifier-access CA |
| Spoofed issuer metadata | TLS, plus signed metadata where an ecosystem requires it: `x5c` chain to one of the client's credential-issuer anchors, a signer that is not self-signed and is bound to the issuer by SAN, `sub` and `credential_issuer`, `iat`, `exp`. Verified on the device even when it comes through the proxy, and the authorization servers are then taken from the signed metadata |
| Over-disclosure | Only the claims on the requested DCQL paths are disclosed; credentials without holder binding are offered only when the verifier allows it |
| Sandbox deviations leaking into production decisions | `relaxProfile` anchors downgrade profile errors to warnings only for client profiles that allow it; strict verifiers see the errors |
| Credentials borrowing trust | The issuer query uses the identifier inside the credential (`iss`/`issuer`), not the endpoint that delivered it; for JSON-LD the issuer must control the signing key |
| Context substitution (JSON-LD) | Standard contexts are bundled; remote fetches are https-only and flagged; safe-mode canonicalization flags terms not covered by the signature |
| Privacy | Wallets decide on the device: by default the service sees only snapshot and JWKS requests, never issuers, verifiers, certificates or credentials (asserted by a live test). Metadata and DID lookups go to the party directly; through the service (opt-in) the proxy hides wallet IPs instead. The server logs no credential contents |
| Revoked issuer, Document Signer or verifier certificate | Every certificate below the anchor is checked against a CRL, with the same rules on the device and in the service. Anchor CRLs ship in the snapshot and are verified again on the device. `requireRevocationStatus` makes an unknown status not trusted |
| Revocation checks revealing who presents what | No OCSP on the device. Anchor CRLs arrive with the snapshot, and other CRLs are per CA. Status lists come from the issuer by default; the relay is opt-in |
| Tampered relay, cache or status list | CRLs are verified against the issuing CA before the device caches them. Cached DID documents stand in only for transient failures, for 24 hours at most, and never once the DID answers 404 or 410. Status lists are checked for signature, signer, subject and expiry; Bitstring lists also for the list credential's proof and issuer. A relay can withhold data, which leaves the status unknown, but it cannot forge it |

The demo authenticates clients with API keys and signs with a JWK file. Production configuration switches on OAuth access tokens or mTLS and rate limits, and moves the signing key into a PKCS#11 HSM; the configuration reference shows both.

## Testing strategy and results

Testing runs in three layers.

1. **Deterministic suites:** 112 Java, 83 trust-client and 41 wallet-core tests. They use generated PKIs, signed fixtures, spec test vectors, real artefacts and an in-memory HAIP issuer for the issuance details no live issuer exercises (credential encryption, attestation proofs, refusal, notification, batch and deferred issuance).
2. **Live end-to-end suites:** wallet-core against public issuers and verifiers through a running trust service.
3. **UI tests:** Playwright on the Expo web build, and the same app in Expo Go on an Android emulator (Hermes).

No local issuer is used; every credential below was issued by a live third-party service.

| Scenario (live) | Spec features exercised | Result |
| --- | --- | --- |
| Animo mDL, pre-authorized code | OID4VCI 1.0, insertion well-known, nonce endpoint, `jwk` proof | valid, TRUSTED (DS → Animo IACA) |
| Animo mDL with DPoP, PIN, and DPoP + wallet attestation + key attestation | HAIP issuance (RFC 9449, ABCA, key attestation) | valid, TRUSTED |
| Animo mDL, sign-in | PAR, PKCE S256, FAPI2 `request_uri`, RFC 9207 `iss` | valid, TRUSTED |
| Animo mDL, deferred 1 min | 202 + `transaction_id`, deferred endpoint with DPoP | issued after 62 s; also stored as pending and retrieved later with the kept DPoP-bound token |
| Animo mDL and EUDI PID SD-JWT, batch of 3 (also with one key attestation for all keys) | `batch_credential_issuance`, `proofs.jwt` × 3, key binding per instance | 3 instances, each valid and TRUSTED; two presentations to the Animo verifier used different instances, both `ResponseVerified` |
| Key attestation demanding `iso_18045_high` | `key_attestations_required` precheck | refused before request |
| Animo EUDI PID SD-JWT VC | x5c issuer chain, disclosures, `cnf` | valid, TRUSTED |
| Present mDL and SD-JWT to the Animo verifier | OID4VP 1.0: `x509_hash`, `request_uri`, DCQL, DeviceResponse with handover, KB-JWT, `direct_post.jwt` A256GCM | verifier `ResponseVerified` |
| MOSIP Farmer VCDM 2.0 JSON-LD | Authorization code + PKCE via eSignet, `did:jwk` binding, Ed25519Signature2020, did:web | valid, TRUSTED (warnings for undefined terms) |
| MOSIP Land VCDM 2.0 JSON-LD | Same | refused: signature invalid (issuer defect; Digital Bazaar library agrees) |
| MOSIP mock mDL | Non-ISO mdoc | valid, TRUSTED via `relaxProfile` for the wallet profile; deviations flagged; refused under the strict verifier profile |
| Outage with a synced snapshot (service mode) | Fallback: direct discovery, local did:web, local X.509, snapshot decisions, circuit-breaker recovery | issuance and presentation work; source `snapshot` |
| Outage without a snapshot | Fallback must not fail open | verified; trust `UNKNOWN` |
| Decisions on the device (default mode) | mDL issue and present (Animo), JSON-LD issue (MOSIP); every request to the trust service recorded | only snapshot and JWKS requests; TRUSTED from the snapshot; MOSIP DID document from the snapshot |
| Evaluator parity | 33 queries under lenient and strict profiles: mdoc, SD-JWT and verifier chains, revoked and on-hold Document Signers, a relaxed sandbox anchor, DID keys, status, authorizations, trusted\_authorities, identifiers claimed without a bound key, live Animo and MOSIP entries | service and device identical (decision, error reasons, entity, revocation status) |
| Revocation (Animo) | Animo mDL Document Signer against the IACA CRL from https://playground.animo.id/crl, compiled into the snapshot | not revoked, with no extra request (privacy test); the same result when the service decides |
| Relays | The Animo CRL and the MOSIP Land status list, fetched through the service | verified on the device; MOSIP's list is signed with a key missing from its DID document, so the status is unknown |
| Wallet web UI (Playwright) | Settings and trust list, mDL issue and present decided on the device, the same decision by the service in service mode, outage; MOSIP JSON-LD (opt-in) | pass |
| Wallet on Android (Expo Go, emulator) | Deep-linked Animo offers (pre-authorized; DPoP + wallet attestation), mDL presentation to the Animo verifier, revocation evidence | TRUSTED, *not revoked*; verifier reports `ResponseVerified` |

The offline suites include spec vectors, so wire formats are checked byte for byte:

- the OpenID4VP 1.0 B.2.6.1 SessionTranscript;
- RFC 7518 Appendix C ECDH-ES Concat KDF;
- RFC 7638 thumbprint;
- the did:key P-256 vector;
- the RFC 9901 disclosure digest.

They also parse the live EU LOTL (sequence 397).

## Operations and configuration

One `application.yml` drives everything: frameworks, sources, clients, HTTP limits, caches and DID drivers. The full reference is `docs/configuration.md` in the repository.

**Running locally**

```sh
scripts/build.sh                # mvn install (112 tests) + npm builds
scripts/start-trust-server.sh   # :8090, loads Animo / MOSIP / EBSI sources
scripts/test-all.sh             # offline suites, then live end-to-end (internet)
scripts/android.sh setup|start  # the wallet in Expo Go on an Android emulator
```

**Observability.**

- `/actuator/health` reports a `trust` component with per-source state and registry counts. It is DOWN until the first load completes.
- `/admin/v1/sources` shows the last attempt and success, errors, counts, `ListInfo` (sequence, `nextUpdate`, signature status) and the next refresh.
- `/admin/v1/registry` gives counts by framework, role and trust domain.
- Micrometer metrics are on `/actuator/metrics`.

**Extending.**

- *New list format:* one `TrustSourceFactory` plus a `META-INF/services` line.
- *New DID method:* either an `http-registry` template in config or a `DidMethodDriver`.
- *New certificate profile:* a `CertificateProfile` bound to a trust domain.
- *Client storage:* any `KeyValueStorage` (AsyncStorage, localStorage).

**Continuous integration.** `.github/workflows/ci.yml` runs the offline suites, the typechecks and the web and Android bundles.

**Roadmap and open questions**

- [x] Production auth (OAuth 2.0 access tokens, mTLS, rate limits) and an HSM-capable signing key with rotation.
- [x] Status checks for verifiers: in the client library, used by wallets and verifier backends alike. The service relays lists but does not decide status, because the status index identifies the credential.
- [x] DNS rebinding in the SSRF guard: closed by connecting only to the vetted addresses.
- [x] Signed issuer metadata: verified wherever it is served; required per client profile (`require-signed-issuer-metadata`) for HAIP ecosystems that ask for it.
- [x] MOSIP's non-ISO mock mDL: trusted with warnings for wallet profiles that allow relaxed anchors, refused by strict verifiers (`allow-relaxed-profiles: false`).
- [ ] DC API (`dc_api.jwt`) presentation needs a native wallet registered with the platform's credential manager; the Expo demo uses the redirect flow, which HAIP accepts on its own (§3: a wallet meets the requirements of the flows it implements). The decision engine already supports the `origin:` client\_id prefix.
- [x] Batch issuance: several instances of one credential, a fresh one for each verifier (HAIP §4: in one batch request).
- [ ] iOS: not tested yet; the app runs on the web and on Android.
- [ ] File the MOSIP collab defect reports (drafts in `docs/upstream-reports.md`).
