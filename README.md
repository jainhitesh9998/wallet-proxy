# VC Trust Service

A spec-agnostic trust service for OpenID4VCI / OpenID4VP wallets and verifiers. It has three parts:

- **Server** (Java 21, Spring Boot 4.1).
  - It ingests trust lists in many formats into one model.
  - It compiles a signed **trust snapshot** per client: entities, trust anchors, evaluation policy, DID documents and metadata policies.
  - It also answers "should I trust this party?" directly (`/evaluate`), for verifier backends and thin clients.
  - It proxies and caches issuer metadata, X.509 chain validation and DID resolution.
- **Client library** (TypeScript, `@vctrust/trust-client`). One API for wallets and verifiers.
  - **By default it decides trust on the device**, from the signed snapshot, with the same rules as the server. The service never learns which issuers or verifiers a user deals with.
  - Lookups that would disclose a counterparty (metadata proxy, DID proxy, on-demand registry lookups) are opt-in.
- **Demo wallet**. A platform-neutral `@vctrust/wallet-core` (OpenID4VCI 1.0, OpenID4VP 1.0, HAIP 1.0) and an Expo React Native app (`apps/wallet`), which on Android also answers Digital Credentials API requests through Credential Manager. It is tested against live issuers: Animo playground (mDL mdoc, SD-JWT VC) and MOSIP collab (W3C VCDM 2.0 JSON-LD, mDL, SD-JWT VC).

Design document: https://claude.ai/artifact/RViVpaEWce3S8yctArPdvk (also in `docs/DESIGN.md`). Configuration reference: [`docs/configuration.md`](docs/configuration.md).

```
trust-server/          Maven: trust-core (model, SPIs, evaluator, X.509, DID, metadata) ← trust-adapters ← trust-server (Spring Boot)
packages/trust-client  @vctrust/trust-client — TS client with fallback (Node, browser, React Native)
packages/wallet-core   @vctrust/wallet-core  — OID4VCI / OID4VP / HAIP holder logic + credential verification
apps/wallet            Expo demo wallet (web, Expo Go; Android release build with the Digital Credentials API)
e2e/                   Playwright UI tests of the wallet web build
tools/mosip-issuance   Headless eSignet login helper used by the MOSIP live tests
scripts/               build / start / test helpers
```

## Quick start

Toolchains are user-local in `~/.local/tools` (JDK 21, Maven 3.9, Node 22). Load them with `. scripts/env.sh`; to make
them permanent, add `source ~/.local/tools/env.sh` to your shell profile.

```sh
scripts/build.sh                 # mvn install (124 tests) + npm install + TS builds
scripts/start-trust-server.sh    # http://localhost:8090 — loads live sources (Animo, MOSIP collab, EBSI on demand)
open http://localhost:8090/swagger-ui.html
curl -H 'Authorization: Bearer demo-wallet-key' 'localhost:8090/api/v1/issuers?format=mso_mdoc'
scripts/test-all.sh              # unit + integration + live end-to-end (needs internet); --offline for unit only
scripts/android.sh setup && scripts/android.sh start   # the wallet in Expo Go on an Android emulator
scripts/android-dcapi.sh setup && scripts/android-dcapi.sh start && scripts/android-dcapi.sh build   # native build, DC API
node e2e/dcapi-android.mjs issue && node e2e/dcapi-android.mjs   # DC API end to end: Chrome → picker → wallet → Animo
```

CI (`.github/workflows/ci.yml`) runs the offline suites, typechecks and the web and Android bundles.

Demo API keys (from `application.yml`): `demo-wallet-key` (wallet profile), `demo-verifier-key` (strict verifier
profile: strict authorization, revocation status required, relaxed anchors refused) and `admin-key` (admin API).
Production deployments use OAuth 2.0 access tokens or mTLS client certificates instead, with rate limits, and keep the
signing key in a PKCS#11 HSM; see the configuration reference.

## Where trust is decided

```
 trust lists (ETSI TL/LoTE, VICAL, OpenID Federation, EBSI, X.509 bundles, OID4VCI discovery, static, admin)
        │  ingest, verify list signatures, normalize
        ▼
 trust service ── per client profile ──► signed trust snapshot (trust-snapshot+jwt)
        │                                  entities · anchors · policy · DID documents · metadata policies · anchor CRLs
        │ /evaluate (verifier backends, thin clients)          │ GET /api/v1/snapshot (the only call a wallet makes)
        ▼                                                       ▼
   decision by the service                       wallet: verify snapshot (pinned key, audience, no rollback)
                                                  → evaluate on the device (same rules as the service)
```

- **`decisions: 'local'`** (default; wallets): the service compiles, the device decides.
  - Live test (`privacy.live.test.ts`): during real mDL issuance and presentation and JSON-LD issuance, the trust service receives only `GET /api/v1/snapshot` and `GET /.well-known/jwks.json`.
  - The parity test (`parity.live.test.ts`) asserts that the device and `/evaluate` agree, under a lenient and a strict client profile: same decision, same error reasons, same entity.
- **`decisions: 'service'`**: the service decides, and the device takes over only while the service is unreachable.

### Revocation
- **Certificates:** every certificate below the trust anchor is checked against a CRL its issuer signed.
  - The service fetches the anchors' CRLs and puts them in the snapshot. An anchor gets its CRL from its own distribution point (Animo's IACA publishes one), `crlUrls`, or a CRL pushed through the admin API.
  - The device verifies every CRL again, so neither the service nor a cache is trusted with revocation.
  - Other CRLs are fetched directly from the CA, or through the service's CRL relay.
- **No OCSP on the device**, because an OCSP request names the exact certificate. A verifier backend can turn OCSP on in the service.
- **Credential status** (in the client library, so verifiers get it too: `checkTokenStatus`, `checkBitstringStatus`):
  - Token Status List: JWT for SD-JWT VC, CWT for ISO mdoc via the MSO `status`.
  - W3C Bitstring Status List.
  - Lists are fetched from the issuer, or through the service's status list relay (opt-in), and are verified on the device either way: signature, signer, subject, expiry, and for Bitstring lists the list credential's proof and issuer. A verified list is reused for its `ttl` (at most 1 h).

## What the server does

| Capability | Endpoint |
| --- | --- |
| Trusted issuers and verifiers with metadata, filterable by format and type | `GET /api/v1/issuers`, `/verifiers`, `/entities/{id}`, `/entities/lookup` |
| Spec-agnostic trust decision (issuer, verifier, wallet provider; identifier, x5c, kid, JWK; DCQL `trusted_authorities`) | `POST /api/v1/evaluate`, `/evaluate/batch` |
| OpenID4VCI metadata proxy: validated, cached, policy-curated, with a trust decision | `GET /api/v1/issuers/metadata?credential_issuer=` |
| X.509 path validation per trust domain (ISO 18013-5 DS profile, verifier access, ...) and anchor export | `POST /api/v1/x509/validate`, `GET /api/v1/x509/anchors` |
| DID resolution proxy (did:web, did:key, did:jwk native; EBSI registry; Universal Resolver) | `GET /api/v1/did/{did}`, `GET /1.0/identifiers/{did}` |
| Signed trust snapshot: everything a client needs to decide on the device, including the anchors' CRLs | `GET /api/v1/snapshot` (`trust-snapshot+jwt`) |
| CRL relay and status list relay (signed objects, passed through and cached; verified by the client); anchor CRL status | `GET /api/v1/revocation/crl?url=`, `/revocation/status-list?uri=`, `/revocation/crls` |
| On-demand registry lookup for parties absent from the snapshot (opt-in, signed) | `GET /api/v1/entities/lookup?identifier=&onDemand=true` |
| Client authentication: API keys, OAuth 2.0 JWT access tokens (RFC 9068), mTLS (RFC 8705 bound tokens), per-client rate limits | `Authorization`, TLS client certificate; methods listed in discovery |
| ToIP Trust Registry Query Protocol v2 | `POST /trqp/authorization`, `/trqp/recognition` |
| Operator API | `/admin/v1/sources`, `/registry`, `/managed/{entities,anchors}/{id}` |

Sources (adapters):
- `static` and `managed` (admin API);
- `x509-bundle`;
- `oid4vci-discovery`;
- `etsi-tl` (ETSI TS 119 612, EU LOTL);
- `etsi-lote` (ETSI TS 119 602);
- `vical` (ISO 18013-5);
- `openid-federation` (1.0);
- `ebsi-tir` (v5).

A new format is one `TrustSourceFactory` (see the configuration reference). Any JSON endpoint returns a service-signed JWT
when called with `Accept: application/jwt`.

## Client library

```ts
import { createTrustClient, KeyValueCacheStore } from '@vctrust/trust-client';

const trust = createTrustClient({
  baseUrl: 'http://localhost:8090', apiKey: 'demo-wallet-key', clientId: 'demo-wallet',
  serviceKeys: { thumbprints: ['<signing_key_thumbprint from /.well-known/trust-service>'] },   // required to accept snapshots
  // decisions: 'local' (default) | 'service'
  // lookups: { metadata: 'direct', did: 'direct', unknownParties: false, crl: 'direct', statusLists: 'direct' }
  // issuerMetadata: { signed: 'off' | 'verify' | 'require' }   // a client profile can require signed metadata
  fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },   // optional app-bundled anchors
});
const md = await trust.getIssuerMetadata(credentialIssuer);         // from the issuer, registry metadata policy applied
const { decision } = await trust.evaluateCredential(credential, 'mso_mdoc', { credentialIssuer });   // decided on the device
const verifier = await trust.evaluateVerifier({ clientId, x5c, responseUri });
const status = await trust.checkTokenStatus(statusRef, { signerX5c: x5c, decision, form: 'cwt' });   // mdoc MSO status
```

Every decision says who decided (`source`: `trust-service`, `snapshot` = this device from the signed snapshot, or
`fallback` = this device with app-pinned anchors only) and from which snapshot version.
- The snapshot is refreshed in the background, never rolled back, and usable for 7 days past its expiry, with a warning.
- Without a verified snapshot or a pinned anchor, a decision is `UNKNOWN`, never `TRUSTED`.
- See [`packages/trust-client/README.md`](packages/trust-client/README.md).

## Demo wallet

See [`apps/wallet/README.md`](apps/wallet/README.md) for running it on the web and in Expo Go. The wallet core works on its own too:

```ts
const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri });
const session = await wallet.receive('openid-credential-offer://?credential_offer_uri=...');   // issuer trust: session.issuerTrust
const [cred] = await wallet.store(await session.acceptPreAuthorized(txCode));   // refused if invalid; stored → credential_accepted
const p = await wallet.startPresentation('openid4vp://?client_id=x509_hash:...&request_uri=...');  // p.verifier.trust, p.dcql
await p.respond();                         // refused unless an x509 verifier is TRUSTED; discloses only the requested claims
// Digital Credentials API (Android): the platform passes the request and the verifier's Origin
const dc = await wallet.startDcApiPresentation(pickDcApiRequest(requestJson, origin)!);
const { dcApi } = await dc.respond();      // {vp_token} or {response: JWE}, bound to origin:<origin>; returned through the platform
```

## Tested end to end against live services

| Scenario | Result |
| --- | --- |
| Animo mDL (mdoc), pre-authorized code | valid + TRUSTED (DS `credo dcs` → Animo IACA, 14 digests, device key) |
| Animo mDL with DPoP, PIN (`tx_code`), and DPoP + wallet attestation + key attestation (HAIP) | valid + TRUSTED |
| Animo mDL, authorization code flow: PAR + PKCE + DPoP + wallet attestation, RFC 9207 `iss` (HAIP mandatory flow) | valid + TRUSTED |
| Animo mDL with deferred issuance (`202` + `transaction_id`, deferred endpoint polled with DPoP), and stored as pending then retrieved later | valid + TRUSTED after about 60 s |
| Animo mDL and EUDI PID SD-JWT, batch issuance of 3 (also with one key attestation for all keys) | 3 instances, each valid + TRUSTED; consecutive presentations use different instances, both `ResponseVerified` |
| Key attestation demanding `iso_18045_high` when the wallet attests less | correctly refused before the request |
| Animo EUDI PID SD-JWT VC issuance | valid + TRUSTED (x5c chain) |
| OpenID4VP to Animo verifier: `x509_hash`, `request_uri`, DCQL, `direct_post.jwt` (mdoc DeviceResponse and SD-JWT+KB) | verifier TRUSTED; verifier reports `ResponseVerified` |
| MOSIP Farmer VCDM 2.0 JSON-LD (eSignet authorization code + PKCE) | valid + TRUSTED (Ed25519Signature2020 over RDFC-1.0, did:web) |
| MOSIP Land VCDM 2.0 JSON-LD | **refused**: signature invalid (issuer defect, confirmed with Digital Bazaar's reference library); the issuer is sent `credential_failure` |
| MOSIP mock mDL | valid + TRUSTED under a `relaxProfile` anchor for the wallet profile, with ISO deviations reported; the strict verifier profile refuses it |
| MOSIP mock identity SD-JWT VC | valid + TRUSTED under a `relaxProfile` anchor (the issuer's published root), with warnings for the signing certificate's key usage, `cnf.kid` instead of `cnf.jwk`, and `expirationDate` instead of `exp` |
| Decisions on the device (default): mDL issue + present to Animo, MOSIP JSON-LD issue | TRUSTED from the snapshot; the trust service saw only snapshot/JWKS requests; MOSIP DID document from the snapshot |
| Parity: 37 queries (including revoked / on-hold / CRL-covered Document Signers, a relaxed sandbox anchor, `origin:` verifiers and a URL written differently) × lenient and strict client profiles, service `/evaluate` vs device, the device asking on demand where the service does | identical decisions, error reasons, entities and per-certificate revocation status |
| Revocation, live: Animo mDL Document Signer against the Animo IACA CRL (`https://playground.animo.id/crl`) | `GOOD`; the CRL comes from the snapshot, with no other request to the service or to Animo |
| Relays, live: the Animo CRL and a MOSIP status list fetched through the service | verified on the device; MOSIP's list is signed with a key missing from its DID document, so its status is reported as unknown |
| Trust service outage, `service` mode with a synced snapshot (mDL issue + present, JSON-LD issue) | works; trust from `snapshot`; recovers afterwards |
| Trust service outage without a snapshot | credential verified; trust `UNKNOWN` (`fallback`) |
| Wallet in Expo Go on an Android emulator: Animo mDL (pre-authorized; DPoP + wallet attestation), presentation to the Animo verifier | TRUSTED, *not revoked*; verifier reports `ResponseVerified` |
| Digital Credentials API, native release build on an Android 37.2 emulator: Animo's verifier in Chrome, the Play services picker, the wallet's consent screen. PID (SD-JWT) and mDL (mdoc) with signed `x509_hash` requests and `dc_api.jwt`; mDL unsigned + `dc_api.jwt`; PID unsigned + `dc_api`; a decline; a multi-signed request from a local page signed by an untrusted verifier | *Verification Successful* for all four presentations, verifier TRUSTED (unsigned: by origin); the decline reaches the page as `NotAllowedError`; the multi-signed request is authenticated and sharing blocked |
| HAIP details no live issuer exercises (offline, in-memory issuer): credential request/response encryption, attestation proofs, refusal and notifications, minimal disclosure, holder binding, verifier trust enforcement, error responses | pass |

### Findings about the live issuers

Draft defect reports for MOSIP are in [`docs/upstream-reports.md`](docs/upstream-reports.md); nothing has been filed.

- **MOSIP Land `LandStatementCredential_VCDM2.0`:** the signature does not verify with standard RDFC-1.0 / Ed25519Signature2020 (our verifier and `jsonld-signatures` agree). The credential subject carries native JSON doubles, which points at a Java-side canonicalization difference in Inji Certify.
- **MOSIP Farmer:** uses terms that its contexts do not define, so they are not covered by the signature. The wallet reports this as a warning; strict libraries reject the credential.
- **MOSIP collab issuers in general:**
  - The signing key's DID (`did:web:inji.github.io:...`) differs from `issuer`, and `assertionMethod` lists the bare DID. Both are reported as warnings; key equivalence is checked.
  - The pre-authorized flow is broken on collab: tokens from `/v1/certify/oauth/token` are rejected by the credential endpoint, and `credential_offer_uri` is not a URL.
  - The mDL is not ISO-conformant: `{docType, issuerSigned}` wrapper, MSO not tag-24 wrapped, no DS EKU, CA leaf.
  - The mock identity issuer's SD-JWT VC breaks HAIP §6.1 twice. It names the holder key by reference (`cnf.kid`, a `did:jwk`) instead of in `cnf.jwk`. It states its expiry as `expirationDate` rather than `exp` (or a status). Its Ed25519 signing certificate allows only `keyEncipherment` and names no issuer (no SAN). The wallet resolves the `did:jwk` and checks it is its own key (a `cnf.kid` it cannot read is refused), and reports each deviation. The issuer has no Mimoto entry; it accepts a token from the Land client's eSignet login.
- **MOSIP status lists:** the Land credential's Bitstring Status List credential is signed with `#0B6e9kc5…`, which is not in `did:web:inji.github.io:inji-config:collab:landregistry`. The wallet reports the status as unknown instead of trusting the bit.
- **Animo playground:** publishes a real IACA CRL (empty, `nextUpdate` 2027-10-26) covering its Document Signer. The DS certificate has no CRL distribution point, which is allowed because the IACA's complete CRL covers it. mDLs and SD-JWTs carry no status list reference.
- **Animo playground:** the verifier requires fully specified `ESP256 (-9)` for device authentication. Metadata mixes the 1.0 `credential_metadata` layout with top-level `display`/`claims`; the wallet accepts both.
