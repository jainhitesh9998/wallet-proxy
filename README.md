# VC Trust Service

A spec-agnostic trust service for OpenID4VCI / OpenID4VP wallets and verifiers. It has three parts:

- **Server** (Java 21, Spring Boot 4.1). It ingests trust lists in many formats into one model and answers "should I trust this party?". It also proxies and caches issuer metadata, X.509 chain validation (mdoc IACA, SD-JWT VC issuers, verifier access certificates) and DID resolution.
- **Client library** (TypeScript, `@vctrust/trust-client`). One API for wallets and verifiers. When the service is unreachable it falls back to standard mechanisms and a signed offline snapshot.
- **Demo wallet**. A platform-neutral `@vctrust/wallet-core` (OpenID4VCI 1.0, OpenID4VP 1.0, HAIP 1.0) and an Expo React Native app (`apps/wallet`). It is tested against live issuers: Animo playground (mDL mdoc, SD-JWT VC) and MOSIP collab (W3C VCDM 2.0 JSON-LD, mDL).

Design document: https://claude.ai/artifact/RViVpaEWce3S8yctArPdvk (also in `docs/DESIGN.md`). Configuration reference: [`docs/configuration.md`](docs/configuration.md).

```
trust-server/          Maven: trust-core (model, SPIs, evaluator, X.509, DID, metadata) ← trust-adapters ← trust-server (Spring Boot)
packages/trust-client  @vctrust/trust-client — TS client with fallback (Node, browser, React Native)
packages/wallet-core   @vctrust/wallet-core  — OID4VCI / OID4VP / HAIP holder logic + credential verification
apps/wallet            Expo demo wallet (web + Expo Go)
e2e/                   Playwright UI tests of the wallet web build
tools/mosip-issuance   Headless eSignet login helper used by the MOSIP live tests
scripts/               build / start / test helpers
```

## Quick start

Toolchains are user-local in `~/.local/tools` (JDK 21, Maven 3.9, Node 22). Load them with `. scripts/env.sh`; to make
them permanent, add `source ~/.local/tools/env.sh` to your shell profile.

```sh
scripts/build.sh                 # mvn install (61 tests) + npm install + TS builds
scripts/start-trust-server.sh    # http://localhost:8090 — loads live sources (Animo, MOSIP collab, EBSI on demand)
open http://localhost:8090/swagger-ui.html
curl -H 'Authorization: Bearer demo-wallet-key' 'localhost:8090/api/v1/issuers?format=mso_mdoc'
scripts/test-all.sh              # unit + integration + live end-to-end (needs internet); --offline for unit only
```

Demo API keys (from `application.yml`): `demo-wallet-key` (wallet profile), `demo-verifier-key` (strict verifier
profile) and `admin-key` (admin API).

## What the server does

| Capability | Endpoint |
| --- | --- |
| Trusted issuers and verifiers with metadata, filterable by format and type | `GET /api/v1/issuers`, `/verifiers`, `/entities/{id}`, `/entities/lookup` |
| Spec-agnostic trust decision (issuer, verifier, wallet provider; identifier, x5c, kid, JWK; DCQL `trusted_authorities`) | `POST /api/v1/evaluate`, `/evaluate/batch` |
| OpenID4VCI metadata proxy: validated, cached, policy-curated, with a trust decision | `GET /api/v1/issuers/metadata?credential_issuer=` |
| X.509 path validation per trust domain (ISO 18013-5 DS profile, verifier access, ...) and anchor export | `POST /api/v1/x509/validate`, `GET /api/v1/x509/anchors` |
| DID resolution proxy (did:web, did:key, did:jwk native; EBSI registry; Universal Resolver) | `GET /api/v1/did/{did}`, `GET /1.0/identifiers/{did}` |
| Signed offline snapshot for clients | `GET /api/v1/snapshot` (`trust-snapshot+jwt`) |
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
  serviceKeys: { thumbprints: ['<signing_key_thumbprint from /.well-known/trust-service>'] },
  fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },   // optional app-bundled anchors
});
await trust.syncSnapshot();                                         // enables offline trust decisions
const md = await trust.getIssuerMetadata(credentialIssuer);         // proxy → or direct .well-known when offline
const { decision } = await trust.evaluateCredential(credential, 'mso_mdoc', { credentialIssuer });
const verifier = await trust.evaluateVerifier({ clientId, x5c, responseUri });
```

Every decision carries `source` (`trust-service`, `snapshot` or `fallback`). Fallback runs only when the service is
unreachable, never on policy errors. Without a verified snapshot or a pinned anchor, an offline decision is
`UNKNOWN`, never `TRUSTED`.

## Demo wallet

See [`apps/wallet/README.md`](apps/wallet/README.md) for running it on the web and in Expo Go. The wallet core works on its own too:

```ts
const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri });
const session = await wallet.receive('openid-credential-offer://?credential_offer_uri=...');   // issuer trust: session.issuerTrust
const [cred] = await wallet.store(await session.acceptPreAuthorized(txCode));                  // cred.report: checks + trust
const p = await wallet.startPresentation('openid4vp://?client_id=x509_hash:...&request_uri=...');  // p.verifier.trust, p.dcql
await p.respond();
```

## Tested end to end against live services

| Scenario | Result |
| --- | --- |
| Animo mDL (mdoc), pre-authorized code | valid + TRUSTED (DS `credo dcs` → Animo IACA, 14 digests, device key) |
| Animo mDL with DPoP, PIN (`tx_code`), and DPoP + wallet attestation + key attestation (HAIP) | valid + TRUSTED |
| Animo mDL, authorization code flow: PAR + PKCE + DPoP + wallet attestation, RFC 9207 `iss` (HAIP mandatory flow) | valid + TRUSTED |
| Animo mDL with deferred issuance (`202` + `transaction_id`, deferred endpoint polled with DPoP) | valid + TRUSTED after about 60 s |
| Key attestation demanding `iso_18045_high` when the wallet attests less | correctly refused before the request |
| Animo EUDI PID SD-JWT VC issuance | valid + TRUSTED (x5c chain) |
| OpenID4VP to Animo verifier: `x509_hash`, `request_uri`, DCQL, `direct_post.jwt` (mdoc DeviceResponse and SD-JWT+KB) | verifier TRUSTED; verifier reports `ResponseVerified` |
| MOSIP Farmer VCDM 2.0 JSON-LD (eSignet authorization code + PKCE) | valid + TRUSTED (Ed25519Signature2020 over RDFC-1.0, did:web) |
| MOSIP Land VCDM 2.0 JSON-LD | signature **invalid** — issuer defect, confirmed with Digital Bazaar's reference library |
| MOSIP mock mDL | valid + TRUSTED under a `relaxProfile` anchor, with ISO deviations reported |
| Trust service outage with a synced snapshot (mDL issue + present, JSON-LD issue) | works; trust from `snapshot`; recovers afterwards |
| Trust service outage without a snapshot | credential verified; trust `UNKNOWN` (`fallback`) |

### Findings about the live issuers

- **MOSIP Land `LandStatementCredential_VCDM2.0`:** the signature does not verify with standard RDFC-1.0 / Ed25519Signature2020 (our verifier and `jsonld-signatures` agree). The credential subject carries native JSON doubles, which points at a Java-side canonicalization difference in Inji Certify.
- **MOSIP Farmer:** uses terms that its contexts do not define, so they are not covered by the signature. The wallet reports this as a warning; strict libraries reject the credential.
- **MOSIP collab issuers in general:**
  - The signing key's DID (`did:web:inji.github.io:...`) differs from `issuer`, and `assertionMethod` lists the bare DID. Both are reported as warnings; key equivalence is checked.
  - The pre-authorized flow is broken on collab: tokens from `/v1/certify/oauth/token` are rejected by the credential endpoint, and `credential_offer_uri` is not a URL.
  - The mDL is not ISO-conformant: `{docType, issuerSigned}` wrapper, MSO not tag-24 wrapped, no DS EKU, CA leaf.
- **Animo playground:** the verifier requires fully specified `ESP256 (-9)` for device authentication. Metadata mixes the 1.0 `credential_metadata` layout with top-level `display`/`claims`; the wallet accepts both.
