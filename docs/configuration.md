# Trust service configuration reference

All settings live under `trust.*` in `trust-server/trust-server/src/main/resources/application.yml`. Any Spring Boot
mechanism can override them: environment variables, `--trust.service.issuer=...`, or an external `application.yml`.

## Service, HTTP, cache, DID

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.service.issuer` | `http://localhost:8090` | Service identifier; `iss` of signed responses and snapshots |
| `trust.service.signing-key-file` | `./data/signing-key.jwk` | ES256 key; generated on first start. Clients pin its thumbprint (`/.well-known/trust-service`) |
| `trust.service.decision-ttl` / `snapshot-ttl` / `signed-response-ttl` | 1h / 24h / 10m | Validity of decisions, snapshots and signed responses. Snapshots are re-signed after half their TTL |
| `trust.service.snapshot-did-documents` | `true` | Embed the DID documents of registered DID identifiers in snapshots, so clients verify without resolving |
| `trust.service.snapshot-max-did-documents` / `snapshot-did-deadline` | 200 / 5s | Bounds on that resolution; documents not ready in time are left out (clients resolve them) |
| `trust.http.connect-timeout` / `read-timeout` | 5s / 15s | Outbound HTTP timeouts |
| `trust.http.max-response-bytes` | 8 MiB | Cap on fetched documents |
| `trust.http.allow-private-networks` | `false` | Allow fetching private / loopback addresses (development only) |
| `trust.http.allowed-private-hosts` | `[]` | Hosts exempt from the private-network check |
| `trust.http.http-allowed-hosts` | `[]` | Hosts that may use plain http (development only; also used for did:web) |
| `trust.cache.metadata-min-ttl` / `metadata-max-ttl` | 1m / 1h | Clamp for upstream `Cache-Control` on issuer metadata |
| `trust.cache.did-ttl` / `negative-ttl` | 15m / 1m | DID document and negative-result caching |
| `trust.cache.stale-if-error` | 24h | How long stale data may be served when an upstream is down |
| `trust.did.registries.<method>` | `ebsi: https://api-pilot.ebsi.eu/did-registry/v5/identifiers/{did}` | Native HTTP-registry DID drivers |
| `trust.did.universal-resolver-url` / `universal-resolver-methods` | `https://dev.uniresolver.io` / `["*"]` | Fallback resolver for other methods (the public instance is rate-limited) |
| `trust.cors-origins` | `["*"]` | CORS origins for `/api/**`, `/.well-known/**`, `/1.0/**`, `/trqp/**` |

## Revocation and relays

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.revocation.enabled` | `true` | Fetch the trust anchors' CRLs, check revocation in `/evaluate` and `/x509/validate`, ship current anchor CRLs in snapshots |
| `trust.revocation.refresh` | 1h | Anchor CRLs are re-fetched at the earlier of this and their `nextUpdate` |
| `trust.revocation.max-crl-bytes` / `snapshot-max-crl-bytes` | 1 MiB / 256 KiB | Cap on a fetched CRL / on a CRL embedded in a snapshot (larger ones are fetched by clients per `lookups.crl`) |
| `trust.revocation.fetch-on-demand` | `true` | Server-side checks fetch the CRL distribution points of CAs below an anchor |
| `trust.revocation.ocsp` | `false` | OCSP for certificates without CRL coverage, in the service's own decisions only (verifier backends). Devices never use OCSP |
| `trust.revocation.relay-crls` | `true` | `GET /api/v1/revocation/crl?url=`: CRL relay (CA-signed, verified by the client) |
| `trust.revocation.relay-status-lists` | `true` | `GET /api/v1/revocation/status-list?uri=`: status list relay (issuer-signed, verified by the client) |
| `trust.revocation.status-list-default-ttl` / `status-list-max-ttl` | 5m / 1h | Relay caching: upstream `max-age` clamped to the max, `no-store` honoured, the default without a header |
| `trust.revocation.max-status-list-bytes` | 2 MiB | Cap on a relayed status list |

## Clients (who may ask, and what they see)

A client profile scopes both the service's own decisions and the snapshot the client decides from. The snapshot
carries `policy: {frameworks, strictAuthorization, requireRevocationStatus}`, so the client applies the same profile on its device.

```yaml
trust:
  anonymous: { enabled: true, frameworks: [] }        # unauthenticated callers; [] = all frameworks
  clients:
    - id: demo-wallet
      api-key: demo-wallet-key                         # Authorization: Bearer <key> or X-API-Key
      frameworks: [animo-playground, mosip-collab]      # only these frameworks are visible / trusted
      strict-authorization: false                       # true: entities without authorizations are not authorized
      require-revocation-status: false                  # true: a certificate whose revocation status is unknown is not trusted
      allow-unregistered-metadata: true                 # false: the metadata proxy serves only registered issuers
      admin: false                                      # true: may use /admin/v1/**
```

## Frameworks and sources

```yaml
trust:
  frameworks:
    - { id: animo-playground, name: Animo OpenID4VC Playground, governance-uri: https://playground.animo.id,
        attributes: { recognizes: "other-framework-id" } }   # used by TRQP /recognition
  sources:
    - id: animo-root-mdoc        # unique
      type: x509-bundle          # adapter type (below)
      framework: animo-playground
      refresh: PT6H              # also bounded by the list's own nextUpdate
      enabled: true
      properties: { ... }        # adapter specific
```

| `type` | Properties | Produces |
| --- | --- | --- |
| `static` | `location` (classpath:, file:, https:) | Entities and anchors in the native format (below) |
| `managed` | none | Entities and anchors from the admin API (`PUT /admin/v1/managed/{entities,anchors}/{id}`), persisted in the database |
| `x509-bundle` | `domain`, `certificateLocation`, optional `certificateJsonField`, `entity`, `docTypes` | Anchors from a PEM/DER bundle or a JSON document holding base64 |
| `oid4vci-discovery` | `issuers: [url \| {url, entityId, authorizations}]` | Issuer entities from live OpenID4VCI metadata (display, per-configuration authorizations); `entityId` merges into an entity defined elsewhere |
| `etsi-tl` | `location`, `followPointers`, `territories`, `serviceTypeDomains`, `includeAllServiceTypes`, `signerCertificates` / `signerCertificateLocation`, `verifyPointerSignatures` | ETSI TS 119 612 TL / EU LOTL: providers as entities, service certificates as anchors (EAA service types map to `credential-issuer` by default) |
| `etsi-lote` | `location`, `signerCertificates`, `serviceTypeDomains`, `allowExpired` | ETSI TS 119 602 LoTE (JSON or JAdES): PID, Pub-EAA, wallet, WRPAC and WRPRC providers |
| `vical` | `location`, `signerCertificates` / `signerCertificateLocation`, `allowUnverified` | ISO 18013-5 VICAL: IACA anchors constrained to their docTypes, issuing-authority entities |
| `openid-federation` | `trustAnchor`, `trustAnchorJwks` / `trustAnchorJwksLocation`, `crawl`, `maxDepth`, `maxEntities` | Entities from validated trust chains (metadata policy applied, trust marks verified); on-demand resolution of unknown entity ids |
| `ebsi-tir` | `baseUrl`, `crawl`, `maxIssuers`, `pageSize` | EBSI Trusted Issuers Registry v5 entities (issuer types and accredited types); on-demand lookup by `did:ebsi` |

### Native entity / anchor format (`static`, `managed`)

```yaml
entities:
  - id: mosip-land                       # entities with the same id across sources are merged
    framework: mosip-collab              # defaults to the source's framework
    roles: [CREDENTIAL_ISSUER]           # VERIFIER, WALLET_PROVIDER, AUTHORIZATION_SERVER, ACCREDITATION_AUTHORITY, STATUS_LIST_PROVIDER
    name: MOSIP Land Registry            # or display: [{locale, name, description, logoUri}]
    identifiers:                         # typed, or bare strings (DID / URL / client_id are guessed)
      - {type: URL, value: "https://injicertify-landregistry.collab.mosip.net"}
      - did:web:injicertify-landregistry.collab.mosip.net
      # types: DID, URL, CLIENT_ID, DNS, X509_SUBJECT, X509_SKI, X509_SHA256, JWK_THUMBPRINT, FEDERATION_ENTITY
    authorizations:                      # what it may issue / request; empty = unconstrained (unless strict client)
      - {format: ldp_vc, type: LandStatementCredential}
    status: ACTIVE                       # SUSPENDED, REVOKED, EXPIRED
    validUntil: 2027-12-31
    certificates: ["<PEM or base64>"]   # end-entity certs bound to the entity (optional)
    metadataPolicy:                      # OpenID Federation operators, applied to live metadata by the proxy
      oauth_authorization_server:
        token_endpoint: {default: "https://issuer.example/token"}
anchors:
  - domain: mdoc-iaca                    # credential-issuer, verifier-access, wallet-provider, status-list, list-signer, ...
    framework: mosip-collab
    entity: mosip-mdl                    # validating a chain to this anchor identifies the entity
    certificate: "<PEM>"                 # or certificates: [...], or certificateLocation (+ certificateJsonField)
    constraints:
      docTypes: [org.iso.18013.5.1.mDL]  # restricts the doctypes this IACA may sign
      relaxProfile: true                 # turn certificate-profile errors into warnings (sandbox issuers only)
      crlUrls: ["https://pki.example/iaca.crl"]   # where this CA publishes its CRL (default for a self-issued anchor: its own CRL DP)
      crl: "<PEM or base64 DER>"         # or a CRL pushed by the operator (e.g. through the admin API); verified against the anchor
```

## Adding a new trust-list format

1. Implement `io.vctrust.trust.core.spi.TrustSourceFactory`, returning a `TrustSource` whose `load()` maps the list
   into `TrustedEntity` / `TrustAnchor` records and a `ListInfo` (sequence, nextUpdate, signature status). Use
   `SourceContext.http()` for all I/O, so the SSRF guard and limits apply.
2. Implement `OnDemandResolver` too if the registry is too large to enumerate.
3. Register the factory in `META-INF/services/io.vctrust.trust.core.spi.TrustSourceFactory`, or expose it as a Spring bean.
4. Reference it from `trust.sources[].type`.

## Client library modes

Wallets use the TypeScript client in its default `decisions: 'local'` mode. It downloads the signed snapshot for its API key and evaluates trust on the device. It never calls `/evaluate`.
- Set `serviceKeys.thumbprints` to the `signing_key_thumbprint` from `/.well-known/trust-service`.
- `lookups` controls the calls that would tell the service which party a user deals with:
  - `metadata` and `did`: `'direct'` (default) or `'service'`;
  - `unknownParties`: on-demand registry lookups, off by default;
  - `crl`: CRLs the snapshot does not carry, `'direct'` (default), `'service'` (relay) or `'none'`;
  - `statusLists`: `'direct'` (default) or `'service'` (relay).

Verifier backends and thin clients can use `decisions: 'service'`. See `packages/trust-client/README.md`.
