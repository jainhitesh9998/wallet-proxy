# Trust service configuration reference

All settings live under `trust.*` in `trust-server/trust-server/src/main/resources/application.yml`. Any Spring Boot
mechanism can override them: environment variables, `--trust.service.issuer=...`, or an external `application.yml`.

## Service, HTTP, cache, DID

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.service.issuer` | `http://localhost:8090` | Service identifier; `iss` of signed responses and snapshots |
| `trust.service.signing-key-file` | `./data/signing-key.jwk` | ES256 key; generated on first start. Clients pin its thumbprint (`/.well-known/trust-service`). Shorthand for `signing-key.file`; see [Signing key](#signing-key) for keystores and HSMs |
| `trust.service.decision-ttl` / `snapshot-ttl` / `signed-response-ttl` | 1h / 24h / 10m | Validity of decisions, snapshots and signed responses. Snapshots are re-signed after half their TTL |
| `trust.service.snapshot-did-documents` | `true` | Embed the DID documents of registered DID identifiers in snapshots, so clients verify without resolving |
| `trust.service.snapshot-max-did-documents` / `snapshot-did-deadline` | 200 / 5s | Bounds on that resolution; documents not ready in time are left out (clients resolve them) |
| `trust.http.connect-timeout` / `read-timeout` | 5s / 15s | Outbound HTTP timeouts (connect; each read and the wait for the response) |
| `trust.http.total-timeout` | 60s | Upper bound on one fetch including its body, so a slowly dripping response is cut off |
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

**Outbound requests and SSRF.** Everything the service fetches for clients (issuer metadata, DID documents, CRLs,
status lists, trust lists) goes through one guarded HTTP client:

- https only (plain http just for `http-allowed-hosts`), at most 3 redirects, each hop checked again;
- a host name is resolved once per connection, and the request is refused if any address is loopback, private,
  link-local, CGNAT, unique-local, multicast or reserved, including IPv4 embedded in NAT64 (`64:ff9b::/96`) or 6to4
  (`2002::/16`) addresses. The socket connects only to the addresses that passed, so DNS rebinding between the check
  and the connect is not possible. TLS still verifies the host name;
- system proxy settings are ignored (a proxy would resolve names itself); bodies are not decompressed.

## Signing key

The service signs snapshots and `Accept: application/jwt` responses with one ES256 (P-256) key. Clients pin the RFC
7638 thumbprints published in `/.well-known/trust-service` as `signing_key_thumbprints` (current key first;
`signing_key_thumbprint` is the current key alone).

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.service.signing-key.type` | `jwk-file` | `jwk-file`, `keystore` (PKCS#12 / JKS file) or `pkcs11` (HSM; the private key never leaves the token) |
| `trust.service.signing-key.file` | `trust.service.signing-key-file` | `jwk-file`: private JWK, generated with mode 0600 on first start |
| `trust.service.signing-key.keystore` / `keystore-type` | none / `PKCS12` | `keystore`: the store file and its type (`PKCS12`, `JKS`) |
| `trust.service.signing-key.password` / `key-password` | none / `password` | `keystore`: store password and key entry password |
| `trust.service.signing-key.alias` | the only key entry | `keystore` / `pkcs11`: the key entry; required when the store holds several keys |
| `trust.service.signing-key.pkcs11-config` / `pin` | none | `pkcs11`: SunPKCS11 configuration file (`library`, `slot`, ...) and the token PIN |
| `trust.service.signing-key.key-id` | RFC 7638 thumbprint | `kid` published for the key |
| `trust.service.signing-key.previous-keys` | `[]` | Public JWKs of retired keys (inline JSON, a path, `file:` or `classpath:`), still published in `/.well-known/jwks.json` and `signing_key_thumbprints` |

At startup the key must be EC P-256, and it signs and verifies a probe; anything else stops the service with a
message that names the key source. To rotate:

1. Publish the new key's thumbprint to clients (they accept a list: `serviceKeys.thumbprints`).
2. Switch the service to the new key and list the old public key in `previous-keys`.
3. Remove it from `previous-keys` once the old snapshots have expired.

```yaml
trust:
  service:
    signing-key:
      type: pkcs11
      pkcs11-config: /etc/trust/softhsm.cfg      # name = SoftHSM; library = /usr/lib/softhsm/libsofthsm2.so; slot = 0
      pin: ${TRUST_HSM_PIN}
      alias: trust-service-2026
      previous-keys: [/etc/trust/trust-service-2025.pub.jwk]
```

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

## Client authentication

Every call to `/api/**`, `/admin/**`, `/trqp/**` and `/1.0/**` is mapped to a client profile (below). The methods
can be combined; `/.well-known/trust-service` lists the enabled ones in `auth_methods_supported` (`api_key`,
`oauth2_jwt`, `mtls`, `anonymous`).

1. **OAuth 2.0 access token** (`Authorization: Bearer <JWT>`): an RFC 9068 JWT from the operator's authorization
   server, for example from the client credentials grant. Checked: signature against the JWKS, `typ`, `iss`, `aud`,
   `exp` / `nbf` with clock skew, and the required scope. The client is the configured client whose `oauth-client-id`
   (default: its `id`) equals the token's `client_id` (or `azp`). A token with `cnf.x5t#S256` (RFC 8705) is accepted
   only over a connection presenting that TLS client certificate.
2. **API key** (`Authorization: Bearer <key>` or `X-API-Key`): any bearer value that is not shaped like a JWT.
3. **TLS client certificate** (`mtls.enabled`): the client registered for the certificate's SHA-256 thumbprint.
   The certificate comes from this server's TLS connector (`server.ssl.client-auth: want`), or from a header set by
   a TLS-terminating proxy. The header is believed only when the TCP peer is in `trusted-proxies`; forwarded
   addresses (`X-Forwarded-For`) are not considered.
4. **Anonymous**, when `trust.anonymous.enabled`.

Failures are `401` problem details (`code` `unauthorized` or `invalid_token`) with `WWW-Authenticate: Bearer
realm="vc-trust-service", error="invalid_token", ...`; a missing scope is `403 insufficient_scope`.

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.auth.api-keys` | `true` | Accept API keys |
| `trust.auth.oauth.enabled` | `false` | Accept JWT access tokens |
| `trust.auth.oauth.issuer` | none (required) | Expected `iss` |
| `trust.auth.oauth.audiences` | `[trust.service.issuer]` | Accepted `aud` values |
| `trust.auth.oauth.jwks-uri` | none (required) | The authorization server's JWKS: https (cached; refreshed on an unknown `kid`), `file:` or `classpath:` |
| `trust.auth.oauth.algorithms` | `[ES256, RS256]` | Accepted algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA (Ed25519) |
| `trust.auth.oauth.token-types` | `[at+jwt, jwt]` | Accepted JOSE `typ` (`application/` prefix optional); `jwt` also admits tokens without `typ` |
| `trust.auth.oauth.client-id-claims` | `[client_id, azp]` | Claims naming the client, tried in order |
| `trust.auth.oauth.required-scope` | none | Scope every token must carry (`scope` string or `scp` array) |
| `trust.auth.oauth.clock-skew` | 60s | Tolerance for `exp` / `nbf` |
| `trust.auth.mtls.enabled` | `false` | A TLS client certificate alone authenticates its client |
| `trust.auth.mtls.certificate-header` | none | Header with the URL-encoded PEM certificate (nginx `$ssl_client_escaped_cert`) |
| `trust.auth.mtls.trusted-proxies` | `[]` | IP addresses or CIDRs of the proxies allowed to set that header |
| `trust.auth.rate-limit.enabled` | `false` | Token bucket per client (anonymous callers: per address); `429` with `Retry-After` |
| `trust.auth.rate-limit.requests-per-minute` / `burst` | 600 / 100 | Sustained rate and burst; a client's `requests-per-minute` overrides the rate |
| `trust.auth.rate-limit.exempt-admin` | `true` | Admin clients are not limited |

```yaml
trust:
  auth:
    api-keys: false                                   # production: tokens and certificates only
    oauth:
      enabled: true
      issuer: https://login.example.com/realms/trust
      jwks-uri: https://login.example.com/realms/trust/protocol/openid-connect/certs
      required-scope: trust.read
    mtls:
      enabled: true
      certificate-header: X-SSL-Client-Cert
      trusted-proxies: [10.0.0.0/8]
    rate-limit: { enabled: true, requests-per-minute: 600, burst: 100 }
  clients:
    - id: verifier-backend
      oauth-client-id: 7d0c1b2e-verifier                # the client's id at the authorization server
      certificate-sha256: ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
      requests-per-minute: 3000
    - id: ops
      api-key-sha256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8   # sha256 of the key
      admin: true
```

## Clients (who may ask, and what they see)

A client profile scopes both the service's own decisions and the snapshot the client decides from. The snapshot
carries `policy: {frameworks, strictAuthorization, requireRevocationStatus, requireSignedIssuerMetadata, allowRelaxedProfiles}`,
so the client applies the same profile on its device.

```yaml
trust:
  anonymous: { enabled: true, frameworks: [] }        # unauthenticated callers; [] = all frameworks
  clients:
    - id: demo-wallet
      api-key: demo-wallet-key                         # Authorization: Bearer <key> or X-API-Key; or api-key-sha256
      frameworks: [animo-playground, mosip-collab]      # only these frameworks are visible / trusted
      strict-authorization: false                       # true: entities without authorizations are not authorized
      require-revocation-status: false                  # true: a certificate whose revocation status is unknown is not trusted
      require-signed-issuer-metadata: false             # true: issuer metadata must be signed (x5c → credential-issuer anchor, HAIP §4.1)
      allow-relaxed-profiles: true                      # false: anchors' relaxProfile is ignored; certificate profiles are enforced
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
- `issuerMetadata.signed`: `'off'` (default), `'verify'` or `'require'`. A client profile with `require-signed-issuer-metadata`
  forces `'require'`. The metadata proxy always asks issuers for signed metadata and uses it when its signer is bound to
  the issuer (SAN) and chains to a `credential-issuer` anchor; whether that signer counts is decided per client (its
  frameworks, `allow-relaxed-profiles`, revocation). Otherwise it falls back to the JSON form with `signedMetadataVerified: false`.

Verifier backends and thin clients can use `decisions: 'service'`. See `packages/trust-client/README.md`.
