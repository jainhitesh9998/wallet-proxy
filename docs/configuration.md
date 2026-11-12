# Configuration guide

Three things are configured: the **trust service** (who may ask, what they see, where the registry comes from), the
**client library** in an app, and the **wallet core** on top of it. [architecture.md](architecture.md) explains what
the parts do; this guide says how to set them up. [trust-methods.md](trust-methods.md) takes the same settings
method by method (X.509 chains, CRLs, status lists, DIDs, issuer metadata, JSON-LD contexts) with an example to run.

- [Trust service](#trust-service): [quick start](#quick-start), [service and signing key](#service-and-signing-key),
  [clients](#clients), [authentication](#client-authentication), [frameworks and sources](#frameworks-and-sources),
  [registry format](#registry-format), [trust mechanisms](#trust-mechanisms),
  [proxy, cache and outbound HTTP](#proxy-cache-and-outbound-http),
  [revocation](#revocation), [admin API](#admin-api), [production checklist](#production-checklist)
- [Client library](#client-library)
- [Wallet core](#wallet-core)

## Trust service

All settings live under `trust.*`. The shipped
[`application.yml`](../trust-server/trust-server/src/main/resources/application.yml) holds the defaults and lists no
clients, frameworks or sources: started as it is, the service refuses every API request and its registry is empty.
Configure it with an external `application.yml`, environment variables (`TRUST_SERVICE_ISSUER=...`) or arguments
(`--trust.service.issuer=...`), as with any Spring Boot application.

Every property under `trust.` that a configuration file or an argument sets must be one the service knows, whatever
its list indices (`trust.clients[1].frameworks[0]` is the known `trust.clients[].frameworks[]`), with names read as
Spring Boot reads them (`signing-key-file`, `signingKeyFile` and `signing_key_file` are one name). Any other name,
a misspelt `trust.revocaton.enabled` say, stops the service at startup with the name and where it was written
(`trust.revocaton.enabled (from URL [file:/etc/trust/application.yml] - 3:14) is not a property this service knows`),
in every configuration source that sets it, also one whose lists a source of higher precedence replaces. Below the
maps that are read as they come (a source's `properties`, a framework's `attributes`, `trust.did.registries`, and
each trust mechanism, which [has rules of its own](#trust-mechanisms)) any name is accepted. Environment variables and
system properties are not checked: a platform that sets `TRUST_SERVICE_PORT` for a service named `trust` does not stop
it.

The demo configuration is a profile,
[`application-demo.yml`](../trust-server/trust-server/src/main/resources/application-demo.yml)
(`--spring.profiles.active=demo`; `scripts/start-trust-server.sh` and `scripts/dev-up.sh` use it): a wallet, a verifier
and an operator client with API keys that are published in this repository, the Animo playground's registry and a
managed source. It is for development on a machine of your own; the service says so in its log when it starts.

### Quick start

```sh
. scripts/env.sh
scripts/build.sh                    # builds and tests the service and the TypeScript packages
scripts/start-trust-server.sh       # http://localhost:8090 with the demo profile, data and logs in .runtime/
curl -s localhost:8090/.well-known/trust-service
curl -s -H 'Authorization: Bearer demo-wallet-key' -H 'Accept: application/jwt' localhost:8090/api/v1/snapshot
```

`scripts/dev-up.sh` additionally starts the reference issuer and verifier on loopback and lists them in the
service; see [Development setup](#development-setup).

The defaults are closed: no client exists until one is configured, requests without credentials are refused, a
client sees only the frameworks its profile names, rate limiting is on, the metadata proxy serves only registered
issuers, a signed list is loaded only when its signature verifies (see [Frameworks and sources](#frameworks-and-sources)
for what authenticates each kind of source), and nothing is fetched from private addresses or over plain http.

### Service and signing key

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.service.issuer` | `http://localhost:8090` | The service's identifier: `iss` of everything it signs. Set it to the public https URL |
| `trust.service.snapshot-ttl` | `PT24H` | Validity of a snapshot. Clients refresh hourly and may use an expired snapshot for a grace period |
| `trust.service.snapshot-recheck` | `PT1M` | How often a client's snapshot content is re-derived: DID documents and contexts change without the registry changing |
| `trust.service.signed-response-ttl` | `PT10M` | Validity of signed proxy responses |
| `trust.service.decision-ttl` | `PT1H` | Validity of the service's own decisions (`POST /api/v1/evaluate`) |
| `trust.service.snapshot-did-documents` | `true` | Resolve the listed DIDs and ship their documents in the snapshot |
| `trust.service.snapshot-max-did-documents` / `snapshot-did-deadline` | `200` / `PT5S` | Bounds on that; a document not ready in time is left out and clients look it up. The deadline also bounds the wait for JSON-LD contexts |
| `trust.service.snapshot-max-context-bytes` | `262144` | JSON-LD context documents are shipped up to this total; past it only their digests are. At most 20 contexts are taken from one entity and 200 into one snapshot |
| `trust.service.max-request-bytes` | `2097152` | Largest request body accepted (`413` beyond it). A decision request is small; an entry sent to the admin API may carry certificates and a CRL. One `x5c` is read up to 10 certificates |
| `trust.cors-origins` | `["*"]` | CORS origins for `/api/**` and `/.well-known/**` |

The service signs snapshots and proxy responses with one ES256 (P-256) key. Clients pin its RFC 7638 thumbprint,
published at `/.well-known/trust-service` (`signing_key_thumbprints`, current key first).

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.service.signing-key.type` | `jwk-file` | `jwk-file` (development), `keystore` (PKCS#12 / JKS) or `pkcs11` (HSM: the private key never leaves the token) |
| `trust.service.signing-key-file` / `signing-key.file` | `./data/signing-key.jwk` | `jwk-file`: the private JWK, generated with mode 0600 on first start |
| `trust.service.signing-key.keystore`, `keystore-type`, `password`, `key-password`, `alias` | none, `PKCS12` | `keystore`: the store, its type and passwords, the key entry |
| `trust.service.signing-key.pkcs11-config`, `pin`, `alias` | none | `pkcs11`: the SunPKCS11 configuration file, the token PIN, the key entry |
| `trust.service.signing-key.key-id` | the thumbprint | `kid` of the key |
| `trust.service.signing-key.previous-keys` | `[]` | Public JWKs of retired keys (inline JSON, a path, `file:` or `classpath:`), still published so clients can verify what they hold |

At startup the key must be EC P-256 and must sign and verify a probe; anything else stops the service with a message
naming the key source. To rotate: (1) ship the new thumbprint to clients next to the old one, (2) switch the service
to the new key and list the old public key in `previous-keys`, (3) remove it once the old snapshots have expired.

```yaml
trust:
  service:
    issuer: https://trust.example.org
    signing-key:
      type: pkcs11
      pkcs11-config: /etc/trust/pkcs11.cfg     # name = HSM; library = /usr/lib/softhsm/libsofthsm2.so; slot = 0
      pin: ${TRUST_HSM_PIN}
      alias: trust-service-2026
      previous-keys: [/etc/trust/trust-service-2025.pub.jwk]
```

### Clients

A client profile decides what a caller sees and how strictly it is served. The snapshot carries the profile
(`policy`), so the device applies the same rules.

```yaml
trust:
  clients:
    - id: wallet-app                      # the audience of everything signed for this client
      name: Wallet app
      api-key-sha256: 5e88...1542d8        # SHA-256 (hex) of the API key; or api-key: <clear text> for development
      frameworks: [eu-pid, national]       # the frameworks it sees; "*" for all; none listed means none
      strict-authorization: false          # true: an entity that lists no authorizations is authorized for nothing
      require-revocation-status: false     # true: a certificate whose revocation status cannot be determined is not trusted
      require-signed-issuer-metadata: false   # true: issuer metadata must be signed under a credential-issuer anchor (HAIP 1.0 §4.1)
      allow-unregistered-metadata: false   # true: the metadata proxy also fetches issuers that are in none of its frameworks
      requests-per-minute: 3000            # overrides the global rate
    - id: ops
      api-key-sha256: ...
      admin: true                          # may use /admin/v1/** and the non-public actuator endpoints; sees every framework
  # Requests without credentials are refused. To serve the public:
  # anonymous: { enabled: true, frameworks: [eu-pid], allow-unregistered-metadata: false }
```

### Client authentication

Every request is mapped to a client, except the public paths: `/.well-known/**` (discovery, JWKS),
`/actuator/health`, `/actuator/info` and the API description (`/v3/api-docs`, `/swagger-ui`). The methods can be
combined; `/.well-known/trust-service` lists the enabled ones.

1. **OAuth 2.0 access token** (`Authorization: Bearer <JWT>`): an RFC 9068 JWT from the operator's authorization
   server, for example from the client credentials grant. Checked: signature against the JWKS, `typ`, `iss`, `aud`,
   `exp` / `nbf`, the required scope. The client is the one whose `oauth-client-id` (default: its `id`) equals the
   token's `client_id` (or `azp`). A token with `cnf.x5t#S256` (RFC 8705) is accepted only over a connection that
   presents that TLS client certificate.
2. **TLS client certificate** (`mtls.enabled`): the client registered for the certificate's SHA-256 thumbprint. The
   certificate comes from this server's TLS connector, or from a header set by a TLS-terminating proxy, which is
   believed only when the TCP peer is one of `trusted-proxies`.
3. **API key** (`Authorization: Bearer <key>` or `X-API-Key`): development, or behind another gateway.

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.auth.api-keys` | `true` | Accept API keys |
| `trust.auth.oauth.enabled`, `issuer`, `jwks-uri` | `false` | Accept JWT access tokens of this issuer; its JWKS as an https URL (cached, refreshed on an unknown `kid`), `file:` or `classpath:` |
| `trust.auth.oauth.audiences` | the service issuer | Accepted `aud` values |
| `trust.auth.oauth.algorithms` / `token-types` | `[ES256, RS256]` / `[at+jwt, jwt]` | Accepted algorithms and JOSE `typ` values |
| `trust.auth.oauth.client-id-claims` | `[client_id, azp]` | Claims naming the client, tried in order |
| `trust.auth.oauth.required-scope` / `clock-skew` | none / `PT60S` | Scope every token must carry; tolerance for `exp` / `nbf` |
| `trust.auth.mtls.enabled` | `false` | A TLS client certificate alone authenticates its client |
| `trust.auth.mtls.certificate-header` / `trusted-proxies` | none / `[]` | Header with the URL-encoded PEM certificate (nginx `$ssl_client_escaped_cert`), and the proxies allowed to set it |
| `trust.auth.rate-limit.enabled`, `requests-per-minute`, `burst`, `exempt-admin` | `true`, `600`, `100`, `true` | Token bucket per client (anonymous callers: per address); `429` with `Retry-After` |
| `trust.auth.rate-limit.max-concurrent` | `32` | Requests one client (or anonymous address) may have in progress at once; more get `429`. One caller asking the proxy for many slow upstreams cannot occupy the service. `0`: no limit |
| `trust.auth.rate-limit.refused-per-minute` | `60` | Refused credentials per address; past it, credentials from that address are turned away unseen (`429`) until the rate allows. `0`: no limit |
| `trust.auth.trusted-proxies` | `[]` | Reverse proxies whose `X-Forwarded-For` names the caller, for per-address limits |

Failures are RFC 9457 problem details: `401` (`unauthorized`, `invalid_token`) with `WWW-Authenticate`, `403`
(`insufficient_scope`, `issuer_not_registered`), `429`, and `503 not_ready` until every required source has loaded.

### Frameworks and sources

A framework is a trust scheme; a source loads entities and anchors into one. A framework id is made of letters,
digits, `.`, `_` and `-`; any other id (in `trust.frameworks`, or as the `framework` of a source) stops the service at
startup with a message that names it, because `<id>@<framework>` is the name an entry falls back to (below) and must
belong to one framework only.

```yaml
trust:
  frameworks:
    - { id: eu-pid, name: EU PID providers, governance-uri: https://example.eu/scheme }
  sources:
    - id: pid-list              # unique
      type: etsi-lote           # the adapter (table below)
      framework: eu-pid
      refresh: PT6H             # also bounded by the list's own next update
      enabled: true
      required: true            # the service is not ready until this source has loaded once
      properties: { ... }       # adapter specific
```

| `type` | Properties | Produces |
| --- | --- | --- |
| `static` | `location` (`classpath:`, `file:`, `https:`) | Entities and anchors in the [registry format](#registry-format) |
| `managed` | none | Entities and anchors maintained through the [admin API](#admin-api), kept in the database. One per framework that is managed this way: a source loads the entries written for its framework |
| `x509-bundle` | `domain`, `certificateLocation`, optional `certificateJsonField`, `entity`, `docTypes`; `sha256` (pins: hex with or without colons, or base64url) or `allowUnpinned: true` for a remote location | Anchors from a PEM / DER bundle. A bundle fetched over the network is loaded only when every certificate matches a pin |
| `vical` | `location`, `signerCertificates` / `signerCertificateLocation`, `allowExpired`, `allowUnverified` | ISO 18013-5 VICAL: IACA anchors constrained to their doctypes, issuing authorities as entities |
| `etsi-tl` | `location`, `signerCertificates` / `signerCertificateLocation`, `followPointers`, `territories`, `serviceTypeDomains`, `includeAllServiceTypes`, `allowExpired`, `allowUnverified` | ETSI TS 119 612 trusted lists and the EU LOTL: providers as entities, service certificates as anchors |
| `etsi-lote` | `location`, `signerCertificates`, `serviceTypeDomains`, `allowExpired`, `allowUnverified` | ETSI TS 119 602 lists of trusted entities (PID, EAA, wallet, access and registration certificate providers) |
| `openid-federation` | `trustAnchor`, `trustAnchorJwks` / `trustAnchorJwksLocation`, `crawl`, `maxDepth`, `maxEntities` | Entities from validated trust chains (metadata policy applied, trust marks verified); asked on demand about unknown entity identifiers |
| `ebsi-tir` | `baseUrl`, `crawl`, `maxIssuers`, `pageSize` | EBSI Trusted Issuers Registry entries; asked on demand about `did:ebsi` issuers |
| `oid4vci-discovery` | `issuers: [url \| {url, entityId}]` | What listed issuers say about themselves (display names, the JSON-LD contexts of their credentials), merged into the entity another source of the framework lists: the one with the id `entityId`, or, for a URL alone, the one entity that lists that URL as an identifier. It describes entities registered elsewhere, authorizes nothing and never makes an entity of its own: a description that finds no such entity, or several, is left out with a warning in the source's state that names the URL and what was looked for (with a misspelt `entityId` it would otherwise be an issuer of its own, active, beside its withdrawn entry). Only display, contexts and metadata are merged in, never roles, status, validity, authorizations, identifiers or certificates |
| `mapped` | `location`, `mappingLocation` / `mapping`, `format`, `verify`, `headers`, `allowUnverified`, `allowExpired`, `publicUri`, `limits` | Entities and anchors from any trust list or registry that speaks JSON, mapped onto the registry by configuration ([mapped sources](#mapped-sources)); with a `lookup`, asked on demand about single identifiers |

What makes a source's content authentic differs by type:

| Sources | Authenticated by |
| --- | --- |
| `vical`, `etsi-tl`, `etsi-lote` | The list's signature, verified against the pinned signer certificates (national lists behind the EU LOTL: against the certificates the LOTL names for them). An ETSI trusted list's signature counts only as the list's own enveloped signature: directly under the root element, with a reference to that root |
| `openid-federation` | Trust chains ending at the pinned trust anchor keys |
| `x509-bundle` from the network | The pinned `sha256` of every certificate |
| `static` from an `https:` location, `ebsi-tir`, `oid4vci-discovery` | TLS to the configured host only: whoever controls that host, or its certificate, controls the content |
| `static` from `classpath:` or `file:`, `managed` | The operator: the deployment, or an admin client |
| `mapped` | `format: jws`: the list's signature, verified against the keys or certificates pinned in `verify` before anything of it is read. `format: json`: TLS to the configured host only, as `static` from `https:`; a local copy: the operator |

`allowUnverified` (and `allowUnpinned`) drop a list to the transport level too; they exist for test environments and
say so in the log on every load.

A list past its next update is not loaded (`allowExpired: true` loads it with a warning): an expired list may be
one from before an entry was withdrawn, served again by whoever controls its location. For the same reason a list
that is older than the one already loaded (issued earlier, or with a lower sequence number) is refused, for as long
as the service runs. A source that fails to load keeps its last good content; its state (`GET /admin/v1/sources`)
shows the error. A `static` or `managed` source fails to load when one of its entries cannot be read (see
[Registry format](#registry-format)): no entry is skipped, since a skipped entity could be the one that withdraws a
party whose CA is trusted.

What a source tells clients about where its list comes from (the `sourceUri` in the `provenance` of what it loads,
and the `trustedListUri` that `vical`, `etsi-tl` and `etsi-lote` put on their anchors and entities, which a DCQL
`trusted_authorities` entry of type `etsi_tl` is matched against) is its location only when that is an `http(s)` URL,
and then without any user information, query or fragment: a credential for fetching a list
(`https://user:secret@host/list`, `?token=...`) stays with the service.
A `file:`, `classpath:` or plain path on the service's host is not published at all. A source that loads a local copy
of a public list, such as an air-gapped service that mirrors an ETSI trusted list, names the list's public URL in
`publicUri` (an optional property of `static`, `x509-bundle`, `vical`, `etsi-tl` and `etsi-lote`): that is published
instead, so `etsi_tl` matching works for the mirror. `publicUri` must be an `http(s)` URL; anything else stops the
service with an error that names the source. The lists an EU LOTL points to are published under their own locations.

**A source speaks for its own framework only.** Everything it loads is placed in the framework it is configured
for. Entities with the same id are merged when they come from sources of the same framework, so several sources may
describe one party together: roles, identifiers, certificates and authorizations are combined, the most restrictive
status counts, and the merged entity is valid only where every entry is (the latest `validFrom` and the earliest
`validUntil` stated), so that an entry saying the registration ended is not outweighed by another that states no
end. An entry that names no role and whose status is not `ACTIVE` withdraws the party whatever it is asked about,
so the merged entity then names no role either: given the other entry's roles, it would be left out of a question
of another role, and the chain to the CA would decide. An answer a source gives on demand (an `openid-federation` or
`ebsi-tir` source, a `mapped` source's `lookup`) is merged the same way with the entity the registry lists under the
answer's id in that source's framework, where the registry lists it (`<id>@<framework>` included); an answer of an id
the framework does not list is taken as it is. Taken alone, an answer would let a party that another source of the
framework withdraws be trusted by an identifier only the answer gives it. An id that an entity of another framework already has is listed as `<id>@<framework>`
instead. A name `<id>@<framework>` (the id of a
configured framework, or of one a source loads into) belongs to that framework, so the name an entry falls back to is
always free. An entity of another framework written with such an id does not get it: it is listed under the name it
would fall back to, `<id>@<its framework>` (`acme@other` of framework `national` as `acme@other@national`), with
everything it says, since a withdrawn entity left out would no longer restrict its party. When an entry of its own
framework already holds the name an entity falls back to (for either reason; only one of its own framework can), the
two are merged as two entries of one id are, whichever is listed first, and the warning says so. An anchor written
with such an id is not loaded. The admin API refuses both
(`invalid_document`). An anchor is tied only to an entity of its own framework: its `entity` must be an id that a
source of the anchor's framework lists, as that source writes it (any source of the framework, in any order; when the
entity is listed as `<id>@<framework>`, the anchor is tied to it there). An anchor whose `entity` names no such entity
is not loaded, and its source's state names the anchor and the id, and says so when only another framework has an
entity of that id. Tied to nobody, the anchor would let a chain to the CA be trusted by itself: with the id written
another way (`Utopia-DMV` for `utopia-dmv`, or a trailing space), or another framework's, the party's entry (a
withdrawal, a limit to some credential types) would no longer restrict the CA's certificates. The same holds for the
`entity` of an `x509-bundle` source, which another source of its framework must list; and through the admin API, an
anchor written before its entity, or kept after its entity is deleted, is not loaded until the entity is there.
An entry that is not loaded for any reason, or is listed under another name, is named in a
warning of its source's state (`GET /admin/v1/sources`); of these, a source's state shows at most 50, then one line
that says how many more there are. A source of one framework therefore adds nothing to, and takes nothing from, what
the clients of another framework are told. Put sources that should not vouch for each other's entries into different
frameworks.

Anchors are not merged. Records of one anchor id in one framework (from two sources, from one list twice, or an anchor
whose fallback name `<id>@<framework>` its framework already uses) that say the same, apart from where and when they
were retrieved, load as one. When they differ in anything else (status, constraints, certificate, entity, domain),
neither is loaded, and the state of each source concerned has a warning that names them all: which record counted
would otherwise depend on the order of the sources, and the one left out could be the CA's withdrawal or constraint.
A chain to that CA is then decided as one to a CA that is not listed (`x509.no_anchor`), unless an anchor of another id
lists the same certificate.

### Registry format

Used by `static` sources and, per entry, by the admin API.

```yaml
entities:
  - id: example-issuer                    # entries with the same id from sources of one framework are merged
    roles: [CREDENTIAL_ISSUER]            # VERIFIER, WALLET_PROVIDER, AUTHORIZATION_SERVER, STATUS_LIST_PROVIDER, ...
    name: Example Issuer                  # or display: [{locale, name, description, logoUri}]
    identifiers:                          # typed, or a bare DID / URL
      - { type: URL, value: "https://issuer.example.org" }      # exactly as the issuer writes it: no normalization
      - did:web:issuer.example.org
      - { type: X509_SUBJECT, value: "CN=Example Issuer,O=Example,C=DE" }   # RFC 2253
      # also: CLIENT_ID, DNS, X509_SKI, X509_SHA256, JWK_THUMBPRINT, FEDERATION_ENTITY
    certificates: ["<PEM>"]               # signing certificates that are this entity's (pinned)
    authorizations:                       # what it may issue or request; none listed = unconstrained, unless the client is strict
      - { format: mso_mdoc, type: org.iso.18013.5.1.mDL }
      - { format: dc+sd-jwt, type: "urn:eudi:pid:1" }
    contexts:                             # JSON-LD contexts of its credentials, shipped in snapshots
      - https://issuer.example.org/contexts/v1
      - { url: "https://issuer.example.org/contexts/v2", sha256: "<base64url digest>" }   # pinned: other content is not shipped
    status: ACTIVE                        # SUSPENDED, REVOKED, EXPIRED
    validUntil: 2027-12-31T00:00:00Z
    metadataPolicy:                       # applied to the issuer's live metadata (OpenID Federation policy operators)
      oauth_authorization_server:
        token_endpoint: { value: "https://issuer.example.org/token" }
anchors:
  - id: example-iaca
    domain: mdoc-iaca                     # credential-issuer, verifier-access, wallet-provider, status-list
    entity: example-issuer                # a chain to this anchor is this entity of the same framework; omit for a CA shared by many parties
    certificate: "<PEM>"                  # or certificateLocation (see below)
    constraints:
      docTypes: [org.iso.18013.5.1.mDL]   # the doctypes this IACA may sign
      crlUrls: ["https://pki.example.org/iaca.crl"]   # where the CA publishes its CRL (default: the anchor's own distribution point); at most the first 8 count
      crl: "<base64 DER>"                 # or a CRL pushed by the operator; verified against the anchor
```

A registry holds `entities` and `anchors`, each a list, and nothing else. An entity entry has these members, and no
others:

| Member | Value |
| --- | --- |
| `id` | Text; required |
| `framework` | Text: the framework of the entry's source (see below) |
| `roles` | A list of role names, or one name: `CREDENTIAL_ISSUER`, `VERIFIER`, `WALLET_PROVIDER`, `AUTHORIZATION_SERVER`, `ACCREDITATION_AUTHORITY`, `STATUS_LIST_PROVIDER`, `OTHER` (in any case). No roles: the entry authorizes nothing, but it can still withdraw a party |
| `name` | Text: the display name in English. Not together with `display` |
| `display` | A list of `{locale, name, description, logoUri}`, each member text and optional |
| `identifiers` | A list. Each item is text (a DID, an `http(s)` URL, or else a client identifier) or `{type, value}`, both text; the types are `DID`, `URL`, `CLIENT_ID`, `DNS`, `X509_SUBJECT`, `X509_SKI`, `X509_SHA256`, `JWK_THUMBPRINT`, `FEDERATION_ENTITY`, `OTHER` |
| `certificates` | A list of certificates, each PEM (one or more `CERTIFICATE` blocks) or base64 DER |
| `certificate` | One certificate, as text |
| `certificateLocation`, `certificateJsonField` | Text: where more certificates are: a PEM bundle or DER, or with `certificateJsonField` the member of a JSON document that holds one |
| `authorizations` | A list of `{format, type, constraints}`: `format` and `type` text (absent: any), `constraints` an object |
| `contexts` | A list. Each item is a URL, or `{url, sha256}`, both text |
| `status` | `ACTIVE` (the default), `SUSPENDED`, `REVOKED`, `EXPIRED` or `UNKNOWN`, in any case |
| `validFrom`, `validUntil` | A date, as text: `2027-12-31` (midnight UTC) or `2027-12-31T00:00:00Z` |
| `metadata`, `metadataPolicy` | An object whose members, named by entity type (`openid_credential_issuer`, `oauth_authorization_server`, ...), are objects |
| `attributes` | An object |

An anchor entry has these:

| Member | Value |
| --- | --- |
| `id` | Text. Without it the anchor is named `<domain>:<SHA-256 of the certificate>`; an entry with several certificates makes one anchor of each, named `<id>-0`, `<id>-1`, ... |
| `framework` | Text, as for an entity |
| `domain` | Text; required |
| `entity` | Text: the id of the entity of the same framework that a chain to this anchor is, as a source of that framework writes it. An anchor whose `entity` no source of its framework lists is not loaded ([Frameworks and sources](#frameworks-and-sources)) |
| `certificate`, `certificates`, `certificateLocation`, `certificateJsonField` | As for an entity; at least one certificate is required |
| `status` | As for an entity; an anchor that is not `ACTIVE` vouches for nothing |
| `constraints` | An object. What the service reads from it must have its type: `docTypes` a list of doctypes, `crlUrls` a URL or a list of URLs, `crl` a CRL as text (PEM or base64 DER). One of these names written another way (`doctypes`, `DocTypes`, `doc_types`, `crl_urls`, `CRL`) cannot be read |

`metadata`, `metadataPolicy`, `attributes`, an anchor's `constraints` and an authorization's `constraints` are
free-form: their members are not checked, beyond the three of `constraints` above and that each has a value. In an
anchor's `constraints`, a member whose name is `docTypes`, `crlUrls` or `crl` once case is ignored and `-` and `_` are
removed, but is not written exactly so, is refused with the name the service reads: read as absent, `doctypes` would
leave the CA valid for every doctype. Any other name is accepted.

**Hash and key identifiers** are compared in the form the evaluators compute from a certificate or a key. Written
another way, an entry would bind nothing, and a `REVOKED` one would never apply:

| Type | Form | Written another way |
| --- | --- | --- |
| `X509_SHA256` | The SHA-256 of the DER certificate (32 bytes) in unpadded base64url, the OpenID4VP `x509_hash` value | Read as that form when it is the digest in hexadecimal (any case, with `:` between all the bytes or none, as `openssl x509 -fingerprint -sha256` prints it) or in base64 or base64url, padded or not. Anything else cannot be read |
| `X509_SKI` | The subject key identifier's bytes in unpadded base64url | Read as that form when it is in standard base64 (`A-Z a-z 0-9 + /`, with correct `=` padding or none) and holds a `+`, `/` or `=`, as ETSI trusted lists write it: padding removed, `+` as `-`, `/` as `_`. Anything else that is not unpadded base64url cannot be read: with `:` or spaces, the two alphabets mixed, wrong padding, padding on base64url, a length no encoding has. Hexadecimal without separators is base64url too and cannot be told from it: it is read as written, and matches only if it is the base64url form |
| `JWK_THUMBPRINT` | The RFC 7638 thumbprint (SHA-256) in unpadded base64url, 43 characters | Cannot be read |

The service and the library read an `X509_SHA256` or `X509_SKI` value so wherever they meet one: in the registry, in
a query (an `x509_hash` client identifier), in what an ETSI trusted list or a LoTE says (an `X509SKI` there is standard
base64), and in trust an app pins. `conformance/evaluation/identifiers.json` holds both to the same forms.

Entries belong to the framework of their source; a `framework` key is accepted only when it names that framework,
and an entry naming another one cannot be read. `certificateLocation` may name a `classpath:` or `file:`
location only in a registry that is itself a local file; in a registry fetched over the network and in entries sent
to the admin API it must be an `https:` URL.

**What cannot be read.** The format is read strictly, so that nothing is read as absent because of how it is
written: an entity written with `staus: REVOKED` would otherwise be active, and an anchor with
`docTypes: org.iso.18013.5.1.mDL` (no brackets) valid for every doctype. An entry cannot be read when:

- it has a member that is not in the tables above, or one of its identifiers, display entries, authorizations or
  contexts has a member other than theirs, or its `constraints` name `docTypes`, `crlUrls` or `crl` another way;
- a member has another type than the tables give: `roles: [7]`, an identifier that is a number, a `status` that is a
  list, a date that is a number, `certificates` that is one certificate rather than a list of them;
- a member is written without a value (`status:` with nothing after it);
- a role, status or identifier type is not one of the names above, or a date is not a date;
- an `X509_SHA256`, `X509_SKI` or `JWK_THUMBPRINT` identifier is not in a form of the table above;
- a certificate is not one, or the text of one holds anything else in PEM armour (a private key, a damaged block);
- it has `certificateJsonField` without `certificateLocation`, or both `name` and `display`;
- it names another framework, has no `id` (an entity) or no `domain` or certificate (an anchor), or is not an object.

**An entry that cannot be read fails the load.** A `static` registry with one entity or anchor that cannot be read is
not loaded at all: the source keeps what it loaded last, its state (`GET /admin/v1/sources`) has the error, and a
required source that has never loaded keeps the service not ready. The error names the entry, by its `id`, or by its
place when it has none (`anchors[2]`), and says what is wrong with it:

```text
Cannot load static registry docs/examples/trust-methods/registry.yaml: entity 'utopia-dmv' cannot be read: unknown member 'staus'; an entity has id, framework, roles, name, display, identifiers, certificates, certificate, certificateLocation, certificateJsonField, authorizations, contexts, status, validFrom, validUntil, metadata, metadataPolicy, attributes
```

A registry with a member other than `entities` and `anchors` (`entites:`) is not loaded either.

The admin API refuses such an entry (`invalid_document`), so a `managed` source meets one only when it was stored
before a rule existed; it then fails to load in the same way, and the entry can still be replaced or deleted through
the admin API. An anchor whose `certificateLocation` cannot be fetched fails the load too, so the anchor stays as it
was loaded last rather than dropping out until the next refresh.

**How to list a party so that its credentials are attributed to it.** An entity is found through what a signing key
proves, never through what a credential claims. List at least one of:

- the party's own anchor (`entity:` on the anchor), when its CA issues only to it;
- its signing certificate (`certificates`), or the certificate's subject, subject key identifier or SHA-256 hash as
  an identifier, when the CA is shared with others;
- its DID, for credentials signed with a DID key;
- for a verifier: its `x509_hash:` or `x509_san_dns:` client identifier, a DNS name of its certificate, or one of
  the above.

A credential that names a registered issuer in `iss` or `issuer` while its key is bound to nobody, or to someone
else, is refused (`identifier.unbound`).

### Mapped sources

A `mapped` source reads a trust list or registry that another service publishes as JSON, and maps it onto the
registry by configuration alone: where the document is, what authenticates it, and how its records become entities
and anchors. No code is written per format. Each record is turned into an entry in the
[registry format](#registry-format) and read by the same parser as a hand-written one, so the rules above hold for it.

```yaml
trust:
  sources:
    - id: partner
      type: mapped
      framework: partner
      refresh: PT1H
      properties:
        location: https://registry.partner.example/v1/issuers
        headers: { Authorization: "Bearer ${PARTNER_TOKEN}" }
        mappingLocation: file:/etc/trust/partner-mapping.yaml
```

| Property | Default | Meaning |
| --- | --- | --- |
| `location` | required | The document: an `https:` URL, or a local copy (`file:`, `classpath:`, a path). Only a source that does nothing but look up goes without |
| `mappingLocation` / `mapping` | one of them | The mapping: a YAML or JSON file of this host (`file:`, `classpath:` or a path, never a URL), or inline. Prefer the file: an inline mapping passes through Spring's property binding ([below](#a-mapping-inside-applicationyml)) |
| `format` | `json` | `json`, or `jws`: a compact JWS or JWT whose payload is the JSON |
| `verify.jwks` / `verify.jwksLocation` | none | For `jws`: the public keys (EC or RSA) the list is signed with, as a JWKS inline or in a `file:` / `classpath:` location. The header's `kid` chooses the key |
| `verify.certificates` / `verify.certificateLocation` | none | Or certificates (PEM or base64 DER; a PEM file) that the JWS's `x5c` chain must validate to. A signing certificate that is itself pinned signs whatever its key usage; any other must be allowed to sign: its key usage, when it has one, includes `digitalSignature`, and it is no CA certificate and no TLS server certificate (extended key usage `serverAuth`) |
| `verify.typ` | none | The JOSE `typ` the JWS must have, so that another document signed with the same key cannot pass for the list |
| `verify.issuer` | none | The `iss` the JWT must name; a document without `iss`, or with another, is refused |
| `verify.audience` | none | This service's name at the list's issuer. A JWT that names an audience (`aud`) is loaded only when it names this one |
| `allowUnverified` | `false` | Load a `jws` list without pinned keys, on the strength of TLS alone. For test environments; said in the log on every load. What needs no key is still checked: `verify.typ`, `verify.issuer`, `verify.audience`, `exp`, `nbf` |
| `allowExpired` | `false` | Load a list past its mapped `nextUpdate` or its `exp`, with a warning. It never covers a lookup answer: one past its `exp` is refused |
| `headers` | none | Sent with requests to the origin of `location` (scheme, host and port) and nowhere else; never shown in a log, a message or the source state |
| `publicUri` | none | Published as the entries' `provenance.sourceUri`. Without it an https `location` is published, and a local one is not |
| `limits.entities` / `limits.anchors` | `5000` / `1000` | More records than this fail the load |
| `limits.text` | `67108864` | What all the records of a load (or of one lookup answer) may yield: the characters of their mapped text, certificates and CRLs included, and one for every node (each value, `null`, list and object, empty or not); more fail the load. Below it, `limits.yield` bounds what a load yields by the bytes it read |
| `limits.yield` | `32` | How many times the bytes it read (over all its pages; for a lookup, the answer's) a load may yield, counted as `limits.text` counts; a whole number from 1 to 1024. At least 1,048,576 is always allowed, and `limits.text` stays a bound on top. Raise it for an honest list that states once what each of its records repeats: types at its root that every record maps (`each: ^.credential_types[*]`: 3,000 terse issuers and 30 types are refused at 32 and load at 64), or authorizations the mapping gives every record. The message of a load refused for it names `limits.yield` |
| `limits.duration` | `PT5M` | How long a load may take; one still fetching pages after that fails |

#### The mapping

```yaml
list:                                    # optional: facts about the list, read from every page
  issuer: $.publisher
  sequence: $.version                    # a whole number; a list with a lower one than the one held is refused
  issuedAt: $.issued                     # an ISO date-time or date, or seconds since the epoch
  nextUpdate: $.next_update              # past it, the list is not loaded
pages:                                   # optional: the list comes in pages, each repeating the list facts
  next: $.links.next                     # the next page's URL (may be relative), absent or empty on the last
  number: $.page                         # optional: the page's own number, first, first + 1, ...
  first: 1                               # with number: the number the first page says, 0 or 1 (default 1)
  count: $.pages                         # optional: how many pages the list has, the same on every page
  max: 50
entities:                                # one or more blocks: every match of each is one entity
  - each: $.issuers[*]
    allowEmpty: false                    # true: a document in which the block finds no record still loads
    required: [validUntil]               # members a record must yield, or it cannot be read completely
    id: { template: "partner:{$.id}" }   # required
    roles: [CREDENTIAL_ISSUER]           # required: every record must yield a role
    name: $.display.name                 # and/or display: [{ each, locale, name, description, logoUri }]
    identifiers:                         # items: type (required), value, and an each of their own if needed
      - { type: URL, value: $.credential_issuer }
      - { each: "$.dids[*]", type: DID, value: $ }
    certificates: $.signing_certificates[*]      # PEM or base64 DER
    authorizations:                      # an item lacking a member it maps cannot be read
      - { each: "$.credentials[*]", format: $.format, type: $.type }
    status: { path: $.state, values: { active: ACTIVE, suspended: SUSPENDED }, default: REVOKED }
    validFrom: $.valid_from
    validUntil: $.valid_until
    contexts: $.contexts[*]              # or items { each, url, sha256 }
    attributes: { country: $.country }
    metadataPolicy: $.metadata_policy    # an object
anchors:
  - each: $.authorities[*]
    id: $.kid
    domain: mdoc-iaca                    # required
    certificate: $.certificate           # required: one certificate, PEM or base64 DER
    entity: { template: "partner:{$.issuer_id}" }
    status: $.status
    docTypes: $.doctypes[*]
    crlUrls: $.crl_urls[*]               # as the list states them; the registry counts the first 8
    crl: $.crl
lookup:                                  # optional: ask about one party at a time (a registry too large to list)
  url: "https://registry.partner.example/v1/issuers/{identifier}"
  identifierTypes: [DID]
  startsWith: ["did:example:"]
  missStatus: [404]                      # the answers that mean "not listed"
  maxAge: PT24H                          # format: jws: how long after its iat an answer without exp counts
  entity: { ... }                        # an entities block (without allowEmpty); each defaults to the whole answer
```

Every member of the registry format that makes sense for remote data can be mapped. `certificateLocation` cannot: a
document from elsewhere never makes the service read a file. Nor can `framework`: every record of a source belongs to
the source's framework, and a mapping that names `framework` is a configuration error. `each`, `allowEmpty` and
`required` say how a block is read; `required` names members the block maps (another name is a configuration error).
A record is handed to the registry format as that format reads it: without the members that yield nothing, and with
its display entries rather than its `name` when both yield (the format takes one of them; the name stands when there
are no display entries). A record the format refuses anyway is treated as one that cannot be read completely (below).
A block of entities (and a lookup's `entity`) must map `roles`, and a record that yields none fails the load: its roles
may be a member the upstream renamed or dropped. Where the upstream writes `"roles": []` for a party it states no role
for (this service's own snapshot does, for an entry that only describes a party, or a withdrawn one), say so with
`roles: { path: $.roles[*], allowEmpty: true }`: such a record is listed without a role, as the document states it. An
entry without a role that is not in good standing keeps its party out whatever is asked; one in good standing is not
considered for any question, and the chain to the party's CA decides as if the entry were not there.

**Values.** Every member takes one of these forms; a member that takes a list takes a list of them.

| Form | Meaning |
| --- | --- |
| `$.path` | A path into the current record: the match of `each` (in an item with an `each` of its own, that match) |
| `^.path` | The same, from the root of the document |
| Any other scalar | A constant |
| `{ value: "$5" }` | A constant that starts with `$` or `^` |
| `{ path: P, values: { a: X, b: Y }, default: Z }` | The value at `P`, translated. Keys are compared without regard to case and to surrounding whitespace, the no-break space and the zero-width space included (`Revoked`, ` revoked` and `revoked` are one key); a number in the document matches a key by its value (`1.0` is the key `1`), text by its text. Two keys of one table that are the same this way are a configuration error. `default` stands for both a value not in the table and no value at `P`, for every member; without it, either yields nothing (in a list that restricts, a value not in the table cannot be read: see below). An object or a list at `P` is not translated, and not the default: the member cannot be read. `values` can also be a list of `{ when, then }` pairs |
| `{ template: "did:web:{$.host}" }` | Text with paths in braces; nothing if any of them yields nothing |
| `{ path: P, allowEmpty: true }` | For `roles` and `docTypes`, with a `[*]` or a filter in `P`: the values at `P`, and when the list is there and has no item at all, the record states none: no role, or no doctype constraint (see below). Also with `values` and `default` |

A path with `[*]` or a filter gives every match to a list member, and its first match to a single one.

**Absent is absent; what cannot be read is never left out quietly.** A path that matches nothing, `null` or an empty
string `""` leaves its member out (`valid_until: ""` is no date, and `certificates: ["", "<PEM>"]` one certificate). A
member cannot be read when its path finds something it cannot use: `[*]`, a filter or an index applied to text or a
number (doctypes written as one string under `$.doctypes[*]`), a member name applied to anything but an object, an
object or a list where text belongs (also in a template or a translation), a date that is not one. A date is an ISO
date-time with its offset (`Z`, `+01:00` or `+0100`) or an ISO date, or seconds since the epoch as a JSON number, whole,
of at most twelve digits. A time in milliseconds is not a date; nor is a string of digits (`"20991231"` and `"2099"`
would be seconds of 1970), `2025-01-01 00:00:00`, or a date-time without its offset (`2025-01-01T00:00:00`, whose
instant depends on where it was written). A member cannot be read either when:

- it is `status`, mapped, and yields nothing: no value at the path, or one the translation does not know and no
  `default`. A state the mapping does not know is not good standing; an operator who means "no status is active"
  writes `default: ACTIVE`;
- an authorization item lacks a member its mapping configures, or yields nothing at all: an authorization without its
  `type` would cover every type of its format, and none at all would leave the entity unconstrained for a lenient
  client. Unless the item says `allowAnyType: true` (its `type` a path from a member of the item, or a translation of
  one): an item that states no type then covers every type of its format, as the registry format reads it and this
  service's snapshot writes it. An item states no type only when the first member the type's path names is not there,
  or is `null` or `""` (`types` in `$.types[0]`). Once that member is there with anything else, the type is read as a
  restricting list is read, and whatever does not yield a type makes the record unreadable: `[]`, `[null]` or `{}`
  under `$.types[*]`, an index past the end, a filter that keeps nothing, an object without the member the path goes
  on to, the wrong kind, a value the translation does not know. Write it only for an upstream that means "every type"
  by no type. An item that says `allowAnyType: true` and gives its `type` a `default` is a configuration error: an item
  that states no type would get the default under one and cover every type of its format under the other;
- it is a restricting list (an `authorizations` item's `each`, an anchor's `docTypes`) that is there and yields
  nothing: `credentials: []`, `[null]` or `{}` under a mapped `authorizations`, a filter that keeps none of them, and
  the same for `docTypes`. This holds wherever the list is in the path, and for an index as for `[*]`:
  `$.doctypes[*].id` over `"doctypes": []`, `$.doctypes[0]` over `[]`, or `$.credentials[*].types[*]` over
  `"credentials": []`, restricts to nothing too; and past a list, an item that lacks the member the path goes on to
  (`[{}]` under `$.doctypes[*].id`) cannot be read. An empty list says "none", which
  is not "no restriction"; only a member that is not there at all, `null` or `""`, is absent. In a restricting list, a
  value its translation does not know (and no `default`) cannot be read either: left out, it would narrow the list
  or empty it. Unless the mapping says `allowEmpty: true` for that list: on a nested item
  (`{ each: "$.credentials[*]", allowEmpty: true, format: $.format, type: $.type }`) or on `docTypes` written as a
  path (`docTypes: { path: $.doctypes[*], allowEmpty: true }`, also with `values` and `default`), a list that is
  there and has no item at all (none but `null`) leaves the member absent. It turns "authorized for nothing" upstream
  into "no restriction" here: write it only where the upstream means "none registered" by an empty list (this
  service's own snapshot does), never where an empty list may mean that everything was withdrawn. It covers nothing
  else: a list a filter has emptied is not empty, and neither is one whose items hold `null` where the path goes on;
  a wrong kind, an item that lacks a member, or a value the translation does not know still cannot be read.
  `allowEmpty` on a member that takes a single value, on an item without an `each` of its own, on a path without a
  `[*]` or a filter, on a member where it changes nothing (`certificates`, `crlUrls`, contexts, identifier and
  display items), or with a value other than `true` or `false`, is a configuration error;
- it is a context item with `sha256` mapped that yields its `url` but no digest (or the reverse): it would be shipped
  unpinned;
- it is an identifier item that yields its `value` but no `type` (or the reverse); an item that finds nothing at all is
  absent. Display items and context URLs without what they need are left out;
- it says whom the record is about (`roles`, `certificates`, an `identifiers` item with an `each` of its own), and
  past a list or an index an item does not yield what the path goes on to: a member missing, `null`, the wrong kind
  (`$.certificates[*].certificate` over `[{"pem": ...}]`, `[{"certificate": null}]`, `[{}]` or `[null]`), or an
  identifier item of the list that yields neither its type nor its value (its members renamed upstream). A list there
  and empty states none (for `roles`, only under `allowEmpty`). Read loosely, the party would be listed without what
  ties it to its key, and its CA alone would decide;
- it says whom the record is about (`roles`, `certificates`, `identifiers` and the members of their items), and its
  path finds a list that is there and holds items, but yields nothing from them: a filter keeps none of them
  (`$.certificates[?@.use == 'sig'].pem` over `[{"usage": "sig", ...}]`, over `"use": "SIG"` or over `"use": "enc"`),
  they are `null` or `""` (`$.certificates[*]` over `[null]`), or an index selects nothing or `null`
  (`$.certificates[1]` over one certificate, `$.certificates[0]` over `[null, ...]`). The same holds for each path
  inside a `template` of such a member (`{template: "{$.certificates[0]}"}`, or an identifier's value
  `{template: "{$.hashes[0]}"}`, over `[null, ...]`): a template yields nothing when one of its paths finds nothing,
  and that is no "none stated" when the path found a list with items. Only a list that is there and
  empty (`[]`, `{}`) states none. A filter on such a member is therefore a statement about every record: a record
  none of whose items pass it fails the load;
- it is `roles`, translated, and the document holds a role the translation does not know (and no `default`); or
  `roles` under `allowEmpty`, and the list is there but yields nothing for another reason than having no item: a
  filter emptied it, or its items are `null`;
- it is named in `required` and yields nothing. This is how a renamed member upstream is caught: a `valid_until` that
  became `validUntil` would otherwise read as "no expiry";
- it holds certificates as text that holds something else in their place. A text with `-----` in it is PEM: the body
  of each `-----BEGIN CERTIFICATE-----` block must be exactly one certificate (not two one after the other, nor a
  certificate followed by other bytes), and outside the blocks a line that holds `-----` cannot be read: a damaged
  armor line (a BEGIN line written with four dashes or in lower case, a block that never ends) or a block with another
  label than `CERTIFICATE` (a key, `TRUSTED CERTIFICATE`). Nor can lines outside the blocks that consist only of
  base64 characters (a blank line among them does not part them) when what they decode to from the start of one of
  them is an X.509 certificate, ending at the end of a line or partway through one: a certificate written beside the
  blocks without its armor, which would be bound to nobody, whatever base64 line or characters stand next to it (`A`,
  `subject=/C=UT/CN=DS`, a second certificate in the same stream, which is read too). Each line is tried once, as the
  start of a certificate as long as its first bytes state; base64 lines written so that trying them would read more
  than four times their length, or call the certificate parser in vain more than 1,024 times (lines of `MAA`, each a
  SEQUENCE of two bytes), cannot be read either: they would cost seconds for one value. A certificate whose base64
  starts partway through a line, or is broken by a line of other text, is not found: write every certificate of a PEM
  text in a block of its own. Any other line outside the blocks is text that explains them, as tools write it
  (`subject=` and `issuer=` lines, `Bag Attributes`, a byte-order mark, a word, a label such as `MASTER` that decodes
  to `0x30`, a hash or a serial number), and is passed over. Any other text is a base64 value, and must be exactly one
  certificate (not two one after the other). The certificate it was would otherwise be read as the first, or passed
  over, and bound to nobody;
- a path of it selects more than 1000 nodes for the record (`null`s and values no translation knows count too), or it
  yields more than 1000 values (all the forms of the member, and the items of a nested `each`, together);
- one of its values is longer than 8,192 characters, or it would take the record beyond 65,536 characters of mapped
  text or beyond 4,096 nodes (every value, `null`, list and object counts, empty or not): a path from the root would
  otherwise repeat a long text, or a long list of `null`s, into every record. A certificate, a PEM bundle or a CRL
  may be up to 1,048,576 characters, which count toward `limits.text` but not toward the record's 65,536. Text that
  only describes the party (a `name`, a display item's member, an attribute) and is longer than 8,192 characters is
  not a reason to suspend it: it is left out with a warning, and the record is otherwise read (a logo written as a
  `data:` URI of 20,000 characters is ordinary).

What then happens depends on the record:

- **An entity whose `id`, `roles`, `identifiers` or `certificates` cannot be read**, or that yields no `id`, or no
  role (unless its roles are there and empty under `allowEmpty`), **fails the load**, with a message that names the
  block, the record and the member. These say whom the record is about. The source keeps its last good content.
- **Ids are kept as written.** One rule gives the id of an entity, of an anchor, of a lookup answer, and the id an
  anchor's `entity` names: the id exactly as the list (and the mapping's template) yields it, whenever it is plain text
  an entry can carry: 1 to 512 characters, not only white space, none of them a control, format, line separator or
  paragraph separator character, nor half of a surrogate pair standing alone (what a source state and a log line would
  show escaped). A URL, a DID with `%3A`, a name with spaces or letters outside ASCII, an email address and a base64
  key identifier are kept. So another source of the framework names a mapped party, or owns a mapped CA, by the id as
  the list writes it: a `static` registry that withdraws `https://dmv.utopia.example` withdraws the party the mapped
  list has under that id, both the record of the list (the two are one entry, merged by the registry, the stricter
  status standing) and a lookup answer of that id (merged with the registry's entry the same way, see *Lookups are
  bound to the question* below); and a mapped
  CA whose `entity` is `Utopia DMV` belongs to the entity `Utopia DMV` of whichever source of the framework lists it.
  A mapped record merges into another source's entry of the same id as any two entries do (roles, identifiers,
  certificates and authorizations are combined, the stricter status standing), so a `static` entry does not limit what
  the mapped list adds to it: an entry authorized for the mDL only and a mapped record of its id authorized for the PID
  make one party authorized for both.
  When no source of the framework lists the id a CA's `entity` names, the CA is not loaded, and the source's state
  says so ([Frameworks and sources](#frameworks-and-sources)). An id that ends in `@` and another framework's id
  (`acme@other`) is the registry's to place, under the source's framework (`acme@other@national`). The admin API's
  stricter rule for an entry's id does not apply here: an entry written through it becomes a path segment, a database
  key and a field of the audit log, and a mapped record none of these. Any other id (one with a line break or a bidi
  override in it, or longer than 512 characters) is replaced by its derived id: `sha256:` and the whole SHA-256 of
  the id as written (UTF-8), in hexadecimal; so is an id the list writes in that very form, so that no id the list
  writes can be the one another becomes. Half of a surrogate pair standing alone (`\ud800` in a JSON string) counts
  as the three bytes UTF-8 gives any other character of its range, as WTF-8 writes it: plain UTF-8 has no form for it
  and writes `?`, so `x\ud800` and `x\udc00` would be one entry. A derived id is this
  source's alone, and no other source names the party by it; nothing else about the record changes: its status is
  the one the list states, and a CA tied to such an id is tied to the entity it became. Two different ids never become
  one entry; one id twice is one entry (the strictest of its records standing). One warning a load says how many ids
  were replaced, and the first with its derived id. A message quotes an id as it quotes any text of the list: escaped,
  and cut at 40 characters.
- **An entity in which anything else cannot be read is listed `SUSPENDED`**, with what identifies it and every member
  that could be read, but none that could not, and a warning that names the record, the members and why. A status
  stricter than `SUSPENDED` that the record states (`REVOKED`, `EXPIRED`) is kept. `SUSPENDED` means here: the list
  says something about this party that this service could not read, so it is not in good standing, and its
  certificates, identifiers and anchor still find it. Leaving it out instead would leave its party to whatever anchor
  its certificate chains to, and a chain to an anchor is trusted also without an entity. An entity record has three
  outcomes only: listed as the document states it, listed not in good standing, or the load fails.
- **An anchor** that cannot be read completely, or lacks its `domain` or `certificate`, **is skipped** with a
  warning: leaving an anchor out removes trust. Unless a certificate in its text is one that another record of the
  load lists in the same domain (in any domain, when its own cannot be read): then the load fails, naming both, since
  two records about one certificate must agree, and one that cannot be read cannot be said to. Every certificate the
  text holds counts, read leniently: a block or a base64 value that holds two certificates (`[IACA‖other]`) or a
  certificate followed by other bytes, and a certificate written as bare base64 lines beside a block. A withdrawn
  `row-7` written so would otherwise leave the CA that `row-1` lists active trusted. Nor is it skipped when its text
  could not be read completely (base64 lines beside its blocks that would cost too much to try, as above): the load
  fails, naming it, since which certificate it is about cannot be told; lines written to use up the tries before the
  IACA would otherwise keep it from ever meeting `row-1`.

A block none of whose records could be read completely fails the load: the format has probably changed, and the last
good content is better than suspending everyone. A lookup answer about the identifier asked that cannot be read
completely answers with a suspended entity, not with "not found"; one whose identifying members cannot be read is a
failed lookup.

A path from the root (`^...`) is evaluated once per page, not once per record.

**Paths.** A subset of JSONPath (RFC 9535), evaluated in time linear in the size of the document:

| Syntax | Selects |
| --- | --- |
| `$`, `^` | The current record; the document |
| `.name`, `['name']` | A member (brackets for a name with characters other than letters, digits and `_`) |
| `[2]`, `[-1]` | An array element; from the end when negative |
| `[*]` | Every element of an array, every member value of an object |
| `[?@.type == 'DSC' && @.country != 'XX']` | The children for which every comparison holds; also written `[?(...)]`. `==` and `!=` compare a member of the child (`@`, `@.a.b`, `@['a']`, `@[0]`) with a string, a number, `true`, `false` or `null`; a missing member equals nothing |

There is no recursive descent (`..`), slice, function, regular expression, `||` or `!`. A path is checked when the
configuration is read.

**What the source does.**

- *Anything unknown is an error.* A property, mapping member, value form, role, status or identifier type that the
  source does not know makes every load fail, with a message that names the source and the place, shown by
  `GET /admin/v1/sources`: `Source 'partner' (mapped): mapping.entities[0]: unknown member [nmae]; known: [...]`.
- *A signed list is verified first.* With `format: jws` the signature is checked against the pinned keys before
  anything else is read: asymmetric algorithms only (ES256, ES384, ES512, PS256, PS384, PS512, and RS256, RS384,
  RS512 with keys of 2048 bits or more), never `none` or HMAC, no `crit`, the key chosen by `kid`. A JWT payload is
  held to `exp`, `nbf`, `aud` and, with `verify.issuer`, `iss`; an `iat` must be a number of seconds. Keys come from
  the configuration, never from the network: a key served next to the list proves nothing about it. The source's
  `listInfo` says `VERIFIED`; for `format: json`, `NOT_SIGNED`. With `allowUnverified` (`NOT_CHECKED`), what needs no
  key is still checked: `verify.typ`, `verify.issuer`, `verify.audience`, `exp` and `nbf`.
- *Pin the list's signer, not a CA of anything.* With `verify.certificates`, a certificate the pinned CA issues can
  sign the list when it may sign (`digitalSignature`), unless it is a CA certificate or a TLS server certificate
  (extended key usage `serverAuth`). A certificate that is itself pinned signs whatever its key usage says: the
  operator named that very key. Pin the signer's own certificate, or a CA that issues only list signers: a CA that
  also issues other certificates that may sign (TLS server certificates without an extended key usage, client
  certificates) lets each of them sign the list.
- *Freshness, when the list says it.* With `nextUpdate` mapped, a list past it is not loaded; with `issuedAt` or
  `sequence` mapped, a list older than the one held is refused, as for every source. A mapped `sequence` must be a
  whole number of at most 18 digits (a number written `5.0` is 5), since only that orders lists: `v5`, `1.2.3` or a
  19-digit value fails the load, and such a list maps `issuedAt` instead. For `format: jws`, when the mapping names no
  `issuedAt`, the JWT's `iat` is the list's: an older list is refused without any mapping. A fact the mapping names
  but the document lacks fails the load, and so does a list issued in the future. `allowExpired` loads a list past
  its `nextUpdate` or `exp`; it does not reach lookup answers, nor a list issued in the future or older than the one
  held.
- *Pages are one list.* Every page repeats the list facts the mapping names, each with the first page's value;
  otherwise the load fails (a page of an older list, or another document, is not a page of this one). Each page of a
  `jws` list is signed on its own, so a `jws` source with `pages` must map `list.sequence` or `list.issuedAt`. Equal
  facts do not show a page left out, though: whoever serves the pages can serve page 3 at page 2's address, serve
  one page twice, or end the list early. Map what the pages say about themselves: with `pages.number`, the first page
  must say `pages.first` (1, or 0 for a list that counts from 0) and each later page the next number; with
  `pages.count`, every page must say the same count, at most `pages.max`, and the pages read must be that many. Any
  difference fails the load. Only both together tie a signed list's pages: the numbers alone do not show a list ended
  early, and the count alone does not show one page served twice in place of another. A `jws` list in pages that does
  not map both loads with a warning, on every load, that its pages can be withheld; for `format: json` the transport
  is all that vouches for the pages anyway. A page is read once: the address asked and the address it was finally
  read from, after redirects, both count as read, and a page read from an address already read fails the load.
- *Headers stay with their origin.* They go with requests to the origin of `location` (for a source that only looks
  up: of `lookup.url`), not to a lookup URL elsewhere, and not after a redirect to another origin: the outbound
  client then passes on `Accept` only.
- *Bounds.* At most `limits.entities` and `limits.anchors` records and `pages.max` pages; a next page must be on the
  origin of `location` and not one already read; strict JSON (no member twice, nothing after the value), nested at
  most 32 deep, every number with at most 40 significant digits and a decimal exponent from -40 to 40 (`1e999999999`
  is eleven characters, and a gigabyte as text); for one record, at most 1000 nodes selected by a path of a member and
  1000 values of a member, at most 8,192 characters in one value (1,048,576 in a certificate, a PEM bundle or a CRL),
  65,536 characters of mapped text and 4,096 nodes in all; for the whole load (and
  for one lookup answer), at most `limits.yield` (32 unless set) times the bytes read (over all pages; at least
  1,048,576 always allowed) and at most `limits.text` characters and nodes, so that a path from the root cannot repeat
  a small document into a large registry (180 kB of `null`s yielded 100 MB); a load still fetching pages after
  `limits.duration` fails; at most 50 warnings, then their number. Past a bound of a record, that record cannot be read
  completely (above); past a bound of the load, the load fails rather than load part of a list. The documented
  examples and the four fixture lists of the tests are far inside these: their records hold a few dozen nodes, and
  they yield less than the bytes they read (the example about 0.95 times, this service's snapshot about 0.8 times),
  against the default of 32, and far less than the mebibyte always allowed. An
  anchor's `crlUrls` are mapped as the list states them; the registry counts the first 8 of an anchor of any source,
  and says in a warning of the source what it left out.
- *A mapping that produces nothing fails.* When the document has records for a block and none of them could be read
  completely, its format has probably changed: the load fails and the source keeps its last good content. So does a
  block that finds no record in any page, unless it says `allowEmpty: true`: another document of the same signer, or
  an empty answer, must not pass for a list that has emptied.
- *A source speaks for its own framework.* Everything lands in the source's framework; `framework` cannot be mapped.
- *Records with one id, or one certificate.* Records of one load that map to the same anchor id must agree on
  certificate, domain, status, entity and constraints (identical ones are one anchor); records with the same domain
  and certificate must agree on status, entity and constraints whatever their ids (a CA listed active as `row-1` and
  withdrawn as `row-7`); otherwise the load fails, naming them. So does a record about a listed certificate that
  cannot be read (above). Records with one entity id are one entity, merged by
  the registry (one entity per country, say); none of them can relax or hide what another states: each gets the
  strictest status, the latest `validFrom` and the earliest `validUntil` of them all, with a warning when they
  disagreed.
- *Lookups are bound to the question.* Only identifiers of `identifierTypes` that start with one of `startsWith`, and
  of at most 4,096 characters, are asked about, URL-encoded into the URL. An answer counts only when the entity it
  maps to carries the identifier asked about (compared as the registry compares identifiers); when several records of
  an answer do, the first holds, with the strictest status, the latest `validFrom` and the earliest `validUntil` of
  them all. When the answer's id is one that the source's last loaded list also holds (a party asked about by an
  identifier the list does not give it), the stricter status and validity of the two stand, as the registry merges two
  entries of one id: a party the list revokes is not trusted by its other identifiers. When the list's record names no
  role and is not `ACTIVE`, it withdraws the party for every role, and the answer names no role either: with its own
  roles, it would be left out of a question of another role. This holds for a kept answer as
  soon as a list is loaded; a list older than the one loaded, which the registry refuses, does not count. The registry
  then merges every answer it hands out with its own entry of the answer's id in the source's framework, as it lists
  that id (`<id>@<framework>` when another framework has the id), as two entries of one id are merged
  ([Frameworks and sources](#frameworks-and-sources)): a party that another source of the framework withdraws (a
  `static` entry `REVOKED`, with no identifier at all) is not trusted by an identifier only the answer gives it, and
  a withdrawal that names no role leaves the answer without one. Answers are
  kept for 10 minutes, misses for 1 minute and failures for 30 seconds, at most 5000 of them
  holding at most 16,777,216 characters of mapped text in all (the least recently used go first when either bound is
  reached; expired ones are dropped as new ones come). A `missStatus` is a miss; any other failure is an error. With
  `format: jws` an answer is verified like the list, and must say when it was made: one with neither `exp` nor `iat`
  is refused, one with `iat` and no `exp` counts for `lookup.maxAge` (24 hours) after `iat`, and one past its `exp`
  is refused whatever `allowExpired` says. An answer is kept no longer than it is good for: until its `exp`, or its
  `iat` plus `lookup.maxAge`, when that is sooner than the 10 minutes. `lookup.url` must not hold user information.
- *Messages name no secret and break no log line.* No message, warning, source state or log line names the query or
  fragment of a web URL (of `location`, of a page, of a lookup URL: cut up to the next whitespace), nor a header
  value. Every message and warning the source makes, and the list's issuer in `listInfo`, has its control, format
  and separator characters escaped (Unicode categories Cc, Cf, Zl and Zp: line breaks, NEL, U+2028, bidi overrides,
  zero-width characters) as `\uXXXX`, whatever it quotes (a document's values, a JWS header, a certificate's names),
  and is at most 2,000 characters long (a warning, 300). The source state and the log then show a source's error and
  warnings as the registry shows every source's: at most 500 characters, the cut marked `…[cut]`. What the source has
  escaped is not escaped again.

**What a signature does not tell apart.** A key that signs several kinds of document (a sandbox list and a production
list, a list of issuers and one of verifiers, lists and lookup answers) lets one of them stand in for another, unless
something in the document tells them apart and the source checks it: `verify.typ`, `verify.issuer`,
`verify.audience` (for documents that name an audience), or a list fact the mapping names. Ask the list's publisher
what distinguishes its documents, and pin it.

#### A mapping inside application.yml

`mapping` can be written inline, under `properties`. Spring's property binding keeps it intact except for map keys,
which keep letters, digits, `-` and `_` and lose everything else unless written in brackets. A translation table
keyed by URIs is therefore written `values: { "[https://partner.example/kinds/iaca]": mdoc-iaca }`, or as
`{ when, then }` pairs; a key that Spring has split is refused with a message that says so. Write the keys of an
inline `values:` table in quotes: Spring's YAML processing fails on an unquoted numeric key (`values: { 1: ACTIVE }`)
before this source sees it. A table whose keys are all numbers arrives as a list even quoted, and needs
`{ when, then }` pairs. A mapping file has none of these limits.

#### Examples

These are shortened from the mappings that `MappedSourceFixturesTest` runs.

A wallet backend's list of the issuers it accepts,
`{"issuers": [{"issuer_id", "credential_issuer", "display": [{"name", "language", "logo"}], "enabled"}]}`:

```yaml
entities:
  - each: $.issuers[*]                   # or $.issuers[?@.enabled == true]: disabled ones left out
    id: { template: "wallet:{$.issuer_id}" }
    roles: [CREDENTIAL_ISSUER]
    display:
      - { each: "$.display[*]", locale: $.language, name: $.name, logoUri: $.logo }
    identifiers:
      - { type: URL, value: $.credential_issuer }
    status: { path: $.enabled, values: { "true": ACTIVE }, default: SUSPENDED }
```

A certificate list in the style of the EU Digital COVID Certificate trust list,
`{"certificates": [{"certificateType", "country", "kid", "rawData"}]}`: the CAs as anchors in the domain their type
says, the document signers as one entity per country.

```yaml
anchors:
  - each: $.certificates[?@.certificateType != 'DSC']
    id: { template: "dcc:{$.kid}" }
    domain: { path: $.certificateType, values: { CSCA: mdoc-iaca, RPCA: verifier-access } }
    certificate: $.rawData
entities:
  - each: $.certificates[?@.certificateType == 'DSC']
    id: { template: "dcc:{$.country}" }  # records with one id are merged into one entity
    roles: [CREDENTIAL_ISSUER]
    certificates: [$.rawData]
```

Another trust service like this one, through its snapshot ([the claims](architecture.md#the-snapshot)): `location`
its `/api/v1/snapshot`, `headers` its API key for this service, `format: jws`, and
`verify: { jwksLocation: file:/etc/trust/upstream-jwks.json, typ: trust-snapshot+jwt, audience: <this service's client id there> }`.
A snapshot writes `"authorizations": []` for an entity with none registered, and `"roles": []` for one it states no
role for, hence `allowEmpty: true` on those lists; and an authorization without `type` for one that covers every type
of its format, hence `allowAnyType: true`.

```yaml
list: { issuer: $.iss, issuedAt: $.iat, nextUpdate: $.exp }
entities:
  - each: $.entities[*]
    id: $.id
    roles: { path: "$.roles[*]", allowEmpty: true }   # [] in a snapshot: an entry that states no role
    display:
      - { each: "$.display[*]", locale: $.locale, name: $.name, description: $.description, logoUri: $.logoUri }
    identifiers:
      - { each: "$.identifiers[*]", type: $.type, value: $.value }
    certificates: $.certificates[*].certificate
    authorizations:                      # [] in a snapshot: none registered, unconstrained unless the client is strict
      - { each: "$.authorizations[*]", allowEmpty: true, allowAnyType: true, format: $.format, type: $.type }
    status: $.status
    validUntil: $.validUntil
    metadataPolicy: $.metadataPolicy
anchors:
  - each: $.anchors[*]
    id: $.id
    domain: $.domain
    certificate: $.certificate
    entity: $.entityId
    status: $.status
    docTypes: $.constraints.docTypes[*]
    crlUrls: $.constraints.crlUrls[*]    # where each CA publishes its CRL
```

The upstream's CRLs are **not** taken from its snapshot: the `crls` claim is not read. This service fetches each CA's
CRL itself, from the locations the anchor records name (`crlUrls`, mapped above) or from the CA certificate's own
distribution point, and decides with what it fetched. An upstream whose anchors name no location and whose CA
certificates name none either gives this service no CRL for them: a certificate such a CA revoked is decided as one it
has not. So it is in the tests' fixture for this mapping (`MappedSourceFixturesTest`, fixture 3, this service's
evaluation vectors): their anchors carry their CRLs only in the snapshot (`crls`), and the two vectors that depend on
the IACA's CRL decide differently behind it.

#### The example

[`docs/examples/mapped-source`](examples/mapped-source) is a service whose only source is a partner's registry
(`partner-registry.json`, a local copy so that it runs without a network) mapped by `mapping.yaml`: issuers and a
verifier, one withdrawn and one disabled, and two CAs from the test PKI of [`conformance/pki`](../conformance/README.md).
From the repository root:

```sh
scripts/build.sh                                    # once
java -jar trust-server/trust-server/target/trust-server.jar \
  --spring.config.additional-location=docs/examples/mapped-source/application.yml       # http://localhost:8096
```

In a second terminal, at the repository root:

```sh
curl -s -H 'Authorization: Bearer ops-key' localhost:8096/admin/v1/sources \
  | jq '.[] | {id, type, lastError, entityCount, anchorCount, listInfo, warnings}'
```

```json
{
  "id": "partner",
  "type": "mapped",
  "lastError": null,
  "entityCount": 3,
  "anchorCount": 2,
  "listInfo": {
    "issuer": "Partner Registry (example)",
    "sequence": "12",
    "issuedAt": "2026-11-01T00:00:00Z",
    "nextUpdate": "2030-01-01T00:00:00Z",
    "signature": "NOT_SIGNED",
    "details": {
      "pages": 1,
      "format": "json"
    }
  },
  "warnings": []
}
```

```sh
curl -s -H 'Authorization: Bearer wallet-key' localhost:8096/api/v1/issuers \
  | jq -c '.items[] | {id, status, identifiers: [.identifiers[].value], source: .provenance.sourceUri}'
# {"id":"partner:closed-college","status":"REVOKED","identifiers":["https://college.example"],"source":"https://registry.partner.example/v1/issuers"}
# {"id":"partner:utopia-dmv","status":"ACTIVE","identifiers":["https://issuer.utopia.example"],"source":"https://registry.partner.example/v1/issuers"}
```

The source is the `publicUri`: the local path the list was read from is not published. The disabled issuer is not
there, and the withdrawn one is `REVOKED`, because the mapping's `status` has a default. The decisions, with the
helpers of [the trust methods guide](trust-methods.md#the-example) on port 8096:

```sh
x5c() { grep -v -- '-----' "conformance/pki/$1.pem" | tr -d '\n'; }
ask() { curl -s -H "Authorization: Bearer $1" -H 'Content-Type: application/json' localhost:8096/api/v1/evaluate -d "$2"; }

ask wallet-key '{"role": "issuer", "subject": {"x5c": ["'"$(x5c ds)"'"]},
  "context": {"credentialFormat": "mso_mdoc", "credentialType": "org.iso.18013.5.1.mDL"}}' | jq -c '[.decision, .summary]'
# ["TRUSTED","Trusted credential issuer 'Utopia DMV' in framework 'partner'"]
ask wallet-key '{"role": "verifier", "subject": {"identifier": "x509_san_dns:verifier.example", "x5c": ["'"$(x5c rp)"'"]},
  "context": {"responseUri": "https://verifier.example/response"}}' | jq -c '[.decision, .summary]'
# ["TRUSTED","Trusted verifier 'Verifier Inc' in framework 'partner'"]
ask wallet-key '{"role": "issuer", "subject": {"identifier": "https://college.example"}}' | jq -c '[.decision, .summary]'
# ["NOT_TRUSTED","Entity 'partner:closed-college' is REVOKED"]
ask wallet-key '{"role": "issuer", "subject": {"identifier": "https://sandbox.example"}}' | jq -c '[.decision, .summary]'
# ["UNKNOWN","No trust information found for the subject in accepted frameworks"]
```

### Trust mechanisms

A trust mechanism is a rule for a class of questions: which proof of key is accepted for them, which trust anchors
count, what the certificate must look like, and whether its revocation status must be known. Trust is decided on the
device, so a mechanism is data: every snapshot carries the mechanisms, and the library applies them exactly as the
service's own evaluator does (the [evaluation vectors](architecture.md#conformance) hold the two alike).
[Trust methods](trust-methods.md#your-own-mechanisms) works through an example.

```yaml
trust:
  mechanisms:
    - id: national-id                        # reported in every decision it governs (evidence.mechanism)
      for:                                   # the questions it governs; every member given must match
        role: issuer                         # issuer | verifier | wallet_provider | status_list_provider | authorization_server
        formats: [mso_mdoc]                  # credential formats; omitted: any
        types: ["org.example.id.*"]          # doctype / vct / VC type: exact, or a prefix ending in *; omitted: any
      keys: [x5c]                            # the proofs of key accepted: x5c, did, jwk; omitted: all
      x509:
        domain: national-id                  # the trust domain whose anchors count (instead of the default one)
        profile:                             # requirements on the chain, on top of the built-in ones
          leaf:
            ca: false
            key-usage: [digitalSignature]
            extended-key-usage: ["1.3.6.1.4.1.99999.1.1"]
            same-country-as-anchor: true
            max-validity-days: 1100
            crl-distribution-point: true
          max-intermediates: 0
        revocation: required                 # an unknown revocation status is an error for every client
    - id: diplomas
      for: { role: issuer, formats: [ldp_vc], types: [UniversityDegreeCredential] }
      keys: [did]
      did:
        methods: [web]                       # the DID methods accepted for a DID key; omitted: any
```

| Member | Values | Meaning |
| --- | --- | --- |
| `id` | 1 to 128 letters, digits or `. _ : @ ~ -`; unique | Named in the evidence of every decision the mechanism governs (`evidence.mechanism`, on the service and on the device) |
| `for.role` | `issuer`, `verifier`, `wallet_provider`, `status_list_provider`, `authorization_server`; required | The role the question asks about. A question that names no role is an issuer question, as it is everywhere else in a decision (its chain is validated in the issuer domains). So is, when no mechanism of its own role matches it, a question about another role whose chain is validated in the issuer domains (`authorization_server`, `accreditation_authority`, `other`): a mechanism of its own role governs it first, and otherwise the issuer mechanisms are tried with its format and types, so that naming another role does not get a chain past them. Questions about a verifier, a wallet provider or a status list provider are governed by mechanisms of their role only. A query's role is read alike on the service and on the device, with the API's other spellings (`credential_issuer`, `rp`, `as`, ...); a role that is none of them is refused, not read as no role |
| `for.formats` | `mso_mdoc`, `dc+sd-jwt` (also written `vc+sd-jwt`), `ldp_vc`, `jwt_vc_json`, `jwt_vc_json-ld`; only with `role: issuer` | Compared in their canonical spelling. A question that names no format matches only a mechanism without `formats`. A question about anyone but an issuer names no format, so a mechanism for another role that lists formats is refused |
| `for.types` | A type, or a prefix followed by `*` (printable ASCII, no spaces, `*` only at the end); only with `role: issuer` | A question matches when any type it asserts matches: its doctype, vct or type, and for a W3C credential every type in `credentialTypes`, so that listing the types in another order does not get a question past a mechanism. A question that asserts no type matches only a mechanism without `types`. As with `formats`, a mechanism for another role that lists types is refused |
| `keys` | `x5c`, `did`, `jwk` | A key presented another way (an `x5c` chain, a DID key, a bare JWK) is refused. A `kid` relative to a DID identifier (`#key-1`) is a DID key of that DID, here and for `did.methods`. A question without key material (an identifier alone, as with a credential offer) is still a registry lookup |
| `x509.domain` | A trust domain as anchors name it (lower case, no spaces) | The anchors of that domain, in the client's frameworks, are the ones that count; the default domain's do not. Omitted: the default domain |
| `x509.profile` | The members below | Requirements on the chain, each a check of its own |
| `x509.revocation` | `required` | An unknown revocation status is an error, whatever the client profile says. Omitted: the client profile decides |
| `did.methods` | DID method names (`web`, `key`, `jwk`, ...) | A DID key of another method is refused |

The certificate profile of a mechanism:

| Member | Requirement | Code |
| --- | --- | --- |
| `leaf.ca: false` | The signing certificate is not a CA | `profile.leaf_is_ca` |
| `leaf.key-usage: [..]` | The key usage extension is present and asserts every listed bit (`digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`) | `profile.key_usage` |
| `leaf.extended-key-usage: [oid..]` | Every listed OID is among the extended key usages | `profile.extended_key_usage` |
| `leaf.same-country-as-anchor: true` | Leaf and anchor both name a country (the subject's first `C` attribute that is text), and it is the same, compared exactly | `profile.country` |
| `leaf.max-validity-days: n` | The leaf's notAfter is at most `n` days (1 to 36500) after its notBefore | `profile.validity` |
| `leaf.crl-distribution-point: true` | The leaf names an http(s) CRL distribution point | `profile.crl_distribution_point` |
| `max-intermediates: n` | At most `n` (0 to 9) CA certificates between the leaf and the anchor | `profile.path_length` |

Each of these reads what the service's and the library's certificate parsers read alike, so that both reach the same
decision from the same chain. There is no member for anything else of a certificate.

How mechanisms apply:

- **The first that matches governs.** Mechanisms are tried in the order they are listed; the first whose `for`
  matches governs the question. A question that none matches is decided exactly as without mechanisms. **List the
  strictest mechanism first.** A question matches by any type it asserts, so a W3C credential that asserts a type of a
  lenient mechanism listed early and a type of a strict one listed later is governed by the lenient one, and the strict
  one never applies to it; the same holds for a broad mechanism (no `types`, or a prefix) listed before a narrow one.
- **A mechanism only tightens.** Everything built in keeps applying to a governed question: RFC 5280 validation, the
  built-in certificate profile of the question, the anchor's `docTypes`, what binds a certificate to the question (the
  DNS name of an `x509_san_dns` client identifier, `x509_hash`), DID relationships, identifier binding, the entity's
  standing and authorizations. A mechanism adds requirements and chooses which anchors count; none of its members
  switches a built-in check off. The built-in profile follows the question (its role and format: an mDL signer still
  needs the mDL extended key usage), also when `x509.domain` names a domain of your own; see the table in
  [X.509 chains](trust-methods.md#x509-chains).
- **The governing domain's anchors, and nothing else.** Under a mechanism with an `x509` block, a certificate counts
  only through a chain that validates to an anchor of the governing domain (`x509.domain`, or the question's default
  domain when the block names none). A chain outside that domain is `UNKNOWN` (`x509.no_anchor`), whatever the
  default domain would have said about it: trusted, revoked or anything else. A pin does not replace the anchor: an
  entity that lists the certificate (`certificates`, an `X509_SHA256` identifier, an `x509_hash` client identifier)
  is not found through the pin alone, and the answer is `NOT_TRUSTED` (`mechanism.anchor_required`), because the pin
  would bring the certificate past the mechanism's profile and revocation rule. A pinned certificate that also chains to
  an anchor of the governing domain is accepted, under every requirement. A certificate that is itself an anchor of
  the governing domain validates as before, and the mechanism's profile applies to it. A mechanism without an `x509`
  block changes nothing about pins.
- **Nothing is ignored.** The service reads `trust.mechanisms` at startup and refuses to start on an unknown member
  (member names are kebab-case, as everywhere under `trust.*`), an unknown value, a duplicate id, an empty list or
  block, or a member that would never apply (an `x509` block when `keys` does not accept `x5c`, a `did` block when it
  does not accept `did`). The message names the mechanism:
  `Trust mechanism trust.mechanisms[0] ('national-id'): x509 is given, but keys does not accept x5c: it would never apply`.
  A property under `trust.` that the service does not know stops it as well, in a configuration file or an argument
  (see [Trust service](#trust-service)): `trust.mechanisms` is a list, so mechanisms written as a map by id are refused
  (`trust.mechanisms.national-id.for.role (from ...) is not a property this service knows: trust.mechanisms is a list,
  and 'national-id' is not an index`), and so is a misspelt `trust.mechanism`.
  The log names the mechanisms in force when it starts (`Trust mechanisms, tried in this order: [national-id]`), and
  `GET /admin/v1/registry` lists their ids (`mechanisms`).
- **One list, from one place.** `trust.mechanisms` is a list, and Spring Boot takes a list as a whole from the
  configuration source of highest precedence that sets any of it (a profile's file, a file given with
  `spring.config.additional-location`, an argument, an environment variable): the list of a source below it is
  replaced, never merged by position or by id. So is every list under `trust.` (`clients`, `sources`, a client's
  `frameworks`, ...). What the replaced list's entries set is left behind and not used, also members that the
  replacing entries do not name: the service starts with the replacing list. The check of names does not count list
  indices, so what is left behind is not refused, while a name the service does not know is refused in whichever source
  it is written. An argument that sets one member of one mechanism (`--trust.mechanisms[0].x509.revocation=required`)
  therefore does not change that member: it stands for the whole list, a mechanism with that member alone, and the
  service refuses to start (`Trust mechanism trust.mechanisms[0]: id is required`). Write the whole list in one source. Members whose
  names are kebab-case (`key-usage`, `extended-key-usage`, `same-country-as-anchor`, `max-validity-days`,
  `crl-distribution-point`, `max-intermediates`) cannot be set through environment variables: a variable's name
  carries no `-`, so `TRUST_MECHANISMS_0_X509_PROFILE_MAXINTERMEDIATES` names a member `maxintermediates`, which the
  service refuses (`x509.profile.maxintermediates is not a member this service knows`). Give mechanisms in a
  configuration file.

| Code | Meaning |
| --- | --- |
| `mechanism.key_not_accepted` | The key is presented in a way the governing mechanism's `keys` does not list: `NOT_TRUSTED` |
| `mechanism.did_method_not_accepted` | A DID key of a method the governing mechanism's `did.methods` does not list: `NOT_TRUSTED` |
| `mechanism.anchor_required` | A certificate an entity pins, without a chain to an anchor of the governing domain, under a mechanism with an `x509` block: `NOT_TRUSTED` |
| `profile.leaf_is_ca`, `profile.key_usage`, `profile.extended_key_usage`, `profile.country`, `profile.validity`, `profile.crl_distribution_point`, `profile.path_length` | A member of `x509.profile` is not met (table above): `NOT_TRUSTED` |
| `x509.revocation_unknown` | With `revocation: required`, an error for every client, not only one with `require-revocation-status` |
| `x509.no_anchor` | No anchor of the governing domain issued the chain: `UNKNOWN`, also when the default domain lists its CA |

**The snapshot format.** The mechanisms travel in the snapshot claim `mechanisms` (camelCase: `keyUsage`,
`maxValidityDays`, ...), and a snapshot that carries them is `format: 5`. A service with none configured issues
`format: 4` without the claim, exactly as before, so that deployments that do not use mechanisms keep working with the
libraries they have. `/.well-known/trust-service` says which format the service issues (`snapshot_format`). A library
that predates mechanisms refuses a format 5 snapshot ("Snapshot format 5 is not the format 4 this client reads: update
the client or the service") and decides from pinned trust instead; one that knows them refuses a snapshot with a
mechanism member or value it does not know, rather than apply part of a rule. **Update the clients before you
configure the first mechanism.**


### Proxy, cache and outbound HTTP

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.cache.metadata-min-ttl` / `metadata-max-ttl` | `PT1M` / `PT1H` | Clamp for the upstream `Cache-Control` of issuer metadata |
| `trust.cache.did-ttl` / `context-ttl` | `PT15M` / `PT24H` | DID documents; JSON-LD contexts (a changed context is logged) |
| `trust.cache.relay-contexts` | `true` | Serve `/api/v1/proxy/context`: JSON-LD contexts a snapshot does not carry, byte for byte from this cache. Only a JSON object with `@context` within `max-document-bytes` is passed on. The relay vouches for nothing: a device holds each context to the digest its snapshot carries |
| `trust.cache.negative-ttl` | `PT30S` | How long a failure is remembered, and a failed refresh not retried |
| `trust.cache.stale-if-error` | `PT24H` | How long a stale entry may be served while the upstream is down |
| `trust.cache.max-bytes` / `max-document-bytes` | 32 MiB / 1 MiB | Bound on each cache; largest document held |
| `trust.http.connect-timeout`, `read-timeout`, `total-timeout` | `PT5S`, `PT15S`, `PT60S` | Outbound timeouts; the total includes the body |
| `trust.http.max-response-bytes` / `max-redirects` | 8 MiB / `3` | Caps on a fetch |
| `trust.http.allow-private-networks` | `false` | Allow private, loopback and link-local addresses. Development only |
| `trust.http.allowed-private-hosts` | `[]` | Hosts exempt from that check |
| `trust.http.http-allowed-hosts` | `[]` | Hosts that may be fetched over plain http (also for `did:web`). Development only |
| `trust.did.registries.<method>` | `ebsi: ...` | DID methods resolved through an HTTP registry (`{did}` placeholder). `did:key`, `did:jwk` and `did:web` are native |
| `trust.did.universal-resolver-url` / `universal-resolver-methods` | none / `["*"]` | A DIF Universal Resolver for other methods; none is contacted unless configured |

Everything the service fetches goes through one guarded client: https only (plain http for `http-allowed-hosts`
and for CRL distribution points, whose content is signed); a host is resolved once per connection and refused if
any address is loopback, private, link-local, CGNAT, unique-local, multicast or reserved, including IPv4 embedded in
NAT64 or 6to4 addresses; the socket connects only to the addresses that passed; proxy settings are ignored. The
size and time caps end a fetch: a response that is too large or too slow is dropped, not read to its end, and a
refusal does not say which address a host resolved to.

### Revocation

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.revocation.enabled` | `true` | Fetch the anchors' CRLs, check revocation in the service's decisions, ship anchor CRLs in snapshots. `false`: none of these, and both relays are off. The service's own decisions then give every certificate below the anchor the status `UNKNOWN` ("revocation checking is switched off on this service"), reported as `x509.revocation_unknown`: a warning, and an error (`NOT_TRUSTED`) for a client with `require-revocation-status: true` or under a mechanism with `revocation: required`, as on a device that can get no CRL. The check of the signer of signed issuer metadata behaves the same way: for a client with `require-revocation-status: true` the signer's unknown status is an error, so the metadata proxy does not count the signed metadata as verified for it, and answers `422 signed_metadata_required` when the client also has `require-signed-issuer-metadata: true`. A certificate pinned as an anchor itself has no status |
| `trust.revocation.refresh` | `PT1H` | Anchor CRLs are fetched again at the earlier of this and their next update |
| `trust.revocation.max-crl-bytes` / `snapshot-max-crl-bytes` | 1 MiB / 256 KiB | Largest CRL fetched; largest shipped in a snapshot. A larger anchor CRL is left out, and a device then fetches it itself: for a certificate the anchor issued from the anchor's `crlUrls` (or a root's own distribution point when it lists none), or from a distribution point the certificate names. An anchor that names no location, whose certificates name none either, gives the device nowhere to look |
| `trust.revocation.fetch-anchor-crls` | `true` | Fetch each anchor's CRL from its `crlUrls` or its own distribution point. `false`: only CRLs pushed with an anchor (`constraints.crl`) are held, for a service without outbound access |
| `trust.revocation.fetch-on-demand` | `true` | The service's own decisions fetch CRLs of CAs below an anchor |
| `trust.revocation.relay-crls` / `relay-status-lists` | `true` | Serve `/api/v1/proxy/crl` and `/api/v1/proxy/status-list` |
| `trust.revocation.status-list-default-ttl` / `status-list-max-ttl` / `max-status-list-bytes` | `PT5M` / `PT1H` / 2 MiB | Relay caching and size |

Where a CA publishes its CRL is configured per framework. For one framework and one anchor certificate, the CRL
locations are those the framework's anchor records of the certificate name (`constraints.crlUrls`, a CRL pushed
with `constraints.crl`), and when they name none and the certificate is self-issued, its own distribution point. An
anchor record of another framework for the same certificate does not enter: its locations are for its own
framework's clients. A client's snapshot carries the CRLs of the frameworks it sees, and the service's own decisions
for that client (`POST /api/v1/evaluate`) use the same CRLs, besides those it fetches for CAs below an anchor. When
several CRLs count for one certificate, a revocation in any of them stands and otherwise the newest decides, on the
service as on the device.

Where a CRL comes from, how a certificate's status is decided on the service and on the device, and how status
lists are checked: [CRLs](trust-methods.md#crls) and [credential status lists](trust-methods.md#credential-status-lists).

### Admin API

For an admin client, under `/admin/v1`:

| Request | Does |
| --- | --- |
| `GET /sources`, `POST /sources/{id}/refresh` | Source states; load one now |
| `GET /crls` | The anchor CRLs the service holds, one entry per anchor certificate and CRL location: `issuer` (the certificate's thumbprint), `anchorIds`, `frameworks` (the frameworks whose anchor records name this location: their clients get this CRL and are decided by it), `subject`, `url` (absent for a pushed CRL), `thisUpdate`, `nextUpdate`, `crlNumber`, `revoked`, `bytes`, `fetchedAt`, `nextFetch`, the last `error`, whether the CRL held is `current`, and whether it is `inSnapshots` (current and no larger than `snapshot-max-crl-bytes`). Empty with `trust.revocation.enabled: false` |
| `GET /registry`, `GET /clients` | What is loaded; the client profiles |
| `GET /managed/{entities\|anchors}` | The managed entries |
| `PUT /managed/{entities\|anchors}/{id}` | Add or replace one (body: an entity or anchor in the registry format) |
| `DELETE /managed/{entities\|anchors}/{id}` | Remove one |
| `POST /cache/clear` | Empty the proxy caches |

Changes are written to the audit log (logger `io.vctrust.trust.audit`), as are operator requests that were refused
(no credentials, or a client that is not an admin). Values a caller chose are logged as quoted JSON strings. An entry's
id is 1 to 128 letters, digits or `. _ : @ ~ -`; it is stored for the framework of the managed source and cannot name
another one.

While a managed source fails to load because of an entry it cannot read (one stored before a rule existed: see
[Registry format](#registry-format)), the source keeps what it loaded last. Writes are still accepted and stored, but
none of them takes effect, a new `REVOKED` entry included, until that entry is replaced or deleted: the source then
loads again, with everything stored. `GET /admin/v1/sources` shows the source's error, which names the entry.

### Production checklist

- `trust.service.issuer` is the public https URL; TLS terminates at the service or at a proxy named in the
  `trusted-proxies` settings.
- The signing key is in a keystore or an HSM; the app ships its thumbprint (and the next one before a rotation).
- `trust.auth.api-keys: false`; clients authenticate with access tokens or certificates; no `api-key` in clear.
- Every client names its frameworks; `anonymous` stays off unless the lists are meant to be public.
- Not the `demo` profile: its API keys, the admin key included, are public.
- No `allowUnverified`, `allowUnpinned`, `allowExpired`, `allow-private-networks` or `http-allowed-hosts`.
- A real database instead of the file-based H2 default (`spring.datasource.*`), and `/actuator/health` for probes.
  The health endpoint is public and says `UP` or `DOWN` only; source states and their errors are at
  `GET /admin/v1/sources` (`management.endpoint.health.show-details: always` shows them at the health endpoint too,
  for a service that is reachable from a private network only).

### Development setup

```sh
scripts/dev-up.sh      # trust service + reference issuer (:8791) and verifier (:8792), listed in the service
scripts/dev-down.sh
```

`dev-up.sh` starts the service with the `demo` profile and `--trust.http.allow-private-networks=true --trust.http.http-allowed-hosts=localhost`,
because the reference issuer lives on `http://localhost`, and runs `scripts/register-reference.mjs`, which lists the
issuer and verifier through the admin API (framework `reference`).

## Client library

```ts
import { createTrustClient, KeyValueCacheStore } from '@vctrust/trust-client';

const trust = createTrustClient({
  service: {
    url: 'https://trust.example.org',
    clientId: 'wallet-app',                       // the audience of everything the service signs for this app
    apiKey: '...',                                // or put a token in front with http.fetch
    keys: { thumbprints: ['WwQ9...3TL4'] },       // from /.well-known/trust-service, shipped with the app
  },
  pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },   // decides only while no snapshot is usable
  storage: new KeyValueCacheStore(AsyncStorage),  // snapshot, pinned keys, cached documents
});

await trust.evaluateIssuer({ credentialIssuer: 'https://issuer.example.org', format: 'mso_mdoc', type: 'org.iso.18013.5.1.mDL' });
await trust.getIssuerMetadata('https://issuer.example.org');
await trust.status();
```

| Option | Default | Meaning |
| --- | --- | --- |
| `service.url`, `clientId`, `apiKey` | none | The trust service and the client this app is registered as. Without `service` the client runs on the standard mechanisms and the pinned trust alone |
| `service.keys` | required with `service` | `thumbprints` (RFC 7638) or `jwks` of the service's signing keys. `trustOnFirstUse: true` pins the first key seen: development only |
| `pinned.anchors`, `pinned.entities` | none | Trust bundled with the app. Used only while no snapshot is usable; with a snapshot the service is the authority, and a pinned anchor does not override it. Pinned trust has no rules of its own: it is decided under the rules in force (`policy`). A pinned anchor's `constraints.crlUrls` say where its CA publishes its CRL, which is then fetched per `lookups.crl` as for an anchor of the snapshot |
| `policy` | none | The app's own minimum rules: `{ requireRevocationStatus, strictAuthorization, requireSignedIssuerMetadata }`, each `true` or `false`, in force for every decision with or without a snapshot. Each rule in force is the stricter of this and the client profile of the last snapshot that verified, which stays in force when no snapshot is usable (also after a restart, with the same `storage`). An unknown key is an error. `status().rules` reports the rules in force |
| `mechanisms` | none | The app's own [trust mechanisms](#trust-mechanisms), in the form of the snapshot claim (camelCase: `keyUsage`, `maxValidityDays`, ...), read as strictly: an unknown member or value is an error. In force only while no snapshot has ever verified (with the same `storage`): once one has, its mechanisms are the ones in force, also when it has none, and they stay in force for pinned trust when no snapshot is usable. Unlike the flags of `policy` they do not combine with the service's: an ordered list has no "stricter of the two". `status().mechanisms` lists the mechanisms in force, next to the flags in `status().rules`; the list and its mechanisms are frozen, so changing them puts nothing in force |
| `lookups` | `'proxy'` with a service | `'proxy'`, `'direct'`, or per kind: `{ metadata, did, crl, statusLists, contexts, unknownParties }`. `crl` may also be `'none'`. `contexts`: JSON-LD contexts the snapshot does not carry, held either way to the digest the snapshot carries (one it does not know is `vouched: false`). `unknownParties: true` asks the service about parties absent from the snapshot (off by default: it tells the service which party) |
| `issuerMetadata.signed` | `'off'` | `'verify'` uses signed issuer metadata when the issuer has it, `'require'` refuses issuers without it. A client profile with `require-signed-issuer-metadata`, or `policy.requireSignedIssuerMetadata`, forces `'require'` |
| `snapshot.refreshMs`, `retryMs`, `graceMs` | 1 h, 30 s, 7 d | Refresh interval; wait after a failed refresh; how long an expired snapshot may still be used |
| `http.fetch`, `timeoutMs`, `retries`, `backoffMs`, `circuitBreaker` | platform `fetch` | Transport |
| `http.insecureHosts` | `[]` | Hosts that may be reached over plain http. Loopback development only; everything else must be https |
| `storage` | in memory | A `CacheStore`; `KeyValueCacheStore` adapts AsyncStorage, localStorage and the like |
| `clock`, `logger` | system | For tests and diagnostics |

What comes back says where it came from: a decision's `source` is `snapshot` or `pinned`, with the snapshot it was
made from; a looked-up document's `source` is `snapshot`, `proxy`, `direct`, `fallback` or `cache`.
`status()` and `onStatusChange()` report the service state, the snapshot in use, the last refresh error and whether
decisions are degraded. See [`packages/trust-client/README.md`](../packages/trust-client/README.md).

## Wallet core

```ts
import { Wallet, SoftwareKeyStore, KeyValueCredentialStore } from '@vctrust/wallet-core';

const wallet = new Wallet({
  trust,                                         // every trust decision and lookup goes through it
  keyStore: new SoftwareKeyStore(),
  credentials: new KeyValueCredentialStore({ get: (k) => AsyncStorage.getItem(k), set: (k, v) => AsyncStorage.setItem(k, v),
    remove: (k) => AsyncStorage.removeItem(k) }),
  redirectUri: 'https://wallet.example.org/callback',
});
```

| Option | Default | Meaning |
| --- | --- | --- |
| `trust`, `keyStore`, `credentials`, `redirectUri` | required | The trust client; holder keys; credential storage; the redirect of authorization code flows |
| `clientId`, `registrations` | none | A public client id, or pre-registered clients per issuer (`{ clientId, redirectUri, usePar }`) |
| `attester` | none | The wallet provider: wallet attestations (`attest_jwt_client_auth`) and key attestations |
| `walletAttestation`, `keyAttestation` | `'auto'` | `'auto'` (when the issuer asks), `'always'`, `'never'` |
| `dpop` | `'auto'` | DPoP-bound tokens when the authorization server supports them |
| `batchSize` | `1` | Instances to request of each credential from issuers with batch issuance; each is bound to its own key and presented to a different verifier |
| `deferredWaitSeconds` | `30` | How long to wait for a deferred credential before keeping it as pending |
| `encryption` | `'required'` | Credential request / response encryption only when the issuer requires it, or `'preferred'` whenever it offers it |
| `insecureHosts` | `[]` | Hosts that may be reached over plain http (a local issuer or verifier in development) |

The wallet's rules are not configurable: only OpenID4VCI 1.0 and OpenID4VP 1.0 messages, https everywhere, an
issuer the trust layer refuses is turned away, an unknown one needs the user's confirmation
(`session.confirmUnknownIssuer()`), and a credential that fails verification is refused.
