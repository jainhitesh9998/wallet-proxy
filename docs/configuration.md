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

A framework is a trust scheme; a source loads entities and anchors into one.

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
| `oid4vci-discovery` | `issuers: [url \| {url, entityId}]` | What listed issuers say about themselves (display names, the JSON-LD contexts of their credentials). It describes entities registered elsewhere and authorizes nothing |

What makes a source's content authentic differs by type:

| Sources | Authenticated by |
| --- | --- |
| `vical`, `etsi-tl`, `etsi-lote` | The list's signature, verified against the pinned signer certificates (national lists behind the EU LOTL: against the certificates the LOTL names for them). An ETSI trusted list's signature counts only as the list's own enveloped signature: directly under the root element, with a reference to that root |
| `openid-federation` | Trust chains ending at the pinned trust anchor keys |
| `x509-bundle` from the network | The pinned `sha256` of every certificate |
| `static` from an `https:` location, `ebsi-tir`, `oid4vci-discovery` | TLS to the configured host only: whoever controls that host, or its certificate, controls the content |
| `static` from `classpath:` or `file:`, `managed` | The operator: the deployment, or an admin client |

`allowUnverified` (and `allowUnpinned`) drop a list to the transport level too; they exist for test environments and
say so in the log on every load.

A list past its next update is not loaded (`allowExpired: true` loads it with a warning): an expired list may be
one from before an entry was withdrawn, served again by whoever controls its location. For the same reason a list
that is older than the one already loaded (issued earlier, or with a lower sequence number) is refused, for as long
as the service runs. A source that fails to load keeps its last good content; its state (`GET /admin/v1/sources`)
shows the error.

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
describe one party together; an id that an entity of another framework already has is listed as `<id>@<framework>`
instead, and an anchor is tied only to an entity of its own framework. A source of one framework therefore adds
nothing to what the clients of another framework are told. Put sources that should not vouch for each other's
entries into different frameworks.

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
    entity: example-issuer                # a chain to this anchor is this entity; omit for a CA shared by many parties
    certificate: "<PEM>"                  # or certificateLocation (see below)
    constraints:
      docTypes: [org.iso.18013.5.1.mDL]   # the doctypes this IACA may sign
      crlUrls: ["https://pki.example.org/iaca.crl"]   # where the CA publishes its CRL (default: the anchor's own distribution point)
      crl: "<base64 DER>"                 # or a CRL pushed by the operator; verified against the anchor
```

Entries belong to the framework of their source; a `framework` key is accepted only when it names that framework,
and an entry naming another one is skipped with a warning. `certificateLocation` may name a `classpath:` or `file:`
location only in a registry that is itself a local file; in a registry fetched over the network and in entries sent
to the admin API it must be an `https:` URL.

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
| `for.role` | `issuer`, `verifier`, `wallet_provider`, `status_list_provider`, `authorization_server`; required | The role the question asks about. A question that names no role is an issuer question, as it is everywhere else in a decision (its chain is validated in the issuer domains). A query's role is read alike on the service and on the device, with the API's other spellings (`credential_issuer`, `rp`, `as`, ...); a role that is none of them is refused, not read as no role |
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
  A property under `trust.` that binds to nothing stops the service as well, in a configuration file or an argument
  (Spring Boot leaves environment variables and system properties out of this check): mechanisms written as a map by
  id instead of a list, or a misspelt `trust.mechanism`, are refused with a message that names them
  (`The elements [trust.mechanisms.national-id.for.role, ...] were left unbound`).
  The log names the mechanisms in force when it starts (`Trust mechanisms, tried in this order: [national-id]`), and
  `GET /admin/v1/registry` lists their ids (`mechanisms`).
- **One list, from one place.** `trust.mechanisms` is a list, and Spring Boot takes a list as a whole from the
  configuration source of highest precedence that sets any of it (a profile's file, a file given with
  `spring.config.additional-location`, an argument, an environment variable): the list of a source below it is
  replaced, never merged by position or by id. Where the replaced entries name a member that the replacing ones do not,
  the service reports it as left unbound and does not start; otherwise the replacement is silent. An argument that sets
  one member of one mechanism (`--trust.mechanisms[0].x509.revocation=required`) therefore does not change that member:
  it stands for the whole list, and the service refuses to start. Write the whole list in one source. Members whose
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
| `trust.revocation.enabled` | `true` | Fetch the anchors' CRLs, check revocation in the service's decisions, ship anchor CRLs in snapshots. `false`: none of these, and both relays are off. The service's own decisions then give every certificate below the anchor the status `UNKNOWN` ("revocation checking is switched off on this service"), reported as `x509.revocation_unknown`: a warning, and an error (`NOT_TRUSTED`) for a client with `require-revocation-status: true` or under a mechanism with `revocation: required`, as on a device that can get no CRL. A certificate pinned as an anchor itself has no status |
| `trust.revocation.refresh` | `PT1H` | Anchor CRLs are fetched again at the earlier of this and their next update |
| `trust.revocation.max-crl-bytes` / `snapshot-max-crl-bytes` | 1 MiB / 256 KiB | Largest CRL fetched; largest shipped in a snapshot. A larger anchor CRL is left out, and a device then fetches it itself: for a certificate the anchor issued from the anchor's `crlUrls` (or a root's own distribution point when it lists none), or from a distribution point the certificate names. An anchor that names no location, whose certificates name none either, gives the device nowhere to look |
| `trust.revocation.fetch-anchor-crls` | `true` | Fetch each anchor's CRL from its `crlUrls` or its own distribution point. `false`: only CRLs pushed with an anchor (`constraints.crl`) are held, for a service without outbound access |
| `trust.revocation.fetch-on-demand` | `true` | The service's own decisions fetch CRLs of CAs below an anchor |
| `trust.revocation.relay-crls` / `relay-status-lists` | `true` | Serve `/api/v1/proxy/crl` and `/api/v1/proxy/status-list` |
| `trust.revocation.status-list-default-ttl` / `status-list-max-ttl` / `max-status-list-bytes` | `PT5M` / `PT1H` / 2 MiB | Relay caching and size |

Where a CRL comes from, how a certificate's status is decided on the service and on the device, and how status
lists are checked: [CRLs](trust-methods.md#crls) and [credential status lists](trust-methods.md#credential-status-lists).

### Admin API

For an admin client, under `/admin/v1`:

| Request | Does |
| --- | --- |
| `GET /sources`, `POST /sources/{id}/refresh` | Source states; load one now |
| `GET /crls` | The anchor CRLs the service holds, one entry per anchor certificate and CRL location: `issuer` (the certificate's thumbprint), `anchorIds`, `subject`, `url` (absent for a pushed CRL), `thisUpdate`, `nextUpdate`, `crlNumber`, `revoked`, `bytes`, `fetchedAt`, `nextFetch`, the last `error`, whether the CRL held is `current`, and whether it is `inSnapshots` (current and no larger than `snapshot-max-crl-bytes`). Empty with `trust.revocation.enabled: false` |
| `GET /registry`, `GET /clients` | What is loaded; the client profiles |
| `GET /managed/{entities\|anchors}` | The managed entries |
| `PUT /managed/{entities\|anchors}/{id}` | Add or replace one (body: an entity or anchor in the registry format) |
| `DELETE /managed/{entities\|anchors}/{id}` | Remove one |
| `POST /cache/clear` | Empty the proxy caches |

Changes are written to the audit log (logger `io.vctrust.trust.audit`), as are operator requests that were refused
(no credentials, or a client that is not an admin). Values a caller chose are logged as quoted JSON strings. An entry's
id is 1 to 128 letters, digits or `. _ : @ ~ -`; it is stored for the framework of the managed source and cannot name
another one.

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
