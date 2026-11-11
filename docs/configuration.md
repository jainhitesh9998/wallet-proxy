# Configuration guide

Three things are configured: the **trust service** (who may ask, what they see, where the registry comes from), the
**client library** in an app, and the **wallet core** on top of it. [architecture.md](architecture.md) explains what
the parts do; this guide says how to set them up.

- [Trust service](#trust-service): [quick start](#quick-start), [service and signing key](#service-and-signing-key),
  [clients](#clients), [authentication](#client-authentication), [frameworks and sources](#frameworks-and-sources),
  [registry format](#registry-format), [proxy, cache and outbound HTTP](#proxy-cache-and-outbound-http),
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

### Proxy, cache and outbound HTTP

| Property | Default | Meaning |
| --- | --- | --- |
| `trust.cache.metadata-min-ttl` / `metadata-max-ttl` | `PT1M` / `PT1H` | Clamp for the upstream `Cache-Control` of issuer metadata |
| `trust.cache.did-ttl` / `context-ttl` | `PT15M` / `PT24H` | DID documents; JSON-LD contexts (a changed context is logged) |
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
| `trust.revocation.enabled` | `true` | Fetch the anchors' CRLs, check revocation in the service's decisions, ship anchor CRLs in snapshots |
| `trust.revocation.refresh` | `PT1H` | Anchor CRLs are fetched again at the earlier of this and their next update |
| `trust.revocation.max-crl-bytes` / `snapshot-max-crl-bytes` | 1 MiB / 256 KiB | Largest CRL fetched; largest shipped in a snapshot (clients fetch larger ones through the proxy) |
| `trust.revocation.fetch-on-demand` | `true` | The service's own decisions fetch CRLs of CAs below an anchor |
| `trust.revocation.relay-crls` / `relay-status-lists` | `true` | Serve `/api/v1/proxy/crl` and `/api/v1/proxy/status-list` |
| `trust.revocation.status-list-default-ttl` / `status-list-max-ttl` / `max-status-list-bytes` | `PT5M` / `PT1H` / 2 MiB | Relay caching and size |

### Admin API

For an admin client, under `/admin/v1`:

| Request | Does |
| --- | --- |
| `GET /sources`, `POST /sources/{id}/refresh` | Source states; load one now |
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
| `pinned.anchors`, `pinned.entities` | none | Trust bundled with the app. Used only while no snapshot is usable; with a snapshot the service is the authority, and a pinned anchor does not override it |
| `lookups` | `'proxy'` with a service | `'proxy'`, `'direct'`, or per kind: `{ metadata, did, crl, statusLists, unknownParties }`. `crl` may also be `'none'`. `unknownParties: true` asks the service about parties absent from the snapshot (off by default: it tells the service which party) |
| `issuerMetadata.signed` | `'off'` | `'verify'` uses signed issuer metadata when the issuer has it, `'require'` refuses issuers without it. A client profile with `require-signed-issuer-metadata` forces `'require'` |
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
