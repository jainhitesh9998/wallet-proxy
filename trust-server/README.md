# Trust service

The server half of [Wallet Proxy](../README.md). Java 21, Spring Boot, Maven.

| Module | What |
| --- | --- |
| `trust-core` | The registry model, the evaluator (`TrustEvaluator`), X.509 path validation and CRLs, DID drivers, issuer metadata discovery and metadata policy. No Spring |
| `trust-adapters` | Trust list formats behind the `TrustSourceFactory` SPI: `static`, `x509-bundle`, `vical`, `etsi-tl`, `etsi-lote`, `openid-federation`, `ebsi-tir`, `oid4vci-discovery` |
| `trust-server` | The application: snapshot signing, the proxy and its caches, client authentication, rate limiting, the admin API |

```sh
mvn verify                                             # builds and tests all three
java -jar trust-server/target/trust-server.jar --spring.profiles.active=demo    # http://localhost:8090, demo configuration (public API keys: development only)
```

API: [`docs/openapi.json`](../docs/openapi.json), or `/swagger-ui.html` on a running service.

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/trust-service`, `/.well-known/jwks.json` | Discovery: endpoints, signing key thumbprints, readiness |
| `GET /api/v1/snapshot` | The signed trust snapshot for the calling client (`ETag` / `If-None-Match`) |
| `GET /api/v1/proxy/issuer-metadata?issuer=` | OpenID4VCI issuer and authorization server metadata, signed for the client |
| `GET /api/v1/proxy/did/{did}` | DID resolution, signed for the client |
| `GET /api/v1/proxy/crl?url=`, `/api/v1/proxy/status-list?uri=` | CRL and status list relays (signed by their own issuers) |
| `GET /api/v1/frameworks`, `/issuers`, `/verifiers`, `/entities/lookup` | The registry as the client may see it; on-demand lookup of unlisted parties |
| `POST /api/v1/evaluate` | The service's own decision, for verifier backends; the reference the client library is checked against |
| `/admin/v1/**` | Sources, registry, managed entities and anchors, caches (admin clients) |

Configuration: [`docs/configuration.md`](../docs/configuration.md). How it works: [`docs/architecture.md`](../docs/architecture.md).

## Adding a trust list format

1. Implement `io.vctrust.trust.core.spi.TrustSourceFactory`; its `TrustSource.load()` maps the list to
   `TrustedEntity` and `TrustAnchor` records. Use `SourceContext.http()` for every request, so the outbound guard and
   the limits apply, and verify the list's signature before returning anything.
2. Implement `OnDemandResolver` as well when the registry is too large to enumerate.
3. Register the factory in `META-INF/services/io.vctrust.trust.core.spi.TrustSourceFactory`.
4. Use its type in `trust.sources[].type`.

## Tests

`mvn test` runs unit tests of the rules, the adapters against sample lists, and integration tests of the running
application. `EvaluationVectorsTest` regenerates [`conformance/evaluation/vectors.json`](../conformance) from the
cases and fails when the checked-in file differs; see [`conformance/README.md`](../conformance/README.md).
