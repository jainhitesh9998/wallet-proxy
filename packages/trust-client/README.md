# @vctrust/trust-client

The client library of [Wallet Proxy](../../README.md): how a wallet or verifier consumes the trust service.

- **Trust decisions on the device.** The library downloads a snapshot the service signed for this app, verifies it
  with a pinned key, and decides from it. The service is not asked about individual parties.
- **Lookups through the proxy, standards as fallback.** Issuer metadata, DID documents, CRLs, status lists and JSON-LD
  contexts come through the service's proxy, verified on the device. When the proxy is down, declines or answers with something
  that does not verify, the library uses the standard mechanism of the specification instead.
- **No service, no trust by accident.** Without a usable snapshot only what the app pins decides; with nothing
  pinned, the answer is `UNKNOWN`. The rules do not lapse with the snapshot: the app's own minimum and the client
  profile of the last snapshot that verified stay in force.

TypeScript, ES modules. Runs in Node 20+, browsers and React Native (Hermes). It depends on `@noble/curves`,
`@noble/hashes` and `fflate` only: CBOR, DER, X.509, CRL and JOSE handling are its own and strict.

## Configure

```ts
import { createTrustClient, KeyValueCacheStore } from '@vctrust/trust-client';

const trust = createTrustClient({
  service: {
    url: 'https://trust.example.org',
    clientId: 'wallet-app',                    // what this app is registered as: the audience of what the service signs
    apiKey: '...',
    keys: { thumbprints: ['WwQ9...3TL4'] },    // the service's signing key, from /.well-known/trust-service
  },
  pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },   // used only while no snapshot is usable
  policy: { requireRevocationStatus: true },   // the app's own minimum rules, with or without a snapshot
  lookups: 'proxy',                            // or 'direct', or per kind: { metadata, did, crl, statusLists, contexts, unknownParties }
  storage: new KeyValueCacheStore(AsyncStorage),   // or localStorage; keeps the snapshot across starts
});
```

Every option is described in the [configuration guide](../../docs/configuration.md#client-library).

## Decide

```ts
// An issuer by its identifier (before asking it for anything):
const d = await trust.evaluateIssuer({ credentialIssuer: 'https://issuer.example.org', format: 'dc+sd-jwt', type: 'urn:eudi:pid:1' });

// A credential's signer: pass the key its signature was verified with, and nothing else.
await trust.evaluate({ role: 'issuer', subject: { x5c }, context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } });
await trust.evaluate({ role: 'issuer', subject: { identifier: issuerDid, kid: verificationMethod }, context: { credentialFormat: 'ldp_vc' } });

// A verifier, from its OpenID4VP request:
await trust.evaluateVerifier({ clientId: 'x509_san_dns:verifier.example.org', x5c, responseUri });
```

A decision is `TRUSTED`, `NOT_TRUSTED` or `UNKNOWN`, with:

- `reasons`: codes with a severity and a message (`x509.revoked`, `identifier.unbound`, `entity.not_authorized`, ...);
- `entity` and `framework`: who the registry says it is;
- `evidence`: the path validation result, the revocation status of every certificate, DID checks,
  `trusted_authorities` matches;
- `source`: `snapshot` or `pinned`, and the snapshot it was made from; `snapshot.stale` when that snapshot has
  expired and could not be refreshed.

The rules are those of the service's evaluator; [the architecture guide](../../docs/architecture.md#how-a-decision-is-made)
describes them. Two of them matter to every caller:

- **An identifier is a claim; a key is proof.** With key material in the query, an entity is found only through
  what that key proves. A credential that names a registered issuer while its key belongs to nobody the registry
  knows, or to someone else, is `NOT_TRUSTED`.
- **Identifiers are compared exactly.** `https://issuer.example.org` and `https://issuer.example.org/` are
  different issuers, as OpenID4VCI and RFC 8414 say.

## Look up

```ts
const md = await trust.getIssuerMetadata('https://issuer.example.org');   // md.source: proxy | fallback | direct | cache
md.credentialIssuerMetadata; md.authorizationServers; md.trust;          // with this device's decision about the issuer

const r = await trust.resolveDid('did:web:issuer.example.org#key-1');     // snapshot | proxy | fallback | direct | cache
const c = await trust.context('https://issuer.example.org/contexts/v1');  // { document, sha256, source, vouched }; snapshot | proxy | fallback | direct | cache

await trust.checkTokenStatus({ idx, uri }, { signerX5c: x5c, form: 'jwt' });          // Token Status List (JWT or CWT)
await trust.checkBitstringStatus(entry, { issuer, verifyListCredential });            // W3C Bitstring Status List
await trust.validateChain(x5c, 'credential-issuer');                                   // path validation with revocation
```

What makes each of these safe to take from a proxy or a cache:

| Lookup | Verified on the device against |
| --- | --- |
| Issuer metadata | The service's signature, the audience, the issuer asked for. Signed issuer metadata: the issuer's own certificate |
| DID document | The snapshot's signature, or a signed response bound to the DID. For a DID the snapshot lists, the snapshot is the resolver |
| CRL | The signature of the CA that issued the certificate being checked (for one fetched from where a trust anchor publishes, its `crlUrls` or a root's own distribution point, the anchor's name and key); a CRL that does not verify is not kept |
| Status list | The list's own signature, its signer (the credential's signer or one certified by the same anchor), subject and age |
| JSON-LD context | The digest the snapshot carries, whether the document came through the relay or from its URL (a relayed one with another digest is not used: its URL is asked); `vouched: false` for a context the snapshot does not know |

Metadata discovery is strict: the `.well-known` location with the path inserted (OpenID4VCI 1.0 §12.2.2, RFC 8414),
a `credential_issuer` identical to the one asked for, https.

## State

```ts
const s = await trust.status();
// { service: 'online' | 'offline' | 'unconfigured', snapshot: { id, issuedAt, expiresAt, stale, entities, anchors, ... } | null,
//   lastSyncError?, degraded, rules: { requireRevocationStatus, strictAuthorization, requireSignedIssuerMetadata } }
trust.onStatusChange((e) => ...);
await trust.sync();          // refresh the snapshot now
```

The snapshot is refreshed in the background (hourly by default; after a failure, not more often than every 30 s),
never replaced by an older one, and usable for a grace period after it expires (7 days by default), during which
decisions carry a warning.

## The building blocks

`@vctrust/trust-client/primitives` exports what the client is made of, for code that verifies credentials next to
it: CBOR and COSE, JOSE, X.509 certificates and CRLs, DID documents, status lists, the evaluator. They change with
the client; only the main entry is a stable interface.

## Tests

```sh
npm test -w @vctrust/trust-client                 # offline: the client, strict parsers, the evaluation vectors
LIVE=1 npx vitest run test/parity.live.test.ts    # against a running service (scripts/dev-up.sh)
LIMBO_JSON="$(sh scripts/fetch-limbo.sh)" npx vitest run test/x509-limbo.conformance.test.ts
```

`test/vectors.test.ts` runs the queries of `conformance/evaluation/vectors.json` through the client and compares
with what the service decided: any difference between the two evaluators fails it.
