# @vctrust/trust-client

A TypeScript client for the VC Trust Service, for wallets and verifiers. It runs in Node 20+, browsers and React Native (Hermes).
There are no platform crypto dependencies: it uses noble curves/hashes plus built-in CBOR, DER and X.509 code.

```ts
import { createTrustClient, KeyValueCacheStore } from '@vctrust/trust-client';

const trust = createTrustClient({
  baseUrl: 'https://trust.example',       // omit to run on standards + local configuration only
  apiKey: process.env.TRUST_API_KEY,
  clientId: 'my-verifier',                // expected audience of signed snapshots
  serviceKeys: { thumbprints: ['WwQ91FCwRpJsBxzWtk3QaYTY62lIHT6WLd1Mox-3TL4'] },   // pin the service key
  cache: new KeyValueCacheStore(localStorage),                                      // or AsyncStorage
  fallback: { localAnchors: [{ domain: 'mdoc-iaca', certificate: IACA_PEM }] },
});
```

| Method | Online (trust service) | Offline fallback |
| --- | --- | --- |
| `evaluate(query)` and `evaluateIssuer` / `evaluateVerifier` / `evaluateCredential` | `POST /api/v1/evaluate` | Local evaluator over the signed snapshot + local anchors; `UNKNOWN` without them |
| `getIssuerMetadata(issuer)` | Metadata proxy (validated, curated, trust attached) | Cached answer, else OpenID4VCI 1.0 discovery directly |
| `resolveDid(did)` | `GET /api/v1/did/{did}` | Cache, else did:key / did:jwk / did:web locally |
| `validateChain(x5c, domain)` | `POST /api/v1/x509/validate` | Local RFC 5280 validation + ISO 18013-5 / verifier profiles |
| `issuers()`, `verifiers()`, `lookup()`, `frameworks()` | Registry API | Snapshot contents |
| `syncSnapshot()` | `GET /api/v1/snapshot` (verified, persisted) | n/a |

Every `TrustDecision` has a `source` field (`trust-service`, `snapshot` or `fallback`):
- Fallback happens only on `TrustServiceUnavailableError` (network failure, timeout, 5xx, open circuit).
- `TrustServiceError` (for example a 403 policy denial) and `TrustIntegrityError` (for example a bad snapshot signature) are thrown, never bypassed.

## Verifier example: trust the issuer of a presented mdoc

```ts
import { createTrustClient, decodeIssuerSigned } from '@vctrust/trust-client';
const trust = createTrustClient({ baseUrl, apiKey: 'demo-verifier-key', clientId: 'demo-verifier' });

// documents[i].issuerSigned from a DeviceResponse you have already signature-checked
const { decision } = await trust.evaluateCredential(issuerSignedB64, 'mso_mdoc');
if (decision.decision !== 'TRUSTED') reject(decision.summary, decision.reasons);

// DCQL trusted_authorities matching (aki / etsi_tl / openid_federation)
const r = await trust.evaluateCredential(sdJwt, 'dc+sd-jwt', { trustedAuthorities: [{ type: 'aki', values: [aki] }] });
const matched = r.decision.evidence?.trustedAuthorities?.some((m) => m.matched);
```

Building blocks are exported for reuse:
- `parseCertificate`, `validateCertificateChain`
- `decodeJws`, `verifyJws`, `verifySignature`, `coseAlgToJose`
- `resolveDidLocally`, `verificationMethodPublicKey`
- `fetchIssuerMetadata`
- the `cbor` codec

Tests: `npx vitest run` (34 tests).
