# @vctrust/wallet-core

Platform-neutral holder logic for OpenID4VCI 1.0, OpenID4VP 1.0 and HAIP 1.0, built on `@vctrust/trust-client`. The demo app
(`apps/wallet`) is a thin UI over this package.

- **Issuance:**
  - Flows: credential offers (by value or reference), the pre-authorized code with `tx_code`, and the authorization code flow with PKCE, PAR and the RFC 9207 `iss` check. Wallet-initiated issuance is supported too.
  - HAIP features: DPoP with server nonces; wallet attestation (`attest_jwt_client_auth`) wherever the AS supports it, with one instance key per authorization server and attestation challenges; key attestation.
  - Credential requests: nonce endpoint, `proofs.jwt` (ES256 checked against the issuer) or `proofs.attestation`, holder binding by `jwk`, `did:jwk` or `did:key`, request and response encryption when the issuer requires it (`encryption: 'preferred'` whenever offered). Deferred issuance is handled.
  - Acceptance: a credential that fails verification (or an SD-JWT VC from an untrusted `x5c` issuer) is refused with an `IssuanceError` carrying the report, and the issuer gets `credential_failure`. `wallet.store()` sends `credential_accepted`, `wallet.discard()` sends `credential_deleted`.
  - Per-issuer client registrations cover issuers that need a pre-registered client or a token proxy (MOSIP).
- **Verification** (`verifyCredential`), each format returning a per-check report plus the issuer `TrustDecision`:
  - *mso_mdoc:* COSE_Sign1, item digests, validity and device-key binding.
  - *JSON-LD VC (VCDM 1.1/2.0):* Ed25519Signature2020, eddsa-rdfc-2022 and ecdsa-rdfc-2019 over RDFC-1.0. Contexts are bundled, safe mode is on, issuer key control and status lists are checked.
  - *SD-JWT VC:* disclosure digests, cnf binding and the Token Status List.
- **Presentation:**
  - Request handling: `request_uri` (GET or POST, `client_id` required alongside), JAR checks (`typ`, signature, `exp`) for `x509_hash`, `x509_san_dns`, `decentralized_identifier` and `redirect_uri`. Verifier trust comes from the trust client and is enforced: `verifier.refusal` is set, and `respond()` refuses, unless an `x509_*` verifier is TRUSTED.
  - Credential selection with DCQL, including credential and claim sets (per candidate), `trusted_authorities` and holder binding (required by default). Only the claims on the requested paths are disclosed (`selectDisclosures`).
  - Errors after authentication (`transaction_data`, `redirect_uri` with `direct_post`) carry `reportTo`; `reportPresentationError()` returns them to the verifier once the user has seen them.
  - Presentation formats: SD-JWT + KB-JWT, an mdoc DeviceResponse with the OpenID4VPHandover transcript, and ldp_vp.
  - Responses go back as `direct_post` or `direct_post.jwt` (ECDH-ES + AES-GCM JWE).

```ts
const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri });
const session = await wallet.receive(offerUri);
const [credential] = await wallet.store(await session.acceptPreAuthorized(txCode));
console.log(credential.report.valid, credential.report.trust.decision, credential.report.checks);

const p = await wallet.startPresentation(openid4vpUri);
console.log(p.verifier.trust.decision, p.dcql.satisfied);
await p.respond();
```

Tests:
- `npx vitest run`: offline suite (33 tests), including the OpenID4VP SessionTranscript and RFC 7518 KDF vectors, and an in-memory HAIP issuer for encryption, attestation proofs, refusal and notifications.
- `npm run test:live`: live suites against the Animo playground, MOSIP collab and a local trust server.
