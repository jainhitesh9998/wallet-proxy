# @vctrust/wallet-core

Platform-neutral holder logic for OpenID4VCI 1.0, OpenID4VP 1.0 and HAIP 1.0, built on `@vctrust/trust-client`. The demo app
(`apps/wallet`) is a thin UI over this package.

- **Issuance:**
  - Flows: credential offers (by value or reference), the pre-authorized code with `tx_code`, and the authorization code flow with PKCE, PAR and the RFC 9207 `iss` check. Wallet-initiated issuance is supported too.
  - HAIP features: DPoP with server nonces, wallet attestation (`attest_jwt_client_auth`) and key attestation.
  - Credential requests: nonce endpoint, `proofs.jwt` and holder binding by `jwk`, `did:jwk` or `did:key`. Deferred issuance and notification are handled.
  - Per-issuer client registrations cover issuers that need a pre-registered client or a token proxy (MOSIP).
- **Verification** (`verifyCredential`), each format returning a per-check report plus the issuer `TrustDecision`:
  - *mso_mdoc:* COSE_Sign1, item digests, validity and device-key binding.
  - *JSON-LD VC (VCDM 1.1/2.0):* Ed25519Signature2020, eddsa-rdfc-2022 and ecdsa-rdfc-2019 over RDFC-1.0. Contexts are bundled, safe mode is on, issuer key control and status lists are checked.
  - *SD-JWT VC:* disclosure digests, cnf binding and the Token Status List.
- **Presentation:**
  - Request handling: `request_uri` (GET or POST), JAR checks for `x509_hash`, `x509_san_dns`, `decentralized_identifier` and `redirect_uri`, and verifier trust via the trust client.
  - Credential selection with DCQL, including credential and claim sets and `trusted_authorities`.
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
- `npx vitest run`: offline suite (14 tests), including the OpenID4VP SessionTranscript and RFC 7518 KDF vectors.
- `npm run test:live`: live suites against the Animo playground, MOSIP collab and a local trust server.
