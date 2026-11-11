# @vctrust/wallet-core

Platform-neutral wallet logic for OpenID4VCI 1.0, OpenID4VP 1.0 and HAIP 1.0, with credential verification, on top
of [`@vctrust/trust-client`](../trust-client). The demo app ([`apps/wallet`](../../apps/wallet)) is a thin UI over it.

Everything the wallet needs to know about a counterparty comes through the trust client: the issuer's metadata and
trust, the verifier's trust, DID documents, JSON-LD contexts, CRLs and status lists. What the trust layer says
decides what the wallet does.

```ts
const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri });

const session = await wallet.receive(offerUri);          // throws when the trust layer refuses the issuer
if (session.needsConfirmation) {                         // the issuer is unknown to the trust layer
  // show session.issuerTrust to the user, and only if they agree:
  session.confirmUnknownIssuer();
}
const [credential] = await wallet.store(await session.acceptPreAuthorized(txCode));
credential.report;                                       // every check, the issuer's trust decision, the claims

const p = await wallet.startPresentation(openid4vpUri);
p.verifier;                                              // who asks, their trust decision, a refusal if there is one
p.dcql;                                                  // what can be presented: required and optional credentials
await p.respond();                                       // optional credentials only when named: respond(choice, include)
```

## What it does

**Issuance (OpenID4VCI 1.0).** Credential offers by value or by reference; the pre-authorized code grant with a
transaction code; the authorization code grant with PKCE, PAR and the RFC 9207 `iss` check; DPoP with server nonces;
wallet attestation (`attest_jwt_client_auth`) and key attestation; the nonce endpoint; `jwt` and `attestation`
proofs; binding by `jwk`, `cose_key`, `did:jwk` or `did:key`; batch issuance with one key per instance; deferred
issuance, also resumed later; notifications; credential request and response encryption.

**Verification.** `verifyCredential(format, credential, options)` returns a report with one entry per check and the
issuer's trust decision. Formats: `mso_mdoc`, `dc+sd-jwt`, `ldp_vc`. See
[what is checked](../../docs/architecture.md#credential-verification-in-the-wallet).

**Presentation (OpenID4VP 1.0).** Request objects by reference (GET or POST with wallet metadata); the client
identifier prefixes `x509_hash`, `x509_san_dns`, `decentralized_identifier` and `redirect_uri`; DCQL with credential
sets, claim sets, values and `trusted_authorities`; SD-JWT VC with key binding, mdoc DeviceResponse, W3C
presentations; `direct_post` and `direct_post.jwt`; and the Digital Credentials API (Appendix A: unsigned, signed
and multi-signed requests, origin-bound responses).

## Rules that are not options

- Only OpenID4VCI 1.0 and OpenID4VP 1.0 messages. Earlier draft shapes are errors.
- https for every endpoint a counterparty names. `insecureHosts` exists for an issuer on localhost during development.
- An issuer the trust layer refuses is turned away before anything is fetched from it; from an unknown one nothing
  beyond its metadata is requested until `confirmUnknownIssuer()`.
- An issued credential is verified with the key the wallet proved, must be of the type that was asked for, and is
  refused (the issuer is told `credential_failure`) when any check fails, when its issuer is not trusted, or when
  it is signed with a certificate that chains to no trusted anchor.
- A verifier that presents a certificate must chain to a trusted verifier anchor; a refused verifier can only be
  declined.
- A credential that failed its last verification is not offered for presentation; credentials the verifier marks
  optional are not sent unless the user adds them.

## Tests

```sh
npm test -w @vctrust/wallet-core      # offline
LIVE=1 npx vitest run test/proxy.live.test.ts test/animo.live.test.ts test/waltid.live.test.ts   # see below
```

| Test | Covers |
| --- | --- |
| `sdjwt.test.ts`, `mdoc.test.ts` | Each rule a credential can break, one at a time, with credentials built from the test PKI |
| `interop.test.ts` | The wallet against the reference issuer and verifier (`test-ecosystem`, run as its own process): all formats and flows, altered W3C credentials, revocation, presentation |
| `real-world.test.ts` | Credentials that public sandbox issuers issued (`conformance/real-world`) |
| `oid4vp.test.ts`, `dcapi.test.ts`, `haip.test.ts`, `vectors.test.ts` | Request authentication, DCQL, the Digital Credentials API, HAIP features against an in-memory issuer, specification test vectors |
| `proxy.live.test.ts` | Trust service + reference ecosystem + wallet, including the service going away (`scripts/dev-up.sh`) |
| `animo*.live.test.ts`, `waltid.live.test.ts` | The Animo playground and walt.id's demo issuer through the trust service (internet) |
