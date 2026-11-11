# Reference ecosystem

A reference credential issuer and verifier to test the trust service, the client library and the wallet against. The
point is that their compliance does not rest on code written in this repository:

| Concern | Done by |
| --- | --- |
| OpenID4VCI 1.0, OAuth 2.0, OpenID4VP 1.0 | `@openid4vc/openid4vci`, `@openid4vc/oauth2`, `@openid4vc/openid4vp` 0.9.2 (OpenWallet Foundation, the library behind Animo's playground) |
| DCQL queries and their evaluation | `dcql` (OpenWallet Foundation) |
| W3C VCDM 2.0 with Data Integrity, Bitstring Status List | `@digitalbazaar/vc`, `data-integrity`, the `ecdsa-rdfc-2019` and `eddsa-rdfc-2022` cryptosuites, `vc-bitstring-status-list`, `did-method-key` |
| ISO/IEC 18013-5 mdoc | `@owf/mdoc` |
| SD-JWT VC, Token Status List | `@sd-jwt/sd-jwt-vc`, `@sd-jwt/jwt-status-list` |
| X.509 certificates, CRLs, path building | `@peculiar/x509` |
| JWS and JWE | `jose` |

**This is a test tool.** The issuer asks nobody: `/authorize` redirects straight back with a code, any `client_id` and
`redirect_uri` are accepted, and whoever reaches `/api` can create offers and revoke. Private keys, including those of
the CAs, lie in the data directory. It listens on loopback over plain http, which the specifications allow nowhere else.

## Run

```sh
. scripts/env.sh
npm start -w @vctrust/reference-ecosystem      # issuer on :8791, verifier on :8792
npm test  -w @vctrust/reference-ecosystem
```

`ISSUER_PORT`, `VERIFIER_PORT` and `DATA_DIR` (default `test-ecosystem/.data`) come from the environment. The data
directory holds `pki.json` (the PKI) and `issuer.json` (assertion keys, access token key, status lists, issued
credentials, Document Signer revocation), so trust anchors and revocations survive a restart. The certificates and the
issuer DID name the issuer URL: a data directory serves the ports it was created with. Remove it to start over.

## Issuer

OpenID4VCI 1.0 at `http://localhost:8791`; it is its own authorization server.

- **Flows**: pre-authorized code, optionally with a transaction code; authorization code with PKCE S256 (required),
  directly or through a pushed authorization request. With `issuer_state` the grant covers the offer; a wallet-initiated
  request names credentials by `scope` or `authorization_details`. A token request (or PAR) with a DPoP proof gets a
  DPoP-bound access token.
- **Endpoints**: `/.well-known/openid-credential-issuer`, `/.well-known/oauth-authorization-server`, `/jwks`, `/par`,
  `/authorize`, `/token`, `/nonce`, `/credential`, `/deferred_credential`, `/notification`.
- **Key proofs**: `jwt`, ES256, with a nonce of the nonce endpoint that is spent by the request carrying it. One
  credential per proof, at most 5 per request.

| Configuration id | Format | Holder binding | Status |
| --- | --- | --- | --- |
| `UniversityDegree_ldp_vc_ecdsa-rdfc-2019` | `ldp_vc`, VCDM 2.0, `ecdsa-rdfc-2019` (P-256) | `credentialSubject.id` is the did:jwk in the proof's `kid` | `BitstringStatusListEntry`, list at `/status/bitstring` |
| `UniversityDegree_ldp_vc_eddsa-rdfc-2022` | `ldp_vc`, VCDM 2.0, `eddsa-rdfc-2022` | as above | as above |
| `mDL_mso_mdoc` | `mso_mdoc`, `org.iso.18013.5.1.mDL` | device key is the proof's `jwk` | none; the Document Signer is on the IACA's CRL when revoked |
| `Identity_dc_sd_jwt` | `dc+sd-jwt`, vct `urn:reference:identity:1` | `cnf.jwk` is the proof's `jwk` | `status.status_list`, token at `/status/token` |

The `ldp_vc` issuer is `did:web:localhost%3A8791` (`/.well-known/did.json`, Multikey verification methods under
`assertionMethod`); every claim term is defined by `/contexts/reference/v1`. The mdoc's `x5chain` and the SD-JWT VC's
`x5c` carry the signer certificate only. Trust anchors: `/pki/iaca.pem` (mdoc), `/pki/issuer-ca.pem` (SD-JWT VC),
CRL at `/pki/iaca.crl`.

Admin API, as functions of `createIssuer` and over HTTP:

```sh
# { offerId, credentialOfferUri: "openid-credential-offer://?credential_offer=…", credentialOffer, txCode? }
curl -s localhost:8791/api/offers -H 'Content-Type: application/json' -d '{
  "configurationIds": ["Identity_dc_sd_jwt"], "grant": "pre-authorized_code", "txCode": true,
  "claims": { "given_name": "Max" }, "deferSeconds": 5 }'
curl -s localhost:8791/api/credentials                       # what was issued: { id, offerId, configurationId, format, issuedAt, revoked }
curl -s localhost:8791/api/revoke -H 'Content-Type: application/json' -d '{"id":"<id>"}'
curl -s -X POST localhost:8791/api/revoke-document-signer   # /pki/iaca.crl lists the Document Signer from now on
curl -s localhost:8791/api/notifications                     # what wallets reported to /notification
```

Only `configurationIds` is required. `grant` is `pre-authorized_code` (default) or `authorization_code`; `txCode`
is `true` for a random six digit code or a code of your own (pre-authorized code only); `claims` replace or add subject
claims (`ldp_vc`: terms of the reference context; mDL: data elements, the three dates as `YYYY-MM-DD`; SD-JWT VC:
top-level claims, which become selectively disclosable); with `deferSeconds` the credential endpoint answers 202 and
the deferred endpoint delivers after that time. An offer is valid for ten minutes and is redeemed once.

The `id` of an issued credential is its status entry: `credentialStatus.id` of an `ldp_vc`, and
`status.status_list.uri + '#' + idx` of an SD-JWT VC.

## Verifier

OpenID4VP 1.0 at `http://localhost:8792`: a signed request object by reference, client identifier prefix `x509_hash`
(the relying-party certificate is the only entry of `x5c`; its CA is at `/pki/verifier-ca.pem`), a DCQL query, and
`response_mode` `direct_post.jwt` (ECDH-ES on P-256 to a key of that request, A128GCM or A256GCM) or `direct_post`.

```sh
# { id, authorizationRequestUri: "openid4vp://?client_id=x509_hash:…&request_uri=…" }
curl -s localhost:8792/api/requests -H 'Content-Type: application/json' -d '{
  "responseMode": "direct_post.jwt",
  "credentials": [
    { "id": "degree", "format": "ldp_vc", "type": ["https://reference.example/vocab#UniversityDegreeCredential"], "claims": [["credentialSubject", "givenName"]] },
    { "id": "mdl", "format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL", "claims": [["org.iso.18013.5.1", "family_name"]] },
    { "id": "identity", "format": "dc+sd-jwt", "vct": "urn:reference:identity:1", "claims": [["given_name"]] } ] }'
curl -s localhost:8792/api/requests/<id>
# { id, status: "pending" | "verified" | "failed" | "rejected" | "expired", error?, credentials?: { <query id>: [{ format, issuer, type, claims }] } }
```

`type` of an `ldp_vc` holds expanded type IRIs, as DCQL wants them. A request takes one response and expires after five
minutes. The response endpoint answers 200 `{}` when the response verified and 400 with the reason when it did not.

On a response the library validates the envelope; then every presentation is verified by its reference implementation:

- `ldp_vc`: a W3C Verifiable Presentation with a Data Integrity proof (`challenge` = nonce, `domain` = client_id),
  with `@digitalbazaar/vc`, including the status of the credential. Holder DIDs: did:jwk, did:key, did:web.
- `dc+sd-jwt`: SD-JWT with Key Binding (`aud` = client_id, nonce, `sd_hash`) with `@sd-jwt/sd-jwt-vc`, including the
  Token Status List.
- `mso_mdoc`: a DeviceResponse with `@owf/mdoc` over the session transcript of OpenID4VP 1.0 appendix B.2.6.1.

Which issuers are accepted is injected: `createVerifier({ …, isTrustedIssuer })` is asked with
`{ format, issuer?, x5c?, type }` (`issuer`: the DID of an `ldp_vc` or `iss` of an SD-JWT VC; `x5c`: the certificate
chain of an mdoc or SD-JWT VC, base64 DER). The default accepts the reference issuer's DID, a Document Signer of the
reference IACA that its CRL does not list, and an SD-JWT VC signer of the reference issuer CA whose SAN names `iss`.

## From another package

```js
import { startEcosystem } from '@vctrust/reference-ecosystem';

const eco = await startEcosystem({ issuerPort: 0, verifierPort: 0 });   // 0: free ports; dataDir: persist
const { credentialOfferUri } = await eco.issuer.createOffer({ configurationIds: ['mDL_mso_mdoc'] });
const { id, authorizationRequestUri } = await eco.verifier.createRequest({ credentials: [{ format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL' }] });
// … the wallet under test redeems the offer and answers the request …
eco.verifier.requestState(id);                 // { id, status, credentials | error }
eco.issuer.revokeCredential(eco.issuer.credentials()[0].id);
await eco.stop();
```

| Export | |
| --- | --- |
| `startEcosystem({ issuerPort?, verifierPort?, dataDir? })` | `Promise<{ issuer, verifier, issuerUrl, verifierUrl, pki, stop() }>` |
| `createIssuer({ baseUrl, pki, dataDir? })` (`/issuer`) | `Promise<{ baseUrl, did, contextUrl, statusUrls, configurationIds, issuerMetadata, handle(request, body), createOffer(opts), revokeCredential(id), revokeDocumentSigner(), credentials(), notifications() }>` |
| `createVerifier({ baseUrl, pki, isTrustedIssuer?, fetch? })` (`/verifier`) | `Promise<{ baseUrl, clientId, handle(request, body), createRequest(opts), requestState(id) }>` |
| `loadOrCreatePki(dataDir, { issuerUrl, verifierHost })`, `generatePki(…)` (`/pki`) | `Promise<Pki>`: `iaca`, `ds`, `issuerCa`, `issuerSigner`, `verifierCa`, `verifier`, each `{ pem, serialNumber, privateJwk, publicJwk }`, and `issuerUrl`, `verifierHost`, `crlUrl` |

`handle(request, body)` takes `{ method, url, headers: Headers }` and the parsed JSON or form body, and returns
`{ status, body?, headers? }`; `src/http.mjs` puts it on `node:http`.

## What this package adds to the libraries

Glue, and the few decisions the libraries leave to their caller:

- The cryptographic callbacks of the protocol and mdoc libraries, on `jose` and WebCrypto, and key resolution from
  did:jwk and `x5c`.
- Certification path checks after `@peculiar/x509` built and signature-verified the path: validity periods and CA
  constraints, and the CRL lookup (`src/pki.mjs`).
- Bitstring Status List: `@digitalbazaar/vc-bitstring-status-list` verifies the list and reads the bit but does not
  judge it, and does not check the minimum list length. `checkStatus` in `src/ldp.mjs` adds both (Validate Algorithm).
- Holder binding of W3C credentials: the presentation must be signed with a key the credential subject authenticates
  with (the same key, whichever DID names it).
- One credential per W3C presentation and one document per DeviceResponse, so a presentation answers one credential query.
- The default trust decision (`src/trust.mjs`).

## Specifications

OpenID4VCI 1.0 (final, 16 September 2025) and OpenID4VP 1.0 (final, 9 July 2025); W3C VCDM 2.0, Data Integrity and
Bitstring Status List v1.0; draft-ietf-oauth-sd-jwt-vc-26 and draft-ietf-oauth-status-list-21; RFC 6749, 7636, 9126,
9207, 9449, 9068; ISO/IEC 18013-5:2021 (Annex B certificate profiles, 9.1.2.4). The ISO text is not public: its
clauses are cited from memory, the others were checked against the published text.

Known limits: no credential request or response encryption, no key attestations, no wallet attestation, no refresh
tokens, no `request_uri_method=post`, no Digital Credentials API, no mdoc status, no signed issuer metadata. The mDL
portrait is a 1x1 placeholder image, and the country code `UT` (Utopia) is not an assigned ISO 3166-1 code.
