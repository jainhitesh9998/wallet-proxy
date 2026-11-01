# mosip-issuance

A headless, fully scripted OpenID4VCI **authorization-code** issuance against MOSIP's public
**collab** sandbox. It downloads real credentials from three Inji Certify issuers:

| CLI arg   | Issuer (`credential_issuer`)                         | `credential_configuration_id`      | Format     |
|-----------|------------------------------------------------------|------------------------------------|------------|
| `Land`    | https://injicertify-landregistry.collab.mosip.net    | `LandStatementCredential_VCDM2.0`  | `ldp_vc` (W3C VCDM 2.0) |
| `Farmer`  | https://injicertify-farmer.collab.mosip.net          | `FarmerCredential_VCDM2.0`         | `ldp_vc` (W3C VCDM 2.0) |
| `MockMdl` | https://injicertify-mdl.collab.mosip.net             | `DrivingLicenseCredential`         | `mso_mdoc` (`org.iso.18013.5.1.mDL`) |

No issuer, AS, or wallet backend runs locally. Every call goes to `*.collab.mosip.net`.

## Usage

```sh
source ~/.local/tools/env.sh          # Node 22
npm install
npx playwright install chromium       # once
node issue.mjs Land                   # or Farmer / MockMdl
node inspect.mjs samples/MockMdl-DrivingLicenseCredential.json   # decode/summarise a sample
```

`issue.mjs` prints the credential response JSON on stdout and progress on stderr. It also writes the
**verbatim** response body to `samples/<issuer>-<config>.json`. Each run takes about 15–25 s.

| Env var | Default | Meaning |
|---|---|---|
| `MOSIP_INDIVIDUAL_ID` | `2154189532` | UIN typed into the eSignet login |
| `MOSIP_OTP` | `111111` | OTP (the collab mock accepts 111111) |
| `MOSIP_REDIRECT_URI` | Mimoto's `redirect_uri` (`io.mosip.residentapp.inji://oauthredirect`) | `https://injiweb.collab.mosip.net/redirect` works too |
| `HEADLESS=0` | headless | watch the browser |
| `NO_SAVE=1` | save | don't write `samples/` |

### Reuse from an e2e suite

```js
import { loginAndGetCode, discover, buildAuthorizeUrl, makePkce, exchangeCode,
         fetchNonce, makeHolderKey, requestCredential, issue } from './tools/mosip-issuance/issue.mjs';

// a) the whole thing
const { json, holder } = await issue('Farmer', { save: false });

// b) only the browser part, with your own authorize URL
const { code, state } = await loginAndGetCode(authorizeUrl, redirectUri,
  { individualId: '2154189532', otp: '111111', headless: true, timeoutMs: 90_000 });
```

`loginAndGetCode` captures the code in three ways:
- from the navigation request to `redirectUri`. This fires even for the custom scheme, which Chromium never loads.
- for `http(s)` redirect URIs, by intercepting the request with `context.route` and fulfilling it locally, so the wallet site is never hit.
- as a fallback, from eSignet's `POST /v1/esignet/authorization/auth-code` XHR, whose response carries `{code, state, redirectUri}`.

If a consent screen shows up, it clicks Allow/Proceed. On collab the consent screen is skipped.

## The recipe (exact parameters)

### 0. Discovery

- Mimoto issuer config: `GET https://api.collab.mosip.net/v1/mimoto/issuers`. This gives `client_id`, `redirect_uri`, and the
  `token_endpoint` proxy for each issuer.
- Issuer metadata: `GET https://<certify-host>/.well-known/openid-credential-issuer`. This gives `credential_endpoint`,
  `nonce_endpoint`, `authorization_servers = ["https://esignet-mock.collab.mosip.net"]`, and each config's `scope`.
- AS metadata: `GET https://esignet-mock.collab.mosip.net/.well-known/openid-configuration`. It gives
  `authorization_endpoint = https://esignet-mock.collab.mosip.net/authorize`.

| Issuer | `client_id` | `scope` | Mimoto token proxy |
|---|---|---|---|
| Land | `mpartner-default-mimoto-land-oidc` | `land_statement_vc_ldp` | `https://api.collab.mosip.net/v1/mimoto/get-token/Land` |
| Farmer | `mpartner-default-mimoto-land-oidc` | `mock_identity_vc_ldp` | `https://api.collab.mosip.net/v1/mimoto/get-token/Farmer` |
| MockMdl | `mpartner-default-mimoto-mdl-oidc` | `sample_vc_mdoc` | `https://api.collab.mosip.net/v1/mimoto/get-token/MockMdl` |

`redirect_uri`: eSignet accepts both `io.mosip.residentapp.inji://oauthredirect` (the Inji mobile value, and
what Mimoto publishes) and `https://injiweb.collab.mosip.net/redirect` (Inji Web), for both clients. Both
were tested end to end.

### 1. Authorization request (PKCE S256 + state)

This is the same parameter set Inji Web sends (`inji-web/src/utils/api.ts`):

```
GET https://esignet-mock.collab.mosip.net/authorize
  ?response_type=code
  &client_id=mpartner-default-mimoto-land-oidc
  &scope=land_statement_vc_ldp
  &redirect_uri=io.mosip.residentapp.inji://oauthredirect
  &state=<random>
  &code_challenge=<b64url(sha256(verifier))>
  &code_challenge_method=S256
  &ui_locales=en
```

Leave these out: `nonce`, `acr_values`, `claims`, `authorization_details`, and the `openid` scope. Inji does not send
them and eSignet doesn't need them. Only one scope, the credential scope, is sent.

### 2. Login (eSignet mock UI)

- The page asks for "Login with UIN/VID": `input#Otp_vid` and the `#get_otp` button. Then 6 `input[type=tel]` OTP boxes and `#verify_otp`.
- Test identity: **UIN `2154189532`, OTP `111111`**. eSignet returns `authFactors: [[{type: "OTP"}]]` for both
  clients. There is no KBI or password factor on these clients.
- `consentAction` is `NOCAPTURE`, so there is no consent screen. eSignet then navigates to
  `io.mosip.residentapp.inji://oauthredirect?state=<state>&code=<code>&ui_locales=null`.

### 3. Token via the Mimoto proxy

eSignet only allows `private_key_jwt`. Mimoto holds the client key and adds `client_assertion` itself.

```
POST https://api.collab.mosip.net/v1/mimoto/get-token/<Land|Farmer|MockMdl>
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<code>&redirect_uri=<same redirect_uri>&code_verifier=<verifier>[&client_id=<client_id>]
```

`client_id` is optional, because Mimoto fills it from its config. The response is `200`:

```json
{"token_type":"Bearer","access_token":"<JWT>","expires_in":3600,"c_nonce":"ZxTLArHkxy1YHC5QU05M"}
```

The response has no `id_token`, `refresh_token`, `c_nonce_expires_in` or `authorization_details`. The access token is a JWT
(`iss=https://esignet-mock.collab.mosip.net/v1/esignet`, `aud=https://esignet-mock.collab.mosip.net/v1/esignet/vci/credential`,
`sub=<UIN>`, `scope=<credential scope>`, and a `c_nonce` claim).

### 4. Nonce

```
POST https://<certify-host>/v1/certify/nonce        (no body, no auth)
→ 200 {"c_nonce":"cf2e1e34-9b93-4022-a527-31581c447e74"}
```

**Do not use the token response's `c_nonce`.** It is eSignet's, and Certify rejects it (see quirks).

### 5. Credential request (OpenID4VCI 1.0 shape, accepted as-is)

```
POST https://<certify-host>/v1/certify/issuance/credential
Authorization: Bearer <access_token>
Content-Type: application/json

{"credential_configuration_id":"LandStatementCredential_VCDM2.0","proofs":{"jwt":["<proof>"]}}
```

The proof JWT is ES256 over a freshly generated P-256 key:

- `ldp_vc`: header `{"typ":"openid4vci-proof+jwt","alg":"ES256","kid":"did:jwk:<b64url({crv,kty,x,y})>#0"}`
- `mso_mdoc`: header `{"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":…,"y":…}}`
- claims: `{"aud":"<credential_issuer>","iat":<now>,"nonce":"<c_nonce>","iss":"<client_id>"}`. `iss` is optional, see quirks.

The response is `200 {"credentials":[{"credential": <VC object | base64url mdoc string>}]}`. It has no `notification_id`
and no `c_nonce`.

There was **no deviation from the 1.0 request shape**. No legacy `format` / `proof` / `credential_definition` was needed.

## Samples

| File | What |
|---|---|
| `samples/Land-LandStatementCredential_VCDM2.0.json` | verbatim credential response (ldp_vc) |
| `samples/Farmer-FarmerCredential_VCDM2.0.json` | verbatim credential response (ldp_vc, ~54 KB because of the `face` data URI) |
| `samples/MockMdl-DrivingLicenseCredential.json` | verbatim credential response (mso_mdoc, base64url) |
| `samples/MockMdl-issuer-root-ca.pem` | mDL trust anchor, from `GET https://injicertify-mdl.collab.mosip.net/v1/certify/system-info/certificate?applicationId=ROOT` |
| `samples/<Land|Farmer>-issuer-did-web-injicertify-*.json` | DID doc of the `issuer` DID (`https://injicertify-<x>.collab.mosip.net/.well-known/did.json`) |
| `samples/<Land|Farmer>-verificationMethod-did-web-inji.github.io-collab-*.json` | DID doc of the DID named in `proof.verificationMethod` (`https://inji.github.io/inji-config/collab/<x>/did.json`) |

Each sample is bound to a throwaway holder key generated for that run. Their private keys are not kept.

### ldp_vc (Land, Farmer)

- `@context`: `["https://www.w3.org/ns/credentials/v2", "https://inji.github.io/inji-config/contexts/<landregistry-statement|farmer>-context.json", "https://w3id.org/security/suites/ed25519-2020/v1"]`. All three URLs resolve with 200.
- `type`: `["VerifiableCredential", "LandStatementCredential" | "FarmerCredential"]`
- `issuer`: `did:web:injicertify-landregistry.collab.mosip.net` / `did:web:injicertify-farmer.collab.mosip.net`
- `proof`: `type: "Ed25519Signature2020"` (no `cryptosuite`), `proofPurpose: "assertionMethod"`, `proofValue` is multibase `z…`.
  - Land: `verificationMethod: did:web:inji.github.io:inji-config:collab:landregistry#2Fx_l12c8_2xKT-I2QL1dF4UIncSNwyuAx11PxLDtdc` (key `z6MkjWT68PLKM2TR3pvkyrHruvwj1EMYbEBichyRLxT6nKqw`)
  - Farmer: `verificationMethod: did:web:inji.github.io:inji-config:collab:farmer#zZivrLb-k3GP7I1RFH1ZrAAMjggK8ohTpjr-q8GT3Sc` (key `z6MkurQYswuw7SuhPCPC4kH49J6mMk35GpGM9y7NBKBR3PmY`)
- `validFrom` / `validUntil` (VCDM 2.0 names). Land is valid for 730 days, Farmer for 740.
- Land has `credentialStatus` `{type: BitstringStatusListEntry, statusPurpose: revocation, statusListIndex: "<string>", statusListCredential: https://injicertify-landregistry.collab.mosip.net/v1/certify/credentials/status-list/<uuid>}`. Farmer has no `credentialStatus`.
- Farmer has `renderMethod: [{type: TemplateRenderMethod, renderSuite: svg-mustache, template: {id: https://injicertify-farmer.collab.mosip.net/v1/certify/rendering-template/5b9c2a12-…, mediaType: image/svg+xml}}]`.
- `id`: `https://mosip.io/credential/<uuid>`

### mso_mdoc (MockMdl)

- `credential` is base64url (no padding) CBOR `{"docType": "org.iso.18013.5.1.mDL", "issuerSigned": {nameSpaces, issuerAuth}}`.
- `issuerAuth` is a COSE_Sign1 with protected header `{1: -7}`, i.e. **ES256**. `x5chain` (label 33) sits in the
  unprotected header as a single DER bstr, the leaf only.
  - Leaf subject: `C=IN, ST=KA, L=BANGALORE, O=IIITB, OU=EXAMPLE-CENTER, CN=www.example.com (CERTIFY_VC_SIGN_EC_R1-EC_SECP256R1_SIGN)`.
    It has a P-256 key, a validity of 2026-02-04 to 2029-02-03, `CA:TRUE, pathlen:1`, and KeyUsage digitalSignature+keyCertSign.
  - Leaf issuer: `C=IN, ST=KA, L=BANGALORE, O=IIITB, OU=EXAMPLE-CENTER, CN=www.example.com (ROOT)`. This is RSA-2048,
    self-signed, `sha256WithRSAEncryption`, valid 2025-02-13 to 2033-02-11. `openssl verify` of leaf→root reports OK.
- The signature verifies with the leaf key (`node inspect.mjs …` reports `signatureVerifiesWithX5chainLeaf: true`), and
  all 6 `valueDigests` (SHA-256) match.
- MSO: `version 1.0`, `digestAlgorithm SHA-256`, `deviceKeyInfo.deviceKey` = the holder's P-256 COSE_Key (`{1:2, 3:-7, -1:1, -2:x, -3:y}`).
- Namespace `org.iso.18013.5.1` contains `family_name`, `given_name`, `birth_date` (tag 1004), `issuing_country`,
  `document_number`, and `driving_privileges`.

## MOSIP-specific quirks and spec deviations

**Discovery / authorization**
1. Mimoto's `wellknown_endpoint` values are inconsistent. Land and MockMdl use `/v1/certify/issuance/.well-known/openid-credential-issuer`,
   Farmer uses `/v1/certify/.well-known/…`. The spec location `https://<host>/.well-known/openid-credential-issuer` works for
   all three, and this tool uses that.
2. The credential scopes (`land_statement_vc_ldp`, `mock_identity_vc_ldp`, `sample_vc_mdoc`) are not in eSignet's
   `scopes_supported`, but they are accepted. eSignet treats them as credential scopes, and `authorizeScopes` comes back empty.
3. eSignet discovery doesn't advertise `code_challenge_methods_supported`, but `S256` works.
4. The redirect gets an extra `ui_locales=null` query parameter.
5. Test data is keyed by the access token `sub`, which is the UIN typed at login.
   - The Farmer and mDL data are CSVs in `inji/inji-config@collab` (`farmer_identity_data.csv`, `driving_license_data.csv`).
     Land is a Postgres query: `select * from statement_data where statement_id=:id`.
   - `2154189532` works for all three.
   - `8267411578` (from the inji-certify repo CSV) logs in but gets `400 {"error":"ERROR_FETCHING_IDENTITY_DATA"}` from Farmer.
   - Other collab Farmer IDs: 5614273165, 2089250384, 5860356276, 3963293078. Their eSignet login is untested.
6. The pre-authorized-code flow is broken on collab: the credential endpoint returns 401 "no matching key(s)" for pre-auth tokens. Use auth-code.

**Token / nonce**

7. The token response `c_nonce` (eSignet's, also present as a claim in the access token) is **rejected by Certify**:
   `400 {"error":"invalid_nonce","error_description":"c_nonce is invalid or expired"}`. Only nonces from
   `POST /v1/certify/nonce` work. The `invalid_nonce` error does **not** carry a fresh `c_nonce` (1.0 behaviour), so re-POST the nonce endpoint and retry. `issue.mjs` does this once.
8. Nonce-endpoint nonces are **not single-use**. The same nonce was accepted twice on the same access token, which is a replay gap.
   The access token is also reusable for several credential requests.
9. The proof `iss` claim is optional. If present it must equal the `client_id`. A wrong `iss` gives
   `400 {"error":"invalid_proof","error_description":"None of the submitted proofs passed validation."}`. A bad bearer token gives `401` with
   `WWW-Authenticate: Bearer error="invalid_token"`.
10. The access token `aud` is eSignet's own `…/v1/esignet/vci/credential`, not the Certify `credential_issuer`. Certify accepts it.

**ldp_vc output**

11. The credential uses VCDM **2.0** but signs with the legacy `Ed25519Signature2020` suite: no `DataIntegrityProof`/`eddsa-rdfc-2022`, and the
    `https://w3id.org/security/suites/ed25519-2020/v1` context is appended after the issuer context. Metadata only says
    `credential_signing_alg_values_supported: ["EdDSA"]`. The `type` and `@context` order in the credential also differ from
    `credential_definition` in the metadata.
12. **`issuer` ≠ the DID of `proof.verificationMethod`.**
    - The issuer is `did:web:injicertify-<x>.collab.mosip.net`, but the proof points at `did:web:inji.github.io:inji-config:collab:<x>#…`.
    - Both DID docs publish the same Ed25519 key, under different VM ids.
    - A verifier that requires the VM's controller to equal `issuer` will reject these credentials.
13. Both DID docs list the **bare DID** in `assertionMethod` and `authentication`, not the VM id. A strict Data Integrity proof-purpose check
    (VM ∈ controller's `assertionMethod`) fails unless you relax it or treat the DID as "all its VMs".
14. `credentialSubject.id` is the holder **DID URL** copied from the proof `kid` (`did:jwk:…#0`), not the bare DID `did:jwk:…`.

**mso_mdoc output (vs ISO 18013-5 / OpenID4VCI 1.0 Appendix A.2)**

15. The credential is `{docType, issuerSigned}`, not the bare `IssuerSigned` structure that OpenID4VCI 1.0 requires.
16. The COSE_Sign1 **payload is the bare MSO map**, not `#6.24(bstr .cbor MSO)` (MobileSecurityObjectBytes). The signature is over the
    untagged bytes, so a verifier that insists on tag 24 will fail to parse it.
17. `validityInfo` has **no `signed`**. `validFrom` and `validUntil` are **untagged tstr with milliseconds**
    (e.g. `2026-10-31T19:26:01.898Z`) rather than `tdate` = `#6.0(tstr)` without fractional seconds.
18. ISO-mandatory mDL elements are missing: `issue_date`, `expiry_date`, `issuing_authority`, `portrait`, `un_distinguishing_sign`.
    `driving_privileges` uses camelCase keys (`vehicleCategoryCode`, `issueDate` as tag 1004) instead of `vehicle_category_code` / `issue_date`.
19. The certificate profile is not IACA / DS:
    - the "document signer" leaf is `CA:TRUE` with keyCertSign, and it is RSA-signed by a generic `www.example.com (ROOT)`;
    - the leaf has a **negative serial number** (`-0x45cee42220d88a5e`, an RFC 5280 violation). Go ≥ 1.23 `crypto/x509` rejects this
      unless `GODEBUG=x509negativeserial=1` is set, while OpenSSL and Node accept it;
    - only the leaf is in `x5chain`. Fetch the root from the URL above.

## Files

- `issue.mjs`: the CLI and library. It exports `loginAndGetCode`, `issue`, `discover`, `buildAuthorizeUrl`, `makePkce`,
  `exchangeCode`, `fetchNonce`, `makeHolderKey`, `makeProofJwt`, `requestCredential`, `checkHolderBinding`, and `ISSUERS`.
- `inspect.mjs`: summarises a saved sample. For ldp_vc it shows contexts, issuer and proof. For mdoc it decodes the CBOR, gives x5chain DNs,
  checks the COSE signature and verifies the value digests.
