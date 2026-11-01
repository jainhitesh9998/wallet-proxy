# VC Trust demo wallet (Expo)

A throwaway demo UI over [`@vctrust/wallet-core`](../../packages/wallet-core) and [`@vctrust/trust-client`](../../packages/trust-client).
All protocol logic and credential verification live in those packages; this app only presents them. It runs in a browser
(react-native-web) and on a phone through Expo Go.

## Run

```sh
. ../../scripts/env.sh && cd ../.. && npm install && cd apps/wallet
../../scripts/start-trust-server.sh     # trust service on :8090 (if not running)
npm run web                             # http://localhost:8081
npm run cors-proxy                      # only for MOSIP issuers on web: dev-only relay on 127.0.0.1:8787
npm start                               # Expo Go: scan the QR. In Settings, set the trust URL to http://<LAN-IP>:8090
```

**Android emulator** (no phone needed; tested on Apple Silicon):

```sh
../../scripts/android.sh setup          # once: Android SDK, emulator, API 35 image and Expo Go (about 2 GB)
npm start                               # Metro on :8081 (or keep `npm run web` running: it serves Android too)
../../scripts/android.sh start          # boots a headless emulator (WINDOW=1 for a window) and opens the wallet
../../scripts/android.sh open "openid-credential-offer://?credential_offer_uri=…"   # or an openid4vp:// request
```

The emulator reaches Metro, the trust service and the CORS relay on `localhost` through `adb reverse`, so the default
trust URL works. Offers and requests arrive as Expo Go deep links (`exp://127.0.0.1:8081/--/receive?offer=…`).

Defaults (Settings):
- trust service `http://localhost:8090`, API key `demo-wallet-key`, client id `demo-wallet`;
- **Decide trust: `local`**. Decisions are made on this device from the signed trust list; the service never learns which issuers or verifiers you use.
- Issuer metadata and DIDs: `direct`. Asking the service about unlisted parties: off.
- HAIP options on `auto`.

The demo wallet-provider key that signs wallet and key attestations is generated into `src/config` by `npm run gen:config`.
It is a demo key bundled in the app; keys live in AsyncStorage / localStorage, not hardware. Attestations bind a separate
instance key per authorization server, so issuers cannot link the user through the attestation. *Simulated
high-assurance key storage* (off by default) attests `iso_18045_high` for software keys; it exists only to try issuers
that demand it.

## Demo script (about 5 minutes)

1. **Settings**
   - Save, then press *Sync trust list*. The page shows the trust list (snapshot) version, verified with the service key. It also shows its contents: entities, trust anchors, DID documents and CRLs, and the policy.
   - The status pill reads *Trust service: online* and *Decisions on this device · trust list vN*.
2. **mDL from the Animo playground**
   - Open https://playground.animo.id. Choose *Issue*, issuer *Utopia Government*, *Driving Licence*, `mso_mdoc`. Optionally enable DPoP and wallet attestation.
   - Copy the offer link.
   - In the wallet, choose *Receive*, paste the link, then *Load offer*. The issuer appears as **TRUSTED**, *decided by: device · list vN*, with the framework. *Metadata via: direct*, so the metadata came from the issuer, not the trust service.
   - *Accept*. The new card shows TRUSTED and *✓ valid signature*.
   - Open the card. The detail view shows these checks: COSE signature, 14 digests, validity, device key, issuer trust. It also shows the X.509 path to the Animo IACA.
   - *Certificate 0 status: not revoked · CRL https://playground.animo.id/crl, next update …*. This is Animo's real IACA CRL, which the service fetched and put in the trust list; the wallet verified it against the IACA and needed no extra request.
3. **Present to the Animo verifier**
   - On the playground, choose *Verify*, *Driving Licence* (mdoc), response mode `direct_post.jwt`. Copy the `openid4vp://` link.
   - In the wallet, choose *Present* and paste the link. The view shows:
     - the verifier **TRUSTED** (`x509_hash` request checks, verifier-access CA, registry entry);
     - the requested claims (only these are disclosed);
     - the matching credential.
   - *Share*. The playground shows the verified presentation.
   - A verifier whose certificate does not chain to a trusted verifier CA is shown with *Sharing is blocked*; only *Decline* is possible. A request the wallet rejects after authenticating it (for example one with `transaction_data`) offers *Tell the verifier*.
4. **JSON-LD (VCDM 2.0) from MOSIP**
   - *Receive*, then *From trusted issuers*, then *MOSIP Farmer Registry*, then `FarmerCredential_VCDM2.0`.
   - Sign in with eSignet in the new tab: UIN `2154189532`, OTP `111111`.
   - On web, paste the final `io.mosip.residentapp.inji://oauthredirect?...` URL into the wallet (the custom scheme cannot return to a web page).
   - The credential shows the Ed25519Signature2020 checks, the issuer DID resolved through the trust service, and warnings for MOSIP's quirks.
5. **Who decides**
   - In Settings, switch *Decide trust* to `service` and *Issuer metadata & DIDs* to `service`, then load another offer. The badge now reads *decided by: trust service*, and the metadata comes through the proxy.
   - Switch both back to `local`/`direct`. This is the privacy-preserving default.
   - *Other CRLs* and *Status lists* choose between fetching from the CA or issuer (`direct`) and the trust service relay (`service`). The relay hides the device from the issuer, but the service then sees which list was checked. Either way the wallet verifies what it receives.
6. **Trust service outage**
   - In Settings, turn on *Simulate trust-service outage*. The pill turns *offline*.
   - Receive another Animo offer. Nothing changes for the user: decisions are made on the device anyway, from the stored trust list. Only refreshing the list fails.
   - After 24 h the list expires; decisions then carry a warning for up to 7 days.
   - Without any trust list, the wallet would show **UNKNOWN**, never TRUSTED.

## Limitations

- Tested on the web (Playwright) and in Expo Go on an Android emulator (API 35, Hermes). iOS was not tested.
- No Digital Credentials API: presentations use the OpenID4VP redirect flow (`openid4vp://`).
- MOSIP's registered redirect is Inji's custom scheme:
  - On the web you paste the redirect URL into the wallet.
  - On iOS, Expo Go's auth session catches it.
  - Android needs a development build with the scheme in `app.json`.
- Incoming `openid-credential-offer://` and `openid4vp://` deep links reach the app only in a development build. In Expo Go, wrap them as `exp://<host>/--/receive?offer=…` or `…/--/present?request=…` (what `scripts/android.sh open` does). The in-app QR scanner works everywhere.
- The snapshot signing key is trusted on first use. Production clients should pin the thumbprint published at `/.well-known/trust-service` (`serviceKeys.thumbprints`).
- The simulated outage points the client at `127.0.0.1:9`, so the browser console shows `ERR_UNSAFE_PORT`. This is expected.

## Tests

From the repo root, `cd e2e && npm test` runs Playwright on the web build:
1. Settings and trust list.
2. Animo mDL issuance, then presentation; the verifier reports `ResponseVerified`.
3. The same decision made by the service in `service` mode.
4. An outage: decisions continue from the stored trust list.

`npm run test:mosip` adds the MOSIP JSON-LD flow.
