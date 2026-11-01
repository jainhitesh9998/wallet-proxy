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

Defaults (Settings):
- trust service `http://localhost:8090`, API key `demo-wallet-key`, client id `demo-wallet`;
- fallback on;
- HAIP options on `auto`.

The demo wallet-provider key that signs wallet and key attestations is generated into `src/config` by `npm run gen:config`.
It is a demo key bundled in the app; keys live in AsyncStorage / localStorage, not hardware.

## Demo script (about 5 minutes)

1. **Settings**
   - Save, then press *Sync offline snapshot*. The page shows the snapshot version, verified with the service key.
   - The status pill reads *Trust service: online*.
2. **mDL from the Animo playground**
   - Open https://playground.animo.id. Choose *Issue*, issuer *Utopia Government*, *Driving Licence*, `mso_mdoc`. Optionally enable DPoP and wallet attestation.
   - Copy the offer link.
   - In the wallet, choose *Receive*, paste the link, then *Load offer*. The issuer appears as **TRUSTED**, *source: trust-service*, with the framework.
   - *Accept*. The new card shows TRUSTED and *✓ valid signature*.
   - Open the card. The detail view shows these checks: COSE signature, 14 digests, validity, device key, issuer trust. It also shows the X.509 path to the Animo IACA.
3. **Present to the Animo verifier**
   - On the playground, choose *Verify*, *Driving Licence* (mdoc), response mode `direct_post.jwt`. Copy the `openid4vp://` link.
   - In the wallet, choose *Present* and paste the link. The view shows:
     - the verifier **TRUSTED** (`x509_hash` request checks, verifier-access CA, registry entry);
     - the requested claims;
     - the matching credential.
   - *Share*. The playground shows the verified presentation.
4. **JSON-LD (VCDM 2.0) from MOSIP**
   - *Receive*, then *From trusted issuers*, then *MOSIP Farmer Registry*, then `FarmerCredential_VCDM2.0`.
   - Sign in with eSignet in the new tab: UIN `2154189532`, OTP `111111`.
   - On web, paste the final `io.mosip.residentapp.inji://oauthredirect?...` URL into the wallet (the custom scheme cannot return to a web page).
   - The credential shows the Ed25519Signature2020 checks, the issuer DID resolved through the trust service, and warnings for MOSIP's quirks.
5. **Trust service outage**
   - In Settings, turn on *Simulate trust-service outage*. The pill turns *offline (fallback)*.
   - Receive another Animo offer. Issuance still works: metadata comes from the cache or direct discovery, and trust comes from **source: snapshot**.
   - Without a snapshot, the wallet would show **UNKNOWN**, never TRUSTED.

## Limitations

- Device builds were checked by bundling only (`npm run export:android`); no device or simulator was used.
- MOSIP's registered redirect is Inji's custom scheme:
  - On the web you paste the redirect URL into the wallet.
  - On iOS, Expo Go's auth session catches it.
  - Android needs a development build with the scheme in `app.json`.
- Incoming `openid-credential-offer://` and `openid4vp://` deep links reach the app only in a development build. The in-app QR scanner works everywhere.
- The snapshot signing key is trusted on first use. Production clients should pin the thumbprint published at `/.well-known/trust-service` (`serviceKeys.thumbprints`).
- The simulated outage points the client at `127.0.0.1:9`, so the browser console shows `ERR_UNSAFE_PORT`. This is expected.

## Tests

From the repo root, `cd e2e && npm test` runs Playwright on the web build:
1. Settings and snapshot.
2. Animo mDL issuance, then presentation; the verifier reports `ResponseVerified`.
3. Outage fallback.

`npm run test:mosip` adds the MOSIP JSON-LD flow.
