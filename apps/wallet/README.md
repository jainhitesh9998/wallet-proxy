# VC Trust demo wallet (Expo)

A demo UI over [`@vctrust/wallet-core`](../../packages/wallet-core) and [`@vctrust/trust-client`](../../packages/trust-client).
All protocol logic and credential verification live in those packages; this app only presents them. It runs in a browser
(react-native-web), in Expo Go, and as a native Android build.

## How it uses the trust service

- **Trust decisions are made on the device**, from the signed snapshot the trust service publishes for this client.
- **Lookups go through the service's proxy first** (issuer metadata, DID documents, CRLs, status lists) and to the party
  itself when the proxy cannot serve them. Settings can switch each kind to `direct`, and CRLs to `none`.
- **While no snapshot is usable, only pinned trust decides.** The app pins the Animo playground root certificate
  (`src/config/pinned.ts`) for mdoc issuers, SD-JWT VC issuers and verifiers. With a snapshot, nothing pinned is consulted.
- **Service key.** Settings take the thumbprint of the service's signing key (`signing_key_thumbprint` at
  `/.well-known/trust-service`). Left empty, the first key seen is trusted and pinned on the device: development only.
- **https only.** Plain http is accepted for `localhost`, `127.0.0.1`, `10.0.2.2` and, when the trust service URL is
  http, that URL's host. These are development addresses (the reference ecosystem runs on `http://localhost`).

## Run

```sh
. scripts/env.sh && npm install          # from the repository root
scripts/dev-up.sh                        # trust service :8090, reference issuer :8791 and verifier :8792, registered
cd apps/wallet
npm run web                              # http://localhost:8081
npm start                                # Expo Go: scan the QR. In Settings, set the trust URL to http://<LAN-IP>:8090
```

Defaults (Settings): trust service `http://localhost:8090`, client `demo-wallet`, API key `demo-wallet-key`, no key
thumbprint, every lookup `proxy`, asking the service about unlisted parties off, HAIP options `auto`, three instances
per credential from issuers with batch issuance.

**Android emulator (Expo Go)**

```sh
scripts/android.sh setup                 # once: Android SDK, emulator, API 35 image, Expo Go
npm start -w @vctrust/wallet-app         # Metro on :8081
scripts/android.sh start                 # boots the emulator and opens the wallet; adb reverse 8081, 8090, 8791, 8792
scripts/android.sh open "openid-credential-offer://?credential_offer=…"   # or an openid4vp:// request
```

**Digital Credentials API (Android, native build).** A page's `navigator.credentials.get({digital: …})` reaches the
wallet through Android's Credential Manager (`modules/dc-api`), which Expo Go cannot host:

```sh
scripts/android-dcapi.sh setup           # once: Android 37.2 image and AVD dcapi-37
scripts/android-dcapi.sh start           # boots it, turns off Chrome's first-run screens, adb reverse 8090, 8791, 8792
scripts/android-dcapi.sh build           # expo prebuild + release APK + install
node e2e/dcapi-android.mjs issue         # an mDL and a PID from the Animo playground (needs the internet)
node e2e/dcapi-android.mjs               # DC API scenarios: Animo's verifier, a decline, a local multi-signed request
```

The wallet registers its mdoc and SD-JWT VC credentials with Credential Manager whenever they change. JSON-LD
credentials are presented through the redirect flow only.

## What the screens do

**Receive.** Paste or scan an offer, or start from *Demo issuers*: the reference issuer (`http://localhost:8791`; the
buttons ask its admin API `POST /api/offers` for an offer, see [test-ecosystem](../../test-ecosystem/README.md)) and
the Animo playground (create an offer there and paste its link). The issuer's trust decision is shown before a token
or credential is requested:

- **TRUSTED**: accept or authorize.
- **UNKNOWN**: a warning; nothing can be requested until the user chooses *Continue with this unknown issuer*. Even
  then a credential signed with a certificate that chains to no trusted anchor is refused.
- **NOT_TRUSTED**: refused with the reason. There is no way around it.

A logo is shown only for a TRUSTED party; images of unknown parties are not fetched. A refused credential is shown
with its verification report.

**Credential.** Claims, every check of the verification report as the verifier reported it (warnings included), the
trust evidence (X.509 path with revocation, or DID), re-verification, and deferred retrieval.

**Present.** The verifier and its trust, the request checks, and what is asked for. Required credentials are shared;
a credential the verifier marks optional is off until the user turns it on; nothing else is shared. A verifier whose
certificate does not chain to a trusted verifier CA is blocked; an unknown one is marked as such.

**Settings.** The trust service and its key, the trust status (`TrustClient.status()`: service online or offline, the
snapshot's issue and expiry time, its contents, the last refresh error, whether decisions are degraded), where lookups
go, *Simulate trust-service outage*, HAIP options, and *Wipe wallet*.

*Simulate trust-service outage* points the trust client at an address where nothing listens. With a stored snapshot
nothing changes for the user except that lookups come from the party itself (`Metadata via: fallback`). Wipe the wallet
during the outage and there is no snapshot either: issuers are UNKNOWN unless a pinned anchor vouches for their key.

## Demo keys

The wallet-provider key that signs wallet and key attestations is generated into `src/config` by `npm run gen:config`
and bundled with the app. Holder keys are software keys in AsyncStorage / localStorage. Attestations bind a separate
instance key per authorization server. *Simulated high-assurance key storage* attests `iso_18045_high` for software
keys; it exists only to try issuers that demand it.

## Tests

`npm test -w @vctrust/e2e` (Playwright, web build; `scripts/dev-up.sh` must be running, no internet needed):

1. Trust status, proxy-first defaults, the service key pin; settings stored by an earlier version.
2. Each of the reference issuer's four configurations: issuer TRUSTED before anything is requested, issuance, the
   verification report, a presentation the reference verifier verifies.
3. The authorization code flow from the demo issuer list.
4. An outage with a snapshot (fallback), and without one: unknown issuer, explicit confirmation, an mdoc still refused.
5. An issuer the trust service lists as suspended: refused.
6. An optional credential: shared only when the user adds it.

`npm run test:live -w @vctrust/e2e` adds the Animo playground (issuance, presentation, and both again with pinned
trust only).

## Limitations

- Tested on the web (Playwright) and as a native release build on an Android 37.2 emulator (`e2e/dcapi-android.mjs`:
  issuance through the UI and six DC API scenarios). This version was not tested in Expo Go or on iOS.
- The reference issuer's certificates and DID name `http://localhost:8791`, so it is reachable only where `localhost`
  is the developer's machine: a browser there, or an emulator with `adb reverse`. A phone on the LAN can use the trust
  service and public issuers, not the reference ecosystem.
- The Digital Credentials API works in the Android native build only; elsewhere presentations use `openid4vp://`.
- Incoming `openid-credential-offer://` and `openid4vp://` deep links reach the app only in a native build. In Expo Go,
  wrap them as `exp://<host>/--/receive?offer=…` or `…/--/present?request=…` (what `scripts/android.sh open` does).
- The simulated outage uses `127.0.0.1:9`, so a browser console shows `ERR_UNSAFE_PORT`. This is expected.
