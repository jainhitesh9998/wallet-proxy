# Real-world credentials

Credentials and certificates of public sandbox issuers, exactly as they issued them, with the public key of the
throwaway holder key they were bound to. They are test data of those sandboxes (the people in them do not exist) and
are kept to check the verifiers against something this repository did not produce:
`packages/wallet-core/test/real-world.test.ts` verifies each one offline, as of the day it was obtained.

| File | Issuer | Obtained | What the wallet makes of it |
| --- | --- | --- | --- |
| `waltid-mdl.json` | walt.id demo issuer, `https://issuer2.demo.walt.id/openid4vci` (OpenID4VCI 1.0, pre-authorized code) | 2026-11-11 | ISO mDL; verifies; trusted with its Document Signer certificate registered |
| `waltid-pid-mdoc.json` | same | 2026-11-11 | EUDI PID as mdoc; verifies; signer certificate issued by the EUDI pre-production "PID Issuer CA 02" |
| `waltid-pid-sdjwt.json` | same | 2026-11-11 | EUDI PID as SD-JWT VC (x5c); verifies; same certificate |
| `talao-emailpass-ldp.json` | Talao sandbox, `https://talao.co/issuer/jfzmmdaedq` | 2026-11-11 | W3C VCDM 1.1, Ed25519Signature2020; refused: its `@context` holds an inline context |
| `talao-pid-sdjwt.json` | Talao sandbox, `https://talao.co/issuer/hrngdrpura` | 2026-11-11 | SD-JWT VC signed with a key named by `kid`; refused: no X.509 chain (HAIP 1.0 §6.1.1) |
| `aegean-pid-sdjwt.json` | University of the Aegean, `https://dss.aegean.gr/rfc-issuer` | 2026-11-11 | refused: `typ` is `vc+sd-jwt`, and no X.509 chain |
| `mosip-land-statement-ldp.json`, `mosip-land-issuer-did.json`, `mosip-land-key-did.json` | MOSIP Inji Certify, collab environment | 2026-10 | W3C VCDM 2.0; refused: the proof's key is published under another DID than the issuer's, and that DID document lists the DID, not the key, under `assertionMethod` |
| `mosip-mock-mdl.json`, `mosip-mock-mdl-root.pem` | MOSIP Inji Certify, collab environment | 2026-10 | refused: a `{docType, issuerSigned}` wrapper instead of the IssuerSigned structure (OpenID4VCI 1.0 A.2.4) |
| `animo-root-2024.der` | Animo playground, `https://playground.animo.id` | 2026-10 | an earlier root certificate of the playground (CN=Animo, issued 2024-11-28), kept as a parsing sample. The playground's current root (CN=Animo Playground Root, issued 2025-11-03) is the anchor in the service's demo registry (`trust-server/.../trust/certs/animo-playground-root.pem`) and the one the demo wallet pins |

No public issuer could be found on 2026-11-11 that issues a W3C VCDM 2.0 credential with a Data Integrity proof over
OpenID4VCI 1.0 to a script: that format is covered by the reference issuer (`test-ecosystem/`), which signs with
Digital Bazaar's implementations of the cryptosuites.
