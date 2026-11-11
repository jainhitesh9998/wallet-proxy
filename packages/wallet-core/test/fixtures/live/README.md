# Trust material of public sandbox issuers

Pinned copies used by the live tests (`*.live.test.ts`), so that a test fails when a sandbox changes its keys instead
of trusting whatever it presents that day.

| File | What | Captured |
| --- | --- | --- |
| `eudi-pid-issuer-ca-02.pem` | "PID Issuer CA 02" of the EUDI Wallet reference implementation's pre-production PKI, from `https://preprod.pki.eudiw.dev/aia/PIDIssuerCA02-EU.cacert.pem`. SHA-256 `3B:0A:22:3E:87:48:F3:C4:22:17:29:8A:D9:05:EC:F1:A1:04:E7:3C:D2:C5:4F:F2:1D:A1:6F:DA:80:70:B2:97` | 2026-11-12 |
| `waltid-mdl-document-signer.pem` | The Document Signer certificate of walt.id's public demo issuer (`https://issuer2.demo.walt.id`), from the `x5chain` of an mDL it issued. Its IACA ("walt.id OSS Issuer2 Test IACA") is not published, so the signer itself is pinned. | 2026-11-11 |
| `waltid-pid-provider.pem` | walt.id's PID provider certificate, issued by "PID Issuer CA 02", from the `x5c` header of a PID it issued. | 2026-11-11 |

These are sandboxes: their signing keys are test keys (walt.id publishes its demo keys). Nothing here belongs in a
production registry.
