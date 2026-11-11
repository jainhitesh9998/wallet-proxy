/**
 * Trust bundled with the app. The trust client uses it only while it holds no usable trust snapshot (never reached
 * the trust service, or the stored snapshot is past its grace period). As soon as a snapshot is usable, the service
 * is the authority and nothing here is consulted.
 */
import type { PinnedAnchor } from '@vctrust/trust-client';

/**
 * Root certificate of the Animo playground (https://playground.animo.id): IACA of its mdocs, CA of its SD-JWT VC
 * signer and of its verifier certificate.
 *
 *   subject  CN=Animo Playground Root, C=NL, O=Animo Solutions B.V.
 *   valid    2025-11-03 to 2029-11-03
 *   SHA-256  52:51:6F:78:B7:1F:31:B2:A9:9E:A1:2D:EF:A1:3D:BA:C6:84:DA:E2:A3:A1:47:87:35:F7:92:A5:A6:FE:5E:85
 *
 * The same certificate the trust service's demo registry anchors (trust-server/.../trust/certs/animo-playground-root.pem)
 * and the playground publishes at /api/x509 (refresh: curl -s https://playground.animo.id/api/x509 | jq -r .pem).
 * conformance/real-world/animo-root-2024.der is a different, older certificate (CN=Animo, issued 2024-11-28,
 * SHA-256 8D:C5:43:8C…): it is not the service's anchor, so it is not pinned here.
 */
export const ANIMO_PLAYGROUND_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgIQIOONR6QLKFUEhhhlVgfaLDAKBggqhkjOPQQDAjBMMR4w
HAYDVQQDExVBbmltbyBQbGF5Z3JvdW5kIFJvb3QxCzAJBgNVBAYTAk5MMR0wGwYD
VQQKExRBbmltbyBTb2x1dGlvbnMgQi5WLjAeFw0yNTExMDMxNjQzNDlaFw0yOTEx
MDMxNjQzNDlaMEwxHjAcBgNVBAMTFUFuaW1vIFBsYXlncm91bmQgUm9vdDELMAkG
A1UEBhMCTkwxHTAbBgNVBAoTFEFuaW1vIFNvbHV0aW9ucyBCLlYuMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEia0hAIuIR6bKL5DU1TuiTckPfkP0OXvmzan2/nyw
oY4X8FQFMuFC7OWlXFsdRmaYFoeXdRzoLz4XxS4pV3NEmKOBoDCBnTAdBgNVHQ4E
FgQUv3MC+XWLbT4Suj06nUJZvBfwwwswDgYDVR0PAQH/BAQDAgEGMCYGA1UdEgQf
MB2GG2h0dHBzOi8vcGxheWdyb3VuZC5hbmltby5pZDASBgNVHRMBAf8ECDAGAQH/
AgEAMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHBzOi8vcGxheWdyb3VuZC5hbmltby5p
ZC9jcmwwCgYIKoZIzj0EAwIDSAAwRQIhANtSsiC903N5GgDhnI11xvk72oWIL2kT
f2OFbcw+pN6yAiAXswddnRXwjJYrRHaM9Cq1MStIotWFhMw6V3DvQAAexA==
-----END CERTIFICATE-----
`;

const ANIMO_FRAMEWORK = 'animo-playground';

/** The Animo root in the three trust domains it serves, as the trust service lists it. */
export const PINNED_ANCHORS: PinnedAnchor[] = (['mdoc-iaca', 'credential-issuer', 'verifier-access'] as const)
  .map((domain) => ({ domain, certificate: ANIMO_PLAYGROUND_ROOT_PEM, frameworkId: ANIMO_FRAMEWORK }));

/** Shown in Settings next to the trust status. */
export const PINNED_TRUST_NOTE = 'Pinned in the app: the Animo playground root certificate (mdoc issuers, SD-JWT VC issuers, verifiers). '
  + 'Pinned trust is used only while no snapshot is usable.';
