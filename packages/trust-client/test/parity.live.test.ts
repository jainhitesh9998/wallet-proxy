/**
 * Parity between the two evaluators: the service's TrustEvaluator (POST /api/v1/evaluate) and the client's
 * device-side LocalEvaluator over the signed snapshot must reach the same decision, for the same reasons, about the
 * same entity, and the same revocation status for every certificate. Runs against the local trust service
 * (scripts/start-trust-server.sh) with test PKI registered through the admin API in the 'local' framework — the test
 * IACA with its CRL pushed — under a lenient (demo-wallet) and a strict (demo-verifier: strict authorization, revocation
 * status required, relaxed anchors not honoured) client profile.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTrustClient, parseCertificate, type TrustDecision, type TrustQuery } from '../src/index.js';
import { b64, fixture, pem } from './helpers.js';

const BASE = process.env.TRUST_URL ?? 'http://localhost:8090';
const ADMIN = 'admin-key';
const DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const MDL = 'org.iso.18013.5.1.mDL';
const ANIMO = 'https://playground.animo.id/oid4vci/b39e71cf-9cf1-4723-a9cd-66f42a510b36';
const OTHER_DID = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9';
const FARMER_KID = 'did:web:inji.github.io:inji-config:collab:farmer#zZivrLb-k3GP7I1RFH1ZrAAMjggK8ohTpjr-q8GT3Sc';

const managed = {
  anchors: {
    'parity-iaca': { domain: 'mdoc-iaca', entity: 'parity-dmv', certificate: pem('iaca'),
      constraints: { docTypes: [MDL], crl: fixture('pki/iaca.crl').toString('base64') } },
    'parity-rp-ca': { domain: 'verifier-access', certificate: pem('rp-ca') },
    'parity-rsa-root': { domain: 'credential-issuer', entity: 'parity-rsa', certificate: pem('rsa-root') },
    // A sandbox IACA the operator relaxed (like MOSIP's mock mDL): its non-ISO Document Signers pass only where relaxations are honoured.
    'parity-sandbox-iaca': { domain: 'mdoc-iaca', entity: 'parity-sandbox', certificate: pem('rsa-root'), constraints: { relaxProfile: true } },
  },
  entities: {
    'parity-dmv': { roles: ['CREDENTIAL_ISSUER'], name: 'Parity DMV', identifiers: [{ type: 'URL', value: 'https://dmv.parity.example' }],
      authorizations: [{ format: 'mso_mdoc', type: MDL }] },
    'parity-verifier': { roles: ['VERIFIER'], name: 'Parity verifier', identifiers: [{ type: 'DNS', value: 'verifier.example' }] },
    'parity-revoked': { roles: ['CREDENTIAL_ISSUER'], name: 'Revoked', status: 'REVOKED', identifiers: [{ type: 'URL', value: 'https://revoked.parity.example' }] },
    'parity-open': { roles: ['CREDENTIAL_ISSUER'], name: 'No authorizations', identifiers: [{ type: 'URL', value: 'https://open.parity.example' }] },
    'parity-did': { roles: ['CREDENTIAL_ISSUER'], name: 'DID issuer', identifiers: [DID] },
    'parity-rsa': { roles: ['CREDENTIAL_ISSUER'], name: 'RSA issuer', identifiers: [{ type: 'URL', value: 'https://rsa.parity.example' }] },
    'parity-sandbox': { roles: ['CREDENTIAL_ISSUER'], name: 'Sandbox issuer', identifiers: [{ type: 'URL', value: 'https://sandbox.parity.example' }],
      authorizations: [{ format: 'mso_mdoc', type: MDL }] },
  },
};

const rp = parseCertificate(pem('rp'));
const iaca = parseCertificate(pem('iaca'));
const issuer = (subject: TrustQuery['subject'], format?: string, type?: string, extra: Record<string, unknown> = {}): TrustQuery =>
  ({ role: 'issuer', subject, context: { protocol: 'oid4vci', credentialFormat: format, credentialType: type, ...extra } });
const verifier = (clientId: string, x5c?: string[], responseUri?: string): TrustQuery =>
  ({ role: 'verifier', subject: { identifier: clientId, x5c }, context: { protocol: 'oid4vp', responseUri } });

const CASES: Array<[string, TrustQuery]> = [
  ['mDL DS chain', issuer({ x5c: [b64(pem('ds'))] }, 'mso_mdoc', MDL)],
  ['DS chain, doctype outside anchor constraint', issuer({ x5c: [b64(pem('ds'))] }, 'mso_mdoc', 'eu.europa.ec.eudi.pid.1')],
  ['DS without the mDL EKU', issuer({ x5c: [b64(pem('ds-noeku'))] }, 'mso_mdoc', MDL)],
  ['DS from another country', issuer({ x5c: [b64(pem('ds-nl'))] }, 'mso_mdoc', MDL)],
  ['DS under an unknown IACA', issuer({ x5c: [b64(pem('rogue-ds'))] }, 'mso_mdoc', MDL)],
  ['DS revoked in the IACA CRL', issuer({ x5c: [b64(pem('ds-revoked'))] }, 'mso_mdoc', MDL)],
  ['DS on hold in the IACA CRL', issuer({ x5c: [b64(pem('ds-hold'))] }, 'mso_mdoc', MDL)],
  ['DS with a CRL distribution point, not revoked', issuer({ x5c: [b64(pem('ds-crldp'))] }, 'mso_mdoc', MDL)],
  ['DS with only an OCSP responder, covered by the IACA CRL', issuer({ x5c: [b64(pem('ds-ocsp'))] }, 'mso_mdoc', MDL)],
  ['issuer URL, authorized type', issuer({ identifier: 'https://dmv.parity.example' }, 'mso_mdoc', MDL)],
  ['issuer URL, unauthorized type', issuer({ identifier: 'https://dmv.parity.example' }, 'dc+sd-jwt', 'urn:eudi:pid:1')],
  ['revoked issuer', issuer({ identifier: 'https://revoked.parity.example' })],
  ['issuer without authorizations (strict differs)', issuer({ identifier: 'https://open.parity.example' }, 'dc+sd-jwt', 'urn:eudi:pid:1')],
  ['DID issuer with key reference', issuer({ identifier: DID, kid: `${DID}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK` }, 'ldp_vc')],
  ['DID issuer, key not in document', issuer({ identifier: DID, kid: `${DID}#missing` }, 'ldp_vc')],
  ['RSA x5c issuer', issuer({ x5c: [b64(pem('rsa-leaf'))] }, 'dc+sd-jwt')],
  ['non-ISO DS under a relaxProfile anchor (strict refuses)', issuer({ x5c: [b64(pem('rsa-leaf'))] }, 'mso_mdoc', MDL)],
  ['trusted_authorities aki', issuer({ x5c: [b64(pem('ds'))] }, 'mso_mdoc', MDL,
    { trustedAuthorities: [{ type: 'aki', values: [iaca.subjectKeyIdentifier!] }, { type: 'aki', values: ['bm9wZQ'] }] })],
  ['unknown issuer', issuer({ identifier: 'https://nobody.parity.example' })],
  ['verifier x509_hash', verifier(`x509_hash:${rp.sha256}`, [b64(pem('rp'))], 'https://verifier.example/post')],
  ['verifier x509_hash mismatch', verifier('x509_hash:AAAA', [b64(pem('rp'))], 'https://verifier.example/post')],
  ['verifier x509_san_dns, other response_uri host', verifier('x509_san_dns:verifier.example', [b64(pem('rp'))], 'https://evil.example/post')],
  ['verifier x509_san_dns, SAN mismatch', verifier('x509_san_dns:other.example', [b64(pem('rp'))], 'https://other.example/post')],
  ['verifier x509_hash without x5c', verifier(`x509_hash:${rp.sha256}`)],
  ['verifier redirect_uri', verifier('redirect_uri:https://rp.parity.example/cb')],
  // Identifiers bound to the presented key: a claim alone never makes a key TRUSTED.
  ['verifier x509_san_dns, certificate outside the anchors', verifier('x509_san_dns:verifier.example', [b64(pem('selfsigned-verifier'))], 'https://verifier.example/post')],
  ['issuer URL claimed with an unanchored chain', issuer({ identifier: 'https://dmv.parity.example', x5c: [b64(pem('rogue-ds'))] }, 'mso_mdoc', MDL)],
  ['issuer URL of another entity than the anchor', issuer({ identifier: 'https://open.parity.example', x5c: [b64(pem('ds'))] }, 'mso_mdoc', MDL)],
  ['DID issuer claimed with another DID key', issuer({ identifier: DID, kid: `${OTHER_DID}#0` }, 'ldp_vc')],
  ['certificate chain and a DID key together', { role: 'verifier', subject: { identifier: `x509_hash:${rp.sha256}`, x5c: [b64(pem('rp'))], kid: `${OTHER_DID}#0` },
    context: { protocol: 'oid4vp', responseUri: 'https://verifier.example/post' } }],
  ['live: Animo issuer metadata URL', issuer({ identifier: ANIMO }, 'mso_mdoc', MDL)],
  ['live: MOSIP did:web issuer key', issuer({ identifier: 'https://injicertify-farmer.collab.mosip.net', kid: FARMER_KID }, 'ldp_vc', 'FarmerCredential')],
  ['live: MOSIP did:web, unknown key', issuer({ identifier: 'https://injicertify-farmer.collab.mosip.net', kid: `${FARMER_KID.split('#')[0]}#rotated` }, 'ldp_vc')],
];

async function admin(method: string, path: string, body?: unknown) {
  const r = await fetch(`${BASE}${path}`, { method, headers: { Authorization: `Bearer ${ADMIN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined });
  if (!r.ok && r.status !== 404) throw new Error(`${method} ${path}: ${r.status} ${await r.text()}`);
}

/** What must agree: decision, the set of ERROR reasons, the entity, the X.509 outcome and revocation, trusted_authorities matches. */
function essence(d: TrustDecision) {
  return {
    decision: d.decision,
    errors: [...new Set(d.reasons.filter((r) => r.severity === 'ERROR').map((r) => r.code))].sort(),
    entity: d.entity?.id ?? null,
    x509: d.evidence?.x509 ? { valid: d.evidence.x509.valid, anchorFound: d.evidence.x509.anchorFound,
      revocation: (d.evidence.x509.revocation ?? []).map((r) => r.status) } : null,
    trustedAuthorities: (d.evidence?.trustedAuthorities ?? []).map((t) => t.matched),
  };
}

describe('evaluator parity: service vs device', () => {
  beforeAll(async () => {
    for (const [id, e] of Object.entries(managed.entities)) await admin('PUT', `/admin/v1/managed/entities/${id}`, e);
    for (const [id, a] of Object.entries(managed.anchors)) await admin('PUT', `/admin/v1/managed/anchors/${id}`, a);
  }, 60_000);

  afterAll(async () => {
    for (const id of Object.keys(managed.anchors)) await admin('DELETE', `/admin/v1/managed/anchors/${id}`);
    for (const id of Object.keys(managed.entities)) await admin('DELETE', `/admin/v1/managed/entities/${id}`);
  });

  for (const [clientId, apiKey] of [['demo-wallet', 'demo-wallet-key'], ['demo-verifier', 'demo-verifier-key']] as const) {
    it(`${clientId}: same decisions on the device as in the service`, async () => {
      const thumbprint = ((await (await fetch(`${BASE}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string }).signing_key_thumbprint;
      const device = createTrustClient({ baseUrl: BASE, apiKey, clientId, serviceKeys: { thumbprints: [thumbprint] } });
      const service = createTrustClient({ baseUrl: BASE, apiKey, clientId, decisions: 'service', serviceKeys: { thumbprints: [thumbprint] } });
      await device.syncSnapshot();
      const rows: string[] = [];
      const mismatches: string[] = [];
      for (const [name, q] of CASES) {
        const [s, l] = [essence(await service.evaluate(q)), essence(await device.evaluate(q))];
        const same = JSON.stringify(s) === JSON.stringify(l);
        rows.push(`${same ? '=' : '≠'} ${s.decision.padEnd(11)} ${name}${s.errors.length ? `  [${s.errors.join(', ')}]` : ''}`);
        if (!same) mismatches.push(`${name}\n  service: ${JSON.stringify(s)}\n  device:  ${JSON.stringify(l)}`);
      }
      process.stderr.write(`\n${clientId}\n${rows.join('\n')}\n`);
      expect(mismatches, mismatches.join('\n')).toEqual([]);
    }, 120_000);
  }

  it('revocation: the IACA CRL ships in the snapshot; the strict profile requires a status', async () => {
    const thumbprint = ((await (await fetch(`${BASE}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string }).signing_key_thumbprint;
    const wallet = createTrustClient({ baseUrl: BASE, apiKey: 'demo-wallet-key', clientId: 'demo-wallet', serviceKeys: { thumbprints: [thumbprint] } });
    const strict = createTrustClient({ baseUrl: BASE, apiKey: 'demo-verifier-key', clientId: 'demo-verifier', serviceKeys: { thumbprints: [thumbprint] } });
    expect((await wallet.syncSnapshot()).crls.some((c) => c.crl.issuer === parseCertificate(pem('iaca')).subject)).toBe(true);
    expect((await strict.syncSnapshot()).policy.requireRevocationStatus).toBe(true);
    const revoked = await wallet.evaluate(CASES.find(([n]) => n === 'DS revoked in the IACA CRL')![1]);
    expect(revoked.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', reason: 'keyCompromise', source: 'snapshot' });
    const rsa = CASES.find(([n]) => n === 'RSA x5c issuer')![1];
    expect((await wallet.evaluate(rsa)).reasons.find((r) => r.code === 'x509.revocation_unknown')?.severity).toBe('WARNING');
    expect((await strict.evaluate(rsa)).reasons.find((r) => r.code === 'x509.revocation_unknown')?.severity).toBe('ERROR');
  });

  it('the strict profile is enforced on the device too', async () => {
    const thumbprint = ((await (await fetch(`${BASE}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string }).signing_key_thumbprint;
    const q = CASES.find(([n]) => n.startsWith('issuer without authorizations'))![1];
    const wallet = createTrustClient({ baseUrl: BASE, apiKey: 'demo-wallet-key', clientId: 'demo-wallet', serviceKeys: { thumbprints: [thumbprint] } });
    const strict = createTrustClient({ baseUrl: BASE, apiKey: 'demo-verifier-key', clientId: 'demo-verifier', serviceKeys: { thumbprints: [thumbprint] } });
    expect((await wallet.evaluate(q)).decision).toBe('TRUSTED');
    expect((await strict.evaluate(q)).decision).toBe('NOT_TRUSTED');
    const relaxed = CASES.find(([n]) => n.startsWith('non-ISO DS under a relaxProfile anchor'))![1];
    const lenient = await wallet.evaluate(relaxed);
    expect(lenient.decision).toBe('TRUSTED');
    expect(lenient.evidence?.x509?.issues.map((i) => i.code)).toContain('x509.profile_relaxed');
    expect((await strict.evaluate(relaxed)).decision).not.toBe('TRUSTED');
    expect((await strict.syncSnapshot()).policy.allowRelaxedProfiles).toBe(false);
  });
});
