/**
 * Parity between the two evaluators over a live service: the service's TrustEvaluator (POST /api/v1/evaluate) and
 * this library's device-side evaluator over the signed snapshot must reach the same decision, for the same reasons,
 * about the same entity, with the same revocation status for every certificate. Runs against the local trust service
 * (scripts/start-trust-server.sh) with test PKI registered through the admin API in the 'local' framework (the test
 * IACA with its CRL pushed), under a lenient (demo-wallet) and a strict (demo-verifier: strict authorization,
 * revocation status required) client profile. The offline counterpart is vectors.test.ts.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTrustClient, type TrustClient, type TrustDecision, type TrustQuery } from '../src/index.js';
import { parseCertificate } from '../src/primitives.js';
import { b64, fixture, pem } from './helpers.js';

const BASE = process.env.TRUST_URL ?? 'http://localhost:8090';
const ADMIN = 'admin-key';
const DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const MDL = 'org.iso.18013.5.1.mDL';
const ANIMO = 'https://playground.animo.id/oid4vci/b39e71cf-9cf1-4723-a9cd-66f42a510b36';
const OTHER_DID = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9';

const managed = {
  anchors: {
    'parity-iaca': { domain: 'mdoc-iaca', entity: 'parity-dmv', certificate: pem('iaca'),
      constraints: { docTypes: [MDL], crl: fixture('pki/iaca.crl').toString('base64') } },
    'parity-rp-ca': { domain: 'verifier-access', certificate: pem('rp-ca') },
    'parity-rsa-root': { domain: 'credential-issuer', entity: 'parity-rsa', certificate: pem('rsa-root') },
  },
  entities: {
    'parity-dmv': { roles: ['CREDENTIAL_ISSUER'], name: 'Parity DMV', identifiers: [{ type: 'URL', value: 'https://dmv.parity.example' }],
      authorizations: [{ format: 'mso_mdoc', type: MDL }] },
    'parity-verifier': { roles: ['VERIFIER'], name: 'Parity verifier', identifiers: [{ type: 'DNS', value: 'verifier.example' }] },
    'parity-revoked': { roles: ['CREDENTIAL_ISSUER'], name: 'Revoked', status: 'REVOKED', identifiers: [{ type: 'URL', value: 'https://revoked.parity.example' }] },
    'parity-open': { roles: ['CREDENTIAL_ISSUER'], name: 'No authorizations', identifiers: [{ type: 'URL', value: 'https://open.parity.example' }] },
    'parity-did': { roles: ['CREDENTIAL_ISSUER'], name: 'DID issuer', identifiers: [DID] },
    'parity-rsa': { roles: ['CREDENTIAL_ISSUER'], name: 'RSA issuer', identifiers: [{ type: 'URL', value: 'https://rsa.parity.example' }] },
    'parity-pinned': { roles: ['CREDENTIAL_ISSUER'], name: 'Pinned certificate', certificates: [pem('selfsigned-issuer')] },
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
  ['issuer URL written differently is another identifier', issuer({ identifier: 'https://dmv.parity.example/' }, 'mso_mdoc', MDL)],
  ['issuer URL, unauthorized type', issuer({ identifier: 'https://dmv.parity.example' }, 'dc+sd-jwt', 'urn:eudi:pid:1')],
  ['revoked issuer', issuer({ identifier: 'https://revoked.parity.example' })],
  ['issuer without authorizations (strict differs)', issuer({ identifier: 'https://open.parity.example' }, 'dc+sd-jwt', 'urn:eudi:pid:1')],
  ['DID issuer with key reference', issuer({ identifier: DID, kid: `${DID}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK` }, 'ldp_vc')],
  ['DID issuer, key not in document', issuer({ identifier: DID, kid: `${DID}#missing` }, 'ldp_vc')],
  ['RSA x5c issuer', issuer({ x5c: [b64(pem('rsa-leaf'))] }, 'dc+sd-jwt')],
  ['a certificate that is not a Document Signer, presented as one', issuer({ x5c: [b64(pem('rsa-leaf'))] }, 'mso_mdoc', MDL)],
  ['pinned self-signed certificate', issuer({ x5c: [b64(pem('selfsigned-issuer'))] }, 'dc+sd-jwt')],
  ['pinned certificate after its validity', issuer({ x5c: [b64(pem('selfsigned-issuer'))] }, 'dc+sd-jwt', undefined, { time: '2099-01-01T00:00:00Z' })],
  ['trusted_authorities aki', issuer({ x5c: [b64(pem('ds'))] }, 'mso_mdoc', MDL,
    { trustedAuthorities: [{ type: 'aki', values: [iaca.subjectKeyIdentifier!] }, { type: 'aki', values: ['bm9wZQ'] }] })],
  ['unknown issuer', issuer({ identifier: 'https://nobody.parity.example' })],
  ['verifier x509_hash', verifier(`x509_hash:${rp.sha256}`, [b64(pem('rp'))], 'https://verifier.example/post')],
  ['verifier x509_hash mismatch', verifier('x509_hash:AAAA', [b64(pem('rp'))], 'https://verifier.example/post')],
  ['verifier x509_san_dns', verifier('x509_san_dns:verifier.example', [b64(pem('rp'))], 'https://verifier.example/post')],
  ['verifier x509_san_dns, other response_uri host', verifier('x509_san_dns:verifier.example', [b64(pem('rp'))], 'https://evil.example/post')],
  ['verifier x509_san_dns, response_uri that is not a plain https URL', verifier('x509_san_dns:verifier.example', [b64(pem('rp'))], 'https://Verifier.example@evil.example/post')],
  ['verifier x509_san_dns, SAN mismatch', verifier('x509_san_dns:other.example', [b64(pem('rp'))], 'https://other.example/post')],
  ['verifier x509_hash without x5c', verifier(`x509_hash:${rp.sha256}`)],
  ['verifier redirect_uri', verifier('redirect_uri:https://rp.parity.example/cb')],
  ['unsigned DC API request, unregistered origin', verifier('origin:https://nobody.parity.example')],
  ['live: unsigned DC API request from the Animo playground', verifier('origin:https://playground.animo.id')],
  // Identifiers bound to the presented key: a claim alone never makes a key TRUSTED.
  ['verifier x509_san_dns, certificate outside the anchors', verifier('x509_san_dns:verifier.example', [b64(pem('selfsigned-verifier'))], 'https://verifier.example/post')],
  ['issuer URL claimed with an unanchored chain', issuer({ identifier: 'https://dmv.parity.example', x5c: [b64(pem('rogue-ds'))] }, 'mso_mdoc', MDL)],
  ['issuer URL of another entity than the anchor', issuer({ identifier: 'https://open.parity.example', x5c: [b64(pem('ds'))] }, 'mso_mdoc', MDL)],
  ['DID issuer claimed with another DID key', issuer({ identifier: DID, kid: `${OTHER_DID}#0` }, 'ldp_vc')],
  ['certificate chain and a DID key together', { role: 'verifier', subject: { identifier: `x509_hash:${rp.sha256}`, x5c: [b64(pem('rp'))], kid: `${OTHER_DID}#0` },
    context: { protocol: 'oid4vp', responseUri: 'https://verifier.example/post' } }],
  ['live: Animo issuer metadata URL', issuer({ identifier: ANIMO }, 'mso_mdoc', MDL)],
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

const thumbprint = async () => ((await (await fetch(`${BASE}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string }).signing_key_thumbprint;
const PROFILES = { 'demo-wallet': 'demo-wallet-key', 'demo-verifier': 'demo-verifier-key' } as const;

async function device(clientId: keyof typeof PROFILES, unknownParties = false): Promise<TrustClient> {
  const url = new URL(BASE);
  return createTrustClient({ service: { url: BASE, clientId, apiKey: PROFILES[clientId], keys: { thumbprints: [await thumbprint()] } },
    lookups: { unknownParties }, http: { insecureHosts: url.protocol === 'http:' ? [url.hostname] : [] } });
}

/** The service's own evaluation: the reference the device must agree with. */
async function service(clientId: keyof typeof PROFILES, q: TrustQuery): Promise<TrustDecision> {
  const r = await fetch(`${BASE}/api/v1/evaluate`, { method: 'POST', body: JSON.stringify(q),
    headers: { Authorization: `Bearer ${PROFILES[clientId]}`, 'Content-Type': 'application/json' } });
  if (!r.ok) throw new Error(`evaluate: ${r.status} ${await r.text()}`);
  return await r.json() as TrustDecision;
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

  for (const clientId of ['demo-wallet', 'demo-verifier'] as const) {
    it(`${clientId}: same decisions on the device as in the service`, async () => {
      // The device also asks the service about parties missing from the snapshot, where the service's evaluator would.
      const d = await device(clientId, true);
      await d.sync();
      const rows: string[] = [];
      const mismatches: string[] = [];
      for (const [name, q] of CASES) {
        const [s, l] = [essence(await service(clientId, q)), essence(await d.evaluate(q))];
        const same = JSON.stringify(s) === JSON.stringify(l);
        rows.push(`${same ? '=' : '≠'} ${s.decision.padEnd(11)} ${name}${s.errors.length ? `  [${s.errors.join(', ')}]` : ''}`);
        if (!same) mismatches.push(`${name}\n  service: ${JSON.stringify(s)}\n  device:  ${JSON.stringify(l)}`);
      }
      process.stderr.write(`\n${clientId}\n${rows.join('\n')}\n`);
      expect(mismatches, mismatches.join('\n')).toEqual([]);
    }, 120_000);
  }

  it('revocation: the IACA CRL ships in the snapshot; the strict profile requires a status', async () => {
    const [wallet, strict] = [await device('demo-wallet'), await device('demo-verifier')];
    expect((await wallet.sync()).crls).toBeGreaterThan(0);
    expect((await strict.sync()).requireRevocationStatus).toBe(true);
    const revoked = await wallet.evaluate(CASES.find(([n]) => n === 'DS revoked in the IACA CRL')![1]);
    expect(revoked.evidence?.x509?.revocation?.[0]).toMatchObject({ status: 'REVOKED', reason: 'keyCompromise', source: 'snapshot' });
    const rsa = CASES.find(([n]) => n === 'RSA x5c issuer')![1];
    expect((await wallet.evaluate(rsa)).reasons.find((r) => r.code === 'x509.revocation_unknown')?.severity).toBe('WARNING');
    expect((await strict.evaluate(rsa)).reasons.find((r) => r.code === 'x509.revocation_unknown')?.severity).toBe('ERROR');
  });

  it('the strict profile is enforced on the device too', async () => {
    const q = CASES.find(([n]) => n.startsWith('issuer without authorizations'))![1];
    expect((await (await device('demo-wallet')).evaluate(q)).decision).toBe('TRUSTED');
    expect((await (await device('demo-verifier')).evaluate(q)).decision).toBe('NOT_TRUSTED');
  });
});
