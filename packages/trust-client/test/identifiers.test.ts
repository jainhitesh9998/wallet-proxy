/**
 * The library compares identifiers exactly as conformance/evaluation/identifiers.json says, and the service is held to the
 * same file (IdentifierFormsTest.java): a certificate hash written in hexadecimal, or in padded or standard base64, reads
 * as the unpadded base64url both evaluators compute. The snapshot carries identifiers in that form already; an app's
 * pinned trust may not.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { LocalEvaluator, identifierKey, type LocalTrustData } from '../src/evaluation/local.js';
import { parseCertificate } from '../src/x509/certificate.js';

interface Forms { same: Array<{ type: string; key: string; values: string[] }>; unchanged: Array<{ type: string; values: string[] }> }
const forms = JSON.parse(readFileSync(new URL('../../../conformance/evaluation/identifiers.json', import.meta.url), 'utf8')) as Forms;

const PKI = new URL('../../../conformance/pki/', import.meta.url);
const pem = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8');
const b64 = (n: string) => pem(n).replace(/-----[^-]+-----/g, '').replace(/\s/g, '');

describe('identifier comparison', () => {
  it('is as the shared list says', () => {
    for (const { type, key, values } of forms.same) {
      for (const value of values) expect(identifierKey(type, value), `${type} ${value}`).toBe(key);
    }
    for (const { type, values } of forms.unchanged) {
      for (const value of values) expect(identifierKey(type, value), `${type} ${JSON.stringify(value)}`).toBe(value);
    }
  });
});

describe('a certificate named by its hash in pinned trust, written another way', () => {
  const ds = parseCertificate(pem('ds'));
  const hex = Buffer.from(ds.sha256, 'base64url').toString('hex').toUpperCase().match(/../g)!.join(':');
  const padded = Buffer.from(ds.sha256, 'base64url').toString('base64');
  const entity = (id: string, status: string, identifiers: Array<{ type: string; value: string }>) =>
    ({ id, frameworkId: 'app', roles: ['CREDENTIAL_ISSUER'], status, display: [{ locale: 'en', name: id }], identifiers, authorizations: [] }) as never;
  const pinned = (entities: unknown[]): LocalTrustData => ({
    entities: entities as never[], frameworks: [], source: 'pinned',
    anchors: [{ certificate: parseCertificate(pem('iaca')), domain: 'mdoc-iaca', frameworkId: 'app', status: 'ACTIVE', entityId: 'utopia-dmv' }] as never[],
    policy: { strictAuthorization: false, requireRevocationStatus: false },
  });
  const ev = new LocalEvaluator(async () => ({ didDocument: null, didResolutionMetadata: { error: 'notFound' }, didDocumentMetadata: {} }) as never);
  const ask = (data: LocalTrustData) => ev.evaluate({ role: 'issuer', subject: { x5c: [b64('ds')] },
    context: { protocol: 'oid4vci', credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } }, data);

  it('binds the certificate, so that a revoked entry keeps its party out', async () => {
    for (const value of [hex, padded]) {
      const d = await ask(pinned([entity('utopia-dmv', 'ACTIVE', []), entity('withdrawn', 'REVOKED', [{ type: 'X509_SHA256', value }])]));
      // Bound to the certificate itself, the revoked entry speaks before the CA's active entity.
      expect([d.decision, d.entity?.id], value).toEqual(['NOT_TRUSTED', 'withdrawn']);
      expect(d.reasons.map((r) => r.code), value).toContain('entity.status');
      expect(d.evidence?.matchedIdentifiers, value).toContain(`X509_SHA256:${ds.sha256}`);
    }
    const trusted = await ask(pinned([entity('utopia-dmv', 'ACTIVE', [])]));
    expect([trusted.decision, trusted.entity?.id]).toEqual(['TRUSTED', 'utopia-dmv']);
  });
});
