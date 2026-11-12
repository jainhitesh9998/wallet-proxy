/**
 * A query member that is not of the type it is declared as is refused, as the service refuses the request (400,
 * TrustServerIntegrationTest): read as something else (a credential type 7 as the type "7", or as no type), the two
 * evaluators would decide the same question differently.
 */
import { describe, expect, it } from 'vitest';
import { LocalEvaluator, type LocalTrustData } from '../src/primitives.js';
import type { TrustQuery } from '../src/index.js';
import { b64, pem } from './helpers.js';

const data: LocalTrustData = { entities: [], anchors: [], frameworks: [], source: 'snapshot' };
const evaluator = new LocalEvaluator(async () => ({ didDocument: null, didResolutionMetadata: { error: 'notFound' }, didDocumentMetadata: {} }) as never);
const ok = { identifier: 'https://x.example' };
const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

const wrong: Array<[string, Record<string, unknown>]> = [
  ['subject.x5c[0]', { subject: { x5c: [null] } }],
  ['subject.x5c[1]', { subject: { x5c: [b64(pem('iaca')), 7] } }],
  ['subject.x5c', { subject: { x5c: b64(pem('iaca')) } }],
  ['subject.identifier', { subject: { identifier: 7 } }],
  ['subject.kid', { subject: { identifier: did, kid: true } }],
  ['context.credentialTypes[0]', { subject: ok, context: { credentialTypes: [7] } }],
  ['context.credentialTypes[1]', { subject: ok, context: { credentialTypes: ['UniversityDegreeCredential', null] } }],
  ['context.credentialTypes', { subject: ok, context: { credentialTypes: 'UniversityDegreeCredential' } }],
  ['context.credentialType', { subject: ok, context: { credentialType: 7 } }],
  ['context.credentialFormat', { subject: ok, context: { credentialFormat: ['mso_mdoc'] } }],
  ['context.responseUri', { subject: ok, context: { responseUri: { uri: 'https://x.example' } } }],
];

describe('a query member of the wrong type', () => {
  it('is refused, naming the member', async () => {
    for (const [member, query] of wrong) {
      await expect(evaluator.evaluate({ role: 'issuer', ...query } as unknown as TrustQuery, data), member)
        .rejects.toThrow(new RegExp(`^${member.replace(/[[\].]/g, '\\$&')} must be (a string|a list of strings)$`));
    }
  });

  it('is absent when it is null, and read when it is a string', async () => {
    const absent = await evaluator.evaluate({ role: 'issuer', subject: { identifier: 'https://x.example', kid: null, x5c: null },
      context: { credentialType: null, credentialFormat: null, responseUri: null, credentialTypes: null } } as unknown as TrustQuery, data);
    expect(absent.decision).toBe('UNKNOWN');
    const read = await evaluator.evaluate({ role: 'issuer', subject: { identifier: 'https://x.example' },
      context: { credentialType: 'T', credentialFormat: 'ldp_vc', credentialTypes: ['T', 'U'] } }, data);
    expect(read.decision).toBe('UNKNOWN');
  });
});
