/**
 * The library reads the role of a query exactly as conformance/evaluation/roles.json says, and the service is held to the
 * same file (RoleSpellingsTest.java): a spelling one side reads and the other does not would put a question under a
 * mechanism on one side and under none on the other.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { LocalEvaluator, readRole, ROLE_SPELLINGS, type LocalTrustData } from '../src/evaluation/local.js';

interface Roles { spellings: Record<string, string>; variants: Record<string, string>; absent: string[]; refused: string[] }
const roles = JSON.parse(readFileSync(new URL('../../../conformance/evaluation/roles.json', import.meta.url), 'utf8')) as Roles;

/** The registry's name of a role the library reads. */
const registryName = (role: string | undefined) => (role === undefined ? undefined : role === 'issuer' ? 'CREDENTIAL_ISSUER' : role.toUpperCase());

describe('the role of a query', () => {
  it('is read exactly as the shared list says', () => {
    expect({ ...ROLE_SPELLINGS }).toEqual(roles.spellings);
    for (const [spelling, role] of [...Object.entries(roles.spellings), ...Object.entries(roles.variants)]) {
      expect(registryName(readRole(spelling)), JSON.stringify(spelling)).toBe(role);
    }
    for (const spelling of [undefined, null, ...roles.absent]) expect(readRole(spelling), JSON.stringify(spelling)).toBeUndefined();
    for (const spelling of [...roles.refused, 7, {}]) expect(() => readRole(spelling), JSON.stringify(spelling)).toThrow(/^Unknown role/);
  });

  it('refuses a query whose role it does not read, instead of deciding it as one without a role', async () => {
    const data: LocalTrustData = { entities: [], anchors: [], frameworks: [], source: 'snapshot' };
    const ev = new LocalEvaluator(async () => ({ didDocument: null, didResolutionMetadata: { error: 'notFound' }, didDocumentMetadata: {} }) as never);
    await expect(ev.evaluate({ role: 'holder' as never, subject: { identifier: 'https://issuer.example' } }, data)).rejects.toThrow(/Unknown role 'holder'/);
    expect((await ev.evaluate({ role: 'Credential-Issuer' as never, subject: { identifier: 'https://issuer.example' } }, data)).decision).toBe('UNKNOWN');
  });
});
