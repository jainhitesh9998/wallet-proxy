/**
 * The status check the verifier applies to W3C credentials, on status lists the reference issuer would never serve:
 * Bitstring Status List v1.0 section 3.2 (Validate Algorithm), the matching status purposes and the minimum length.
 */
import { createCredential, createList } from '@digitalbazaar/vc-bitstring-status-list';
import { beforeAll, describe, expect, it } from 'vitest';
import { createAssertionKeys, didDocument, documentLoader, signCredential, verifyCredential } from '../src/ldp.mjs';

const DID = 'did:web:issuer.example';
const LIST_URL = 'https://issuer.example/status/1';
const validFrom = '2026-01-01T00:00:00Z';

describe('Bitstring Status List validation', () => {
  let sign;
  let statics;
  /** A credential that points at entry 7 of the list, and a loader that serves a list of the given length and purpose. */
  async function credentialWithList({ length, listPurpose = 'revocation', entryPurpose = 'revocation', revoked = false }) {
    const list = await createList({ length });
    list.setStatus(7, revoked);
    const listCredential = await sign({ ...(await createCredential({ id: LIST_URL, list, statusPurpose: listPurpose })), issuer: DID, validFrom });
    const credential = await sign({ '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential'], issuer: DID, validFrom,
      credentialSubject: { id: 'did:example:subject' },
      credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: entryPurpose, statusListIndex: '7', statusListCredential: LIST_URL } });
    return { credential, loader: documentLoader({ statics: { ...statics, [LIST_URL]: listCredential } }) };
  }
  const check = async (options) => { const { credential, loader } = await credentialWithList(options); return verifyCredential(credential, loader); };

  beforeAll(async () => {
    const keys = await createAssertionKeys(DID);
    statics = { [DID]: await didDocument(DID, keys) };
    sign = (credential) => signCredential(credential, keys['ecdsa-rdfc-2019'], 'ecdsa-rdfc-2019', documentLoader({ statics }));
  });

  it('accepts an unset entry of a list of the minimum length, and refuses a set one', async () => {
    expect((await check({ length: 131_072 })).verified).toBe(true);
    const revoked = await check({ length: 131_072, revoked: true });
    expect(revoked.verified).toBe(false);
    expect(revoked.statusResult.error.message).toMatch(/revocation status is set/);
  });

  it('refuses a list with fewer than 131,072 entries', async () => {
    const result = await check({ length: 131_072 - 8 });
    expect(result.verified).toBe(false);
    expect(result.statusResult.error.message).toMatch(/STATUS_LIST_LENGTH_ERROR/);
  });

  it('refuses a list whose purpose is not the purpose of the entry', async () => {
    const result = await check({ length: 131_072, listPurpose: 'revocation', entryPurpose: 'suspension' });
    expect(result.verified).toBe(false);
    expect(result.statusResult.error.message).toMatch(/does not match the status purpose/);
  });
});
