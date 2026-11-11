/**
 * ISO/IEC 18013-5 mdoc verification: what an issued mdoc must be to be kept, and its status (Token Status List in CWT
 * form). The mdocs are built here, member by member, and signed with the test PKI's Document Signer, so each test can
 * break exactly one rule of the standard.
 */
import { describe, expect, it } from 'vitest';
import { deflateSync } from 'node:zlib';
import { bytes, cbor, digest } from '@vctrust/trust-client/primitives';
import { holderBinding, jwkToCoseKey, SoftwareKey, verifyMdoc } from '../src/index.js';
import { buildMdoc, coseSign1, item, MDL, NS, STATUS_URI, tdate, type Parts } from './mdoc-builder.js';
import { der, pem, pinnedTrust, type Routes } from './support.js';

const { Tagged } = cbor;
const holder = SoftwareKey.generate();
const mdoc = (parts: Parts = {}) => buildMdoc(holder, parts);

const anchors = [{ domain: 'mdoc-iaca', certificate: pem('iaca') }];
const verify = (credential: string, options: Partial<Parameters<typeof verifyMdoc>[1]> = {}, routes: Routes = {}) =>
  verifyMdoc(credential, { trust: pinnedTrust(anchors, [], routes), holderJwk: holder.publicJwk, ...options });
const failures = async (credential: string, options?: Partial<Parameters<typeof verifyMdoc>[1]>) =>
  (await verify(credential, options)).checks.filter((c) => c.status === 'fail').map((c) => `${c.id}: ${c.detail}`);
const validity = (dates: Record<string, unknown>) => (mso: Map<string, unknown>) => { mso.set('validityInfo', new Map(Object.entries(dates))); };

describe('a conforming mdoc', () => {
  it('verifies: COSE signature, MSO, digests, validity, device key, Document Signer chain to the IACA', async () => {
    const r = await verify(mdoc(), { expected: { doctype: MDL } });
    expect(r.checks.filter((c) => c.status === 'fail')).toEqual([]);
    expect(r).toMatchObject({ valid: true, trusted: true, credentialType: MDL, trust: { decision: 'TRUSTED' } });
    expect(r.claims).toEqual({ [NS]: { given_name: 'Ada', family_name: 'Lovelace' } });
    expect(r.checks.find((c) => c.id === 'mdoc.digests')?.detail).toBe('2 element(s) match the MSO (SHA-256)');
    expect(holderBinding('mso_mdoc', mdoc())).toEqual({ jwk: holder.publicJwk });
  });

  it('is not trusted under an IACA nobody vouches for', async () => {
    const r = await verifyMdoc(mdoc(), { trust: pinnedTrust([]), holderJwk: holder.publicJwk });
    expect(r).toMatchObject({ valid: true, trusted: false, trust: { decision: 'UNKNOWN' } });
  });
});

describe('ISO 18013-5 and OpenID4VCI A.2.4: an mdoc that must be refused', () => {
  const cases: Array<[string, Parts, RegExp]> = [
    ['a {docType, issuerSigned} wrapper instead of the IssuerSigned', { wrap: (i) => new Map<string, unknown>([['docType', MDL], ['issuerSigned', i]]) }, /mdoc\.structure: The credential is not an IssuerSigned structure/],
    ['a DeviceResponse instead of the IssuerSigned', { wrap: (i) => new Map<string, unknown>([['version', '1.0'], ['documents', [new Map<string, unknown>([['docType', MDL], ['issuerSigned', i]])]]]) },
      /not an IssuerSigned structure/],
    ['an unknown member next to issuerAuth', { wrap: (i) => new Map([...i, ['extra', 1]]) }, /unknown member extra/],
    ['an MSO that is not wrapped in tag 24', { payload: (m) => cbor.encode(m) }, /not MobileSecurityObjectBytes/],
    ['an MSO without digestAlgorithm', { mso: (m) => { m.delete('digestAlgorithm'); } }, /missing digestAlgorithm/],
    ['an MSO with an unknown digestAlgorithm', { mso: (m) => { m.set('digestAlgorithm', 'MD5'); } }, /digestAlgorithm MD5/],
    ['an MSO of another version', { mso: (m) => { m.set('version', '2.0'); } }, /Unsupported MSO version 2\.0/],
    ['items that are not tag-24 byte strings', { rawItems: true }, /not a tag-24 byte string/],
    ['an item whose digest the MSO does not list', { mso: (m) => { (m.get('valueDigests') as Map<string, Map<number, Uint8Array>>).get(NS)!.delete(1); } }, /mdoc\.digests: Not covered by the MSO: org\.iso\.18013\.5\.1\/family_name/],
    ['an item whose value was changed after signing', { mso: (m) => { (m.get('valueDigests') as Map<string, Map<number, Uint8Array>>).get(NS)!.set(0, new Uint8Array(32)); } }, /mdoc\.digests: Not covered by the MSO: org\.iso\.18013\.5\.1\/given_name/],
    ['two items with the same digestID', { items: [item(0, 'given_name', 'Ada'), item(0, 'family_name', 'Lovelace')] }, /mdoc\.digests/],
    ['an item with a random shorter than 16 bytes', { items: [item(0, 'given_name', 'Ada', new Uint8Array(8))] }, /mdoc\.digests/],
    ['validity dates that are not tdates', { mso: validity({ signed: new Date().toISOString(), validFrom: new Date().toISOString(), validUntil: new Date(Date.now() + 1e6).toISOString() }) }, /mdoc\.validity: validityInfo needs signed, validFrom and validUntil as tdate/],
    ['no signed date', { mso: validity({ validFrom: tdate(new Date(Date.now() - 1000)), validUntil: tdate(new Date(Date.now() + 1e6)) }) }, /mdoc\.validity: validityInfo needs signed/],
    ['a validFrom before signed', { mso: validity({ signed: tdate(new Date()), validFrom: tdate(new Date(Date.now() - 60_000)), validUntil: tdate(new Date(Date.now() + 1e6)) }) }, /validFrom is before signed/],
    ['a signing time before the Document Signer certificate existed', { mso: validity({ signed: tdate(new Date('2001-01-01T00:00:00Z')), validFrom: tdate(new Date(Date.now() - 1000)), validUntil: tdate(new Date(Date.now() + 1e6)) }) },
      /mdoc\.validity: Signed 2001-01-01.* outside the validity of the Document Signer certificate/],
    ['an expired validity', { mso: validity({ signed: tdate(new Date(Date.now() - 3e6)), validFrom: tdate(new Date(Date.now() - 2e6)), validUntil: tdate(new Date(Date.now() - 1e6)) }) }, /mdoc\.validity: Not valid now/],
    ['a validity that has not begun', { mso: validity({ signed: tdate(new Date()), validFrom: tdate(new Date(Date.now() + 1e6)), validUntil: tdate(new Date(Date.now() + 2e6)) }) }, /mdoc\.validity: Not valid now/],
    ['no device key', { mso: (m) => { m.set('deviceKeyInfo', new Map()); } }, /mdoc\.device_key: The MSO has no usable deviceKey/],
    ['a device key that is not this wallet\'s', { mso: (m) => { m.set('deviceKeyInfo', new Map([['deviceKey', jwkToCoseKey(SoftwareKey.generate().publicJwk)]])); } }, /mdoc\.device_key: deviceKey is not the key this wallet proved/],
  ];
  for (const [name, parts, reason] of cases) {
    it(name, async () => {
      const failed = await failures(mdoc(parts));
      expect(failed.join('\n')).toMatch(reason);
    });
  }

  it('a signature that the Document Signer certificate does not verify', async () => {
    // Signed by the rogue key, presented with the genuine Document Signer certificate.
    const forged = (() => {
      const items = [item(0, 'given_name', 'Mallory')];
      const encoded = items.map((i) => new Tagged(24, cbor.encode(i)));
      const mso = new Map<string, unknown>([['version', '1.0'], ['digestAlgorithm', 'SHA-256'], ['valueDigests', new Map([[NS, new Map([[0, digest('SHA-256', cbor.encode(encoded[0]!))]])]])],
        ['deviceKeyInfo', new Map([['deviceKey', jwkToCoseKey(holder.publicJwk)]])], ['docType', MDL],
        ['validityInfo', new Map([['signed', tdate(new Date(Date.now() - 2000))], ['validFrom', tdate(new Date(Date.now() - 1000))], ['validUntil', tdate(new Date(Date.now() + 1e6))]])]]);
      const auth = coseSign1('rogue-ds', cbor.encode(new Tagged(24, cbor.encode(mso))), new Map([[1, -7]]), der('ds'));
      return bytes.base64UrlEncode(cbor.encode(new Map<string, unknown>([['nameSpaces', new Map([[NS, encoded]])], ['issuerAuth', auth]])));
    })();
    expect(await failures(forged)).toEqual(['mdoc.signature: The signature does not verify with the Document Signer key']);
  });

  it('a docType other than the one asked for', async () => {
    expect(await failures(mdoc(), { expected: { doctype: 'eu.europa.ec.eudi.pid.1' } })).toEqual([`mdoc.doctype: docType ${MDL} is not the requested eu.europa.ec.eudi.pid.1`]);
  });

  it('never throws on input that is not an mdoc at all', async () => {
    for (const junk of ['', 'not base64url!', 'AAAA', bytes.base64UrlEncode(cbor.encode('text')), bytes.base64UrlEncode(cbor.encode(new Map([['issuerAuth', 1]])))]) {
      const r = await verify(junk);
      expect([r.valid, r.trusted], junk).toEqual([false, false]);
    }
  });
});

describe('mdoc status (Token Status List, CWT)', () => {
  /** statuslist+cwt with 2-bit entries: index 0 VALID, 1 INVALID, 2 SUSPENDED. */
  function statusListCwt(opts: { signer?: string; sub?: string; exp?: number } = {}): Uint8Array {
    const lst = new Uint8Array(deflateSync(Buffer.from([0b00_10_01_00])));
    const claims = new Map<number, unknown>([[2, opts.sub ?? STATUS_URI], [6, Math.floor(Date.now() / 1000)], [4, opts.exp ?? Math.floor(Date.now() / 1000) + 3600],
      [65533, new Map<string, unknown>([['bits', 2], ['lst', lst]])]]);
    return cbor.encode(new Tagged(18, coseSign1(opts.signer ?? 'ds', cbor.encode(claims), new Map<number, unknown>([[1, -7], [16, 'application/statuslist+cwt']]))));
  }
  const status = async (idx: number, list: () => Uint8Array = () => statusListCwt()) => {
    const r = await verify(mdoc({ status: idx }), {}, { [STATUS_URI]: () => new Response(list() as Uint8Array<ArrayBuffer>, { headers: { 'Content-Type': 'application/statuslist+cwt' } }) });
    return { report: r, check: r.checks.find((c) => c.id === 'mdoc.status')! };
  };

  it('reads the MSO status reference and verifies the signed list', async () => {
    const { report, check } = await status(0);
    expect(report).toMatchObject({ valid: true, trusted: true });
    expect(check).toMatchObject({ status: 'pass', detail: expect.stringMatching(/VALID \(statuslist\+cwt, signer the credential signer\)/) });
  });

  it('fails revoked and suspended credentials', async () => {
    expect((await status(1)).check).toMatchObject({ status: 'fail', detail: expect.stringMatching(/^revoked/) });
    expect((await status(2)).check).toMatchObject({ status: 'fail', detail: expect.stringMatching(/^suspended/) });
  });

  it('accepts a list signer certified by the same trust anchor, and nothing else', async () => {
    expect((await status(1, () => statusListCwt({ signer: 'ds-crldp' }))).check.detail).toMatch(/issued under the credential's trust anchor/);
    expect((await status(1, () => statusListCwt({ signer: 'rogue-ds' }))).check).toMatchObject({ status: 'warn', detail: expect.stringMatching(/signer not trusted/) });
    expect((await status(0, () => statusListCwt({ sub: 'https://elsewhere.example/1' }))).check.detail).toMatch(/sub does not match/);
    expect((await status(0, () => statusListCwt({ exp: 1000 }))).check.detail).toMatch(/expired/);
    const tampered = () => { const b = statusListCwt(); b[b.length - 2]! ^= 0xff; return b; };
    expect((await status(1, tampered)).check.detail).toMatch(/signature invalid/);
  });

  it('says so when the status cannot be fetched: unknown, not valid', async () => {
    const r = await verify(mdoc({ status: 0 }));
    expect(r.checks.find((c) => c.id === 'mdoc.status')?.status).toBe('warn');
  });
});
