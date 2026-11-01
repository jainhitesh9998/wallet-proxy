import { describe, expect, it } from 'vitest';
import { cbor, bytes, decodeIssuerSigned, parseCoseSign1, coseX5chain, extractIssuerInfo } from '../src/index.js';
import { fixture } from './helpers.js';

describe('CBOR', () => {
  it('round-trips integers, strings, maps, tags and bigints deterministically', () => {
    const value = new Map<unknown, unknown>([[1, -7], ['a', [1, 'x', new Uint8Array([1, 2])]], [-1, new cbor.Tagged(24, new Uint8Array([0xa0]))],
      ['big', 2n ** 70n], ['f', 1.5], ['t', true], ['n', null]]);
    const enc = cbor.encode(value);
    const dec = cbor.decode(enc) as Map<unknown, unknown>;
    expect(dec.get(1)).toBe(-7);
    expect((dec.get(-1) as InstanceType<typeof cbor.Tagged>).tag).toBe(24);
    expect(dec.get('big')).toBe(2n ** 70n);
    expect(dec.get('f')).toBe(1.5);
    expect(bytes.toHex(cbor.encode(cbor.decode(enc)))).toBe(bytes.toHex(enc));
  });

  it('encodes the OpenID4VP handover test vector hash input shape', () => {
    expect(bytes.toHex(cbor.encode(['x', null, 1]))).toBe('836178f601');
  });
});

describe('mdoc extraction (real MOSIP collab sample)', () => {
  const sample = JSON.parse(fixture('MockMdl-DrivingLicenseCredential.json').toString());
  const credential = sample.credentials?.[0]?.credential ?? sample.credential;

  it('decodes the non-standard {docType, issuerSigned} wrapper', () => {
    const { issuerSigned, docType } = decodeIssuerSigned(credential);
    expect(docType).toBe('org.iso.18013.5.1.mDL');
    const auth = parseCoseSign1(cbor.mapGet(issuerSigned, 'issuerAuth'));
    expect(auth.protectedHeader.get(1)).toBe(-7);
    expect(coseX5chain(auth)).toHaveLength(1);
  });

  it('extracts issuer material', () => {
    const info = extractIssuerInfo(credential, 'mso_mdoc');
    expect(info.x5c).toHaveLength(1);
    expect(info.credentialType).toBe('org.iso.18013.5.1.mDL');
  });

  it('extracts ldp_vc issuer and verification method (cross-DID key)', () => {
    const land = JSON.parse(fixture('Land-LandStatementCredential_VCDM2.0.json').toString());
    const vc = land.credentials?.[0]?.credential ?? land.credential;
    const info = extractIssuerInfo(vc, 'ldp_vc');
    expect(info.issuer).toBe('did:web:injicertify-landregistry.collab.mosip.net');
    expect(info.kid).toMatch(/^did:web:inji\.github\.io:inji-config:collab:landregistry#/);
    expect(info.credentialType).toBe('LandStatementCredential');
  });
});
