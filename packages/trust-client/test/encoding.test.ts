import { describe, expect, it } from 'vitest';
import { cbor, bytes, decodeIssuerSigned, parseCoseSign1, coseX5chain, extractIssuerInfo } from '../src/primitives.js';
import { fixture } from './helpers.js';
import * as der from '../src/encoding/der.js';

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
  const sample = JSON.parse(fixture('mosip-mock-mdl.json').toString());
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
    const land = JSON.parse(fixture('mosip-land-statement-ldp.json').toString());
    const vc = land.credentials?.[0]?.credential ?? land.credential;
    const info = extractIssuerInfo(vc, 'ldp_vc');
    expect(info.issuer).toBe('did:web:injicertify-landregistry.collab.mosip.net');
    expect(info.kid).toMatch(/^did:web:inji\.github\.io:inji-config:collab:landregistry#/);
    expect(info.credentialType).toBe('LandStatementCredential');
  });
});

describe('strict DER reader', () => {
  const b = (hex: string) => new Uint8Array(Buffer.from(hex.replace(/\s/g, ''), 'hex'));

  it('reads definite lengths in their shortest form only', () => {
    expect(der.readTlv(b('0403 010203'), 0)).toEqual({ tag: 0x04, start: 0, valueStart: 2, end: 5 });
    const long = new Uint8Array(3 + 200);
    long.set([0x04, 0x81, 200]);
    expect(der.readTlv(long, 0)).toMatchObject({ valueStart: 3, end: 203 });
    expect(() => der.readTlv(b('0480 010203 0000'), 0)).toThrow(/indefinite length/);
    expect(() => der.readTlv(b('048103 010203'), 0)).toThrow(/shortest form/);             // 0x81 for a length below 128
    expect(() => der.readTlv(b('04820003 010203'), 0)).toThrow(/shortest form/);           // leading zero length octet
    expect(() => der.readTlv(b('0485 0000000003 010203'), 0)).toThrow(/Unsupported DER length/);
    expect(() => der.readTlv(b('0405 010203'), 0)).toThrow(/DER length exceeds data/);
    expect(() => der.readTlv(b('04'), 0)).toThrow(/DER truncated/);
    expect(() => der.readTlv(b('1f8101 00'), 0)).toThrow(/tag numbers above 30/);
    expect(() => der.readSingle(b('0401ff 00'), 'thing')).toThrow(/Trailing bytes after the thing/);
    expect(() => der.children(b('0403 010203'), der.readTlv(b('0403 010203'), 0))).toThrow(/not constructed/);
    expect(() => der.children(b('3003 0405 01'), der.readTlv(b('3003 0405 01'), 0))).toThrow(/DER/);
  });

  it('reads INTEGER, BOOLEAN, BIT STRING and OBJECT IDENTIFIER in their one DER form', () => {
    const int = (hex: string) => { const d = b(hex); return der.unsignedInteger(d, der.readTlv(d, 0), 'n'); };
    expect(int('0201 00')).toBe(0n);
    expect(int('0201 7f')).toBe(127n);
    expect(int('0202 0080')).toBe(128n);
    expect(int('0203 010001')).toBe(65537n);
    expect(() => int('0200')).toThrow(/empty INTEGER/);
    expect(() => int('0202 0001')).toThrow(/not a minimally encoded INTEGER/);
    expect(() => int('0202 007f')).toThrow(/not a minimally encoded INTEGER/);
    expect(() => int('0202 ff80')).toThrow(/not a minimally encoded INTEGER/);
    expect(() => int('0201 ff')).toThrow(/negative/);
    expect(() => int('0201 80')).toThrow(/negative/);
    expect(() => int('0401 01')).toThrow(/has tag 0x4, expected 0x2/);
    const small = (hex: string) => { const d = b(hex); return der.smallInteger(d, der.readTlv(d, 0), 'n'); };
    expect(small('0201 02')).toBe(2);
    expect(() => small('0208 7fffffffffffffff')).toThrow(/too large/);

    const bool = (hex: string) => { const d = b(hex); return der.booleanValue(d, der.readTlv(d, 0), 'flag'); };
    expect(bool('0101 ff')).toBe(true);
    expect(bool('0101 00')).toBe(false);
    for (const bad of ['0101 01', '0101 fe', '0102 ffff', '0100']) expect(() => bool(bad), bad).toThrow(/not a DER BOOLEAN/);

    const bits = (hex: string) => { const d = b(hex); return der.bitString(d, der.readTlv(d, 0), 'bits'); };
    expect(bits('0302 0780')).toEqual({ bytes: b('80'), unused: 7 });
    expect(bits('0301 00')).toEqual({ bytes: b(''), unused: 0 });
    expect(() => bits('0300')).toThrow(/empty BIT STRING/);
    expect(() => bits('0302 0880')).toThrow(/invalid unused-bits count/);
    expect(() => bits('0301 01')).toThrow(/invalid unused-bits count/);
    expect(() => bits('0302 0781')).toThrow(/non-zero unused bits/);
    expect(() => der.octetAlignedBitString(b('0302 0780'), der.readTlv(b('0302 0780'), 0), 'key')).toThrow(/not a whole number of octets/);

    expect(der.decodeOid(b('2a8648ce3d030107'))).toBe('1.2.840.10045.3.1.7');
    expect(der.decodeOid(b('551d13'))).toBe('2.5.29.19');
    expect(() => der.decodeOid(b(''))).toThrow(/malformed OBJECT IDENTIFIER/);
    expect(() => der.decodeOid(b('551d93'))).toThrow(/malformed OBJECT IDENTIFIER/);       // ends inside a sub-identifier
    expect(() => der.decodeOid(b('551d8013'))).toThrow(/not in its shortest form/);         // padded sub-identifier
  });
});

