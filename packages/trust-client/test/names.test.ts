/**
 * The text form of a distinguished name is part of the contract with the service: both render the same string from
 * the same bytes (Certificates.rfc2253 in Java) and compare. The inputs and expectations here are those of the Java
 * NameRenderingTest; the shared vectors add real certificates.
 */
import { describe, expect, it } from 'vitest';
import { readSingle } from '../src/encoding/der.js';
import { parseCountry, parseName } from '../src/x509/certificate.js';

const hex = (s: string) => Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)));
const render = (der: string) => { const d = hex(der); return parseName(d, readSingle(d)); };
const country = (der: string) => { const d = hex(der); return parseCountry(d, readSingle(d)); };

describe('distinguished names as text (the same rules as the service)', () => {
  it('writes the last RDN first, with keywords for the common types', () => {
    const der = '3036310b300906035504061302555431133011060355040a0c0a55746f70696120444d563112301006035504030c0955746f706961204453';
    expect(render(der)).toBe('CN=Utopia DS,O=Utopia DMV,C=UT');
    expect(country(der)).toBe('UT');
  });

  it('escapes special characters wherever they stand, and spaces at either end', () => {
    expect(render('3020311e301c06035504030c1520612c623d632b643c653e6623673b6822695c6a20')).toBe('CN=\\ a\\,b\\=c\\+d\\<e\\>f\\#g\\;h\\"i\\\\j\\ ');
  });

  it('writes other types, and other string types, as hex of their encoding', () => {
    expect(render('304b310b30090603550406130241543110300e06035504610c0756415441542d31310f300d06035504031e060042004d0050310c300a060355040a1603696135310b3009060355040304020102'))
      .toBe('CN=#04020102,O=ia5,CN=#1e060042004d0050,2.5.4.97=#0c0756415441542d31,C=AT');
  });

  it('keeps the attributes of a multi-valued RDN in encoded order, and finds a country inside', () => {
    const der = '302d310f300d060355040a0c0655746f706961311a3009060355040613025858300d06035504030c064f6464204453';
    expect(render(der)).toBe('C=XX+CN=Odd DS,O=Utopia');
    expect(country(der)).toBe('XX');
    expect(country('3011310f300d060355040a0c0655746f706961')).toBeUndefined();
  });

  it('renders bytes that are not UTF-8 as hex', () => {
    expect(render('3011310f300d060355040313064dfc6c6c6572')).toBe('CN=#13064dfc6c6c6572');
    // Overlong and surrogate encodings are not UTF-8 either.
    expect(render('300d310b300906035504030c02c0af')).toBe('CN=#0c02c0af');
    expect(render('300e310c300a06035504030c03eda080')).toBe('CN=#0c03eda080');
  });
});
