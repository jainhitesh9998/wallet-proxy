/**
 * SD-JWT VC verification: what a credential must be to be kept. Each refusal below is one the specifications demand
 * (RFC 9901 §7.1, SD-JWT VC §3.2, HAIP 1.0 §6.1); the credentials are signed with the test PKI.
 */
import { describe, expect, it } from 'vitest';
import { bytes } from '@vctrust/trust-client/primitives';
import { decodeDisclosure, disclosureDigest, holderBinding, parseSdJwt, reconstruct, SoftwareKey, verifySdJwtVc } from '../src/index.js';
import { b64, enc, es256, pem, pinnedTrust } from './support.js';

const trust = pinnedTrust([{ domain: 'credential-issuer', certificate: pem('rp-ca') }]);
const holder = SoftwareKey.generate();
const disclosure = (...parts: unknown[]) => enc(parts);
const D = { given: disclosure('s1', 'given_name', 'Erika'), family: disclosure('s2', 'family_name', 'Mustermann'), birth: disclosure('s3', 'birthdate', '1984-01-26') };
const seconds = () => Math.floor(Date.now() / 1000);

interface Options { header?: Record<string, unknown>; payload?: Record<string, unknown>; disclosures?: string[]; signer?: string; tail?: string }

/** An SD-JWT VC as HAIP profiles it, signed by the test "rp" certificate (issued by rp-ca); every part can be replaced. */
function sdJwt({ header = {}, payload = {}, disclosures = Object.values(D), signer = 'rp', tail = '~' }: Options = {}): string {
  const jwt = es256({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [b64(pem('rp'))], ...header },
    { vct: 'urn:eudi:pid:1', iat: seconds(), exp: seconds() + 3600, _sd_alg: 'sha-256', _sd: Object.values(D).map(disclosureDigest), cnf: { jwk: holder.publicJwk }, ...payload }, signer);
  return `${jwt}${disclosures.map((d) => `~${d}`).join('')}${tail}`;
}
const verify = (credential: string, options: Partial<Parameters<typeof verifySdJwtVc>[1]> = {}) => verifySdJwtVc(credential, { trust, holderJwk: holder.publicJwk, ...options });
const failures = async (credential: string, options?: Partial<Parameters<typeof verifySdJwtVc>[1]>) =>
  (await verify(credential, options)).checks.filter((c) => c.status === 'fail').map((c) => `${c.id}: ${c.detail}`);

describe('a conforming SD-JWT VC', () => {
  it('verifies: signature by the certified key, disclosures, validity, holder key, issuer trust', async () => {
    const r = await verify(sdJwt());
    expect(r.checks.filter((c) => c.status !== 'pass')).toEqual([]);
    expect(r).toMatchObject({ valid: true, trusted: true, credentialType: 'urn:eudi:pid:1', trust: { decision: 'TRUSTED', source: 'pinned' } });
    expect(r.claims).toMatchObject({ given_name: 'Erika', family_name: 'Mustermann', birthdate: '1984-01-26', vct: 'urn:eudi:pid:1' });
    expect(r.claims).not.toHaveProperty('_sd');
    expect(r.claims).not.toHaveProperty('_sd_alg');
  });

  it('may withhold disclosures and carry decoy digests', async () => {
    const r = await verify(sdJwt({ disclosures: [D.given], payload: { _sd: [...Object.values(D).map(disclosureDigest), 'decoy-digest-nobody-discloses'] } }));
    expect(r.valid).toBe(true);
    expect(r.claims).toHaveProperty('given_name');
    expect(r.claims).not.toHaveProperty('family_name');
  });

  it('discloses array elements and nested claims', async () => {
    const [de, fr] = [disclosure('s4', 'DE'), disclosure('s5', 'FR')];
    const street = disclosure('s6', 'street_address', 'Heidestraße 17');
    const r = await verify(sdJwt({ disclosures: [D.given, de, street],
      payload: { nationalities: [{ '...': disclosureDigest(de) }, { '...': disclosureDigest(fr) }], address: { locality: 'Köln', _sd: [disclosureDigest(street)] } } }));
    expect(r.valid).toBe(true);
    expect(r.claims).toMatchObject({ nationalities: ['DE'], address: { locality: 'Köln', street_address: 'Heidestraße 17' } });
  });

  it('is read for its holder key without being verified', () => {
    expect(holderBinding('dc+sd-jwt', sdJwt())).toEqual({ jwk: holder.publicJwk });
    expect(holderBinding('dc+sd-jwt', sdJwt({ payload: { cnf: undefined } }))).toEqual({});
  });
});

describe('RFC 9901 §7.1: an SD-JWT that must be rejected', () => {
  const cases: Array<[string, Options, RegExp]> = [
    ['a disclosure nothing refers to', { disclosures: [...Object.values(D), disclosure('s9', 'admin', true)] }, /not referenced by the issuer-signed JWT/],
    ['a digest that occurs twice', { payload: { _sd: [disclosureDigest(D.given), disclosureDigest(D.given)] }, disclosures: [D.given] }, /occurs more than once/],
    ['a disclosure given twice', { disclosures: [D.given, D.given] }, /given twice/],
    ['a disclosed claim that already exists at its level', { payload: { given_name: 'Mallory' } }, /already exists at its level/],
    ['a disclosure named _sd', { payload: { _sd: [disclosureDigest(disclosure('s7', '_sd', ['x']))] }, disclosures: [disclosure('s7', '_sd', ['x'])] }, /reserved claim name _sd/],
    ['a disclosure named ...', { payload: { _sd: [disclosureDigest(disclosure('s7', '...', 'x'))] }, disclosures: [disclosure('s7', '...', 'x')] }, /reserved claim name \.\.\./],
    ['an object property digest that refers to an array element disclosure', { payload: { _sd: [disclosureDigest(disclosure('s7', 'DE'))] }, disclosures: [disclosure('s7', 'DE')] },
      /refers to an array element disclosure/],
    ['an array element digest that refers to an object property disclosure', { payload: { _sd: [], list: [{ '...': disclosureDigest(D.given) }] }, disclosures: [D.given] },
      /refers to an object property disclosure/],
    ['a disclosure with four members', { payload: { _sd: [disclosureDigest(disclosure('s', 'a', 'b', 'c'))] }, disclosures: [disclosure('s', 'a', 'b', 'c')] }, /not \[salt, name, value\]/],
    ['a disclosure that is not JSON', { disclosures: ['bm90LWpzb24'] }, /not base64url-encoded JSON/],
    ['a claim named ...', { payload: { '...': 'x' } }, /reserved for array element digests/],
    ['an _sd that is not an array', { payload: { _sd: 'x' }, disclosures: [] }, /_sd is not an array/],
    ['an _sd_alg below the top level', { payload: { address: { _sd_alg: 'sha-256' } } }, /top level only/],
    ['a hash algorithm other than sha-256', { payload: { _sd_alg: 'sha-512' } }, /Unsupported _sd_alg sha-512/],
    ['a missing final separator', { tail: '' }, /not referenced|not base64url|Not an SD-JWT|key binding JWT/],
    ['a key binding JWT on an issued credential', { tail: '~eyJhbGciOiJFUzI1NiJ9.e30.c2ln' }, /carries no key binding JWT/],
  ];
  for (const [name, options, reason] of cases) {
    it(name, async () => {
      const r = await verify(sdJwt(options));
      expect(r.valid).toBe(false);
      expect(r.checks.find((c) => c.id === 'sdjwt.structure')).toMatchObject({ status: 'fail', detail: expect.stringMatching(reason) });
    });
  }

  it('rebuilds the claims exactly as the specification describes', () => {
    const d = decodeDisclosure(D.given);
    expect(d).toMatchObject({ salt: 's1', name: 'given_name', value: 'Erika', digest: disclosureDigest(D.given) });
    expect(reconstruct({ _sd: [d.digest], _sd_alg: 'sha-256', vct: 'x' }, [d])).toEqual({ claims: { given_name: 'Erika', vct: 'x' }, used: new Set([d.digest]) });
    expect(parseSdJwt('a.b.c~d1~d2~')).toEqual({ issuerJwt: 'a.b.c', disclosures: ['d1', 'd2'] });
    expect(parseSdJwt('a.b.c~d1~k.b.jwt')).toEqual({ issuerJwt: 'a.b.c', disclosures: ['d1'], kbJwt: 'k.b.jwt' });
    expect(() => parseSdJwt('a.b.c')).toThrow(/no "~" separator/);
  });
});

describe('SD-JWT VC and HAIP rules', () => {
  it('requires typ dc+sd-jwt', async () => {
    for (const typ of ['vc+sd-jwt', 'JWT', undefined]) expect(await failures(sdJwt({ header: { typ } }))).toEqual([expect.stringMatching(/^sdjwt\.typ: typ is .*dc\+sd-jwt is required/)]);
  });

  it('requires vct, and the vct that was asked for', async () => {
    expect(await failures(sdJwt({ payload: { vct: undefined } }))).toEqual(['sdjwt.vct: vct is missing']);
    expect(await failures(sdJwt(), { expected: { vct: 'urn:eudi:pid:2' } })).toEqual(['sdjwt.vct: vct urn:eudi:pid:1 is not the requested urn:eudi:pid:2']);
    expect((await verify(sdJwt(), { expected: { vct: 'urn:eudi:pid:1' } })).valid).toBe(true);
  });

  it('refuses vct, cnf, exp or status given as disclosures (SD-JWT VC §3.2.2.2)', async () => {
    const hidden = disclosure('s8', 'vct', 'urn:eudi:pid:1');
    expect(await failures(sdJwt({ payload: { vct: undefined, _sd: [disclosureDigest(hidden)] }, disclosures: [hidden] })))
      .toEqual(expect.arrayContaining([expect.stringMatching(/vct must not be selectively disclosable/)]));
    const exp = disclosure('s8', 'exp', seconds() + 10);
    expect(await failures(sdJwt({ payload: { exp: undefined, _sd: [disclosureDigest(exp)] }, disclosures: [exp] })))
      .toEqual(expect.arrayContaining([expect.stringMatching(/exp must not be selectively disclosable/)]));
  });

  it('verifies the issuer signature only with a key certified in x5c (HAIP §6.1.1)', async () => {
    expect(await failures(sdJwt({ header: { x5c: undefined, kid: 'did:web:issuer.example#key-1' }, payload: { iss: 'did:web:issuer.example' } })))
      .toEqual([expect.stringMatching(/^sdjwt\.structure: No x5c header/)]);
    expect(await failures(sdJwt({ header: { x5c: undefined }, payload: { iss: 'https://issuer.example' } }))).toEqual([expect.stringMatching(/No x5c header/)]);
    // Signed by another key than the certificate's.
    expect(await failures(sdJwt({ signer: 'ds' }))).toEqual([expect.stringMatching(/^sdjwt\.signature: The signature does not verify/)]);
  });

  it('refuses a self-signed certificate in x5c: as signer, or as a trust anchor sent along', async () => {
    expect(await failures(sdJwt({ header: { x5c: [b64(pem('rp')), b64(pem('rp-ca'))] } }))).toEqual([expect.stringMatching(/x5c contains a self-signed certificate/)]);
  });

  it('is not trusted when the certificate chains to no credential-issuer anchor', async () => {
    const r = await verifySdJwtVc(sdJwt(), { trust: pinnedTrust([{ domain: 'mdoc-iaca', certificate: pem('rp-ca') }]), holderJwk: holder.publicJwk });
    expect(r).toMatchObject({ valid: true, trusted: false, trust: { decision: 'UNKNOWN' } });
  });

  it('requires the holder key as cnf.jwk, and this wallet\'s key', async () => {
    expect(await failures(sdJwt({ payload: { cnf: { jwk: SoftwareKey.generate().publicJwk } } }))).toEqual(['sdjwt.holder: cnf.jwk is not the key this wallet proved']);
    expect(await failures(sdJwt({ payload: { cnf: { kid: `did:jwk:${enc(holder.publicJwk)}#0` } } }))).toEqual(['sdjwt.holder: No cnf.jwk, although the wallet proved a key to the issuer']);
    expect(await failures(sdJwt({ payload: { cnf: undefined } }))).toEqual(['sdjwt.holder: No cnf.jwk, although the wallet proved a key to the issuer']);
    // Asked for without a key proof (a configuration with no binding method): a credential without cnf is what was asked for.
    const unbound = await verifySdJwtVc(sdJwt({ payload: { cnf: undefined } }), { trust });
    expect(unbound.valid).toBe(true);
    expect(unbound.checks.find((c) => c.id === 'sdjwt.holder')?.status).toBe('warn');
  });

  it('enforces exp and nbf', async () => {
    expect(await failures(sdJwt({ payload: { exp: seconds() - 1 } }))).toEqual([expect.stringMatching(/^sdjwt\.validity: Expired/)]);
    expect(await failures(sdJwt({ payload: { nbf: seconds() + 600 } }))).toEqual([expect.stringMatching(/^sdjwt\.validity: Not valid before/)]);
    // An issuer whose clock runs a little ahead of this device's: what it just issued is not refused for that.
    expect(await failures(sdJwt({ payload: { nbf: seconds() + 30 } }))).toEqual([]);
    expect(await failures(sdJwt({ payload: { exp: 'tomorrow' } }))).toEqual(['sdjwt.validity: exp / nbf are not numbers']);
    expect((await verify(sdJwt({ payload: { exp: undefined } }))).valid).toBe(true);
  });

  it('says when iss names someone the certificate does not', async () => {
    const named = await verify(sdJwt({ payload: { iss: 'https://verifier.example' } }));
    expect(named.checks.find((c) => c.id === 'sdjwt.iss')).toMatchObject({ status: 'pass' });
    const other = await verify(sdJwt({ payload: { iss: 'https://someone-else.example' } }));
    expect(other.checks.find((c) => c.id === 'sdjwt.iss')).toMatchObject({ status: 'warn', detail: expect.stringMatching(/not a name in the signing certificate/) });
  });

  it('refuses a status it cannot read', async () => {
    expect(await failures(sdJwt({ payload: { status: { status_list: { idx: -1, uri: 'https://issuer.example/status' } } } }))).toEqual([expect.stringMatching(/^sdjwt\.status: status carries no usable status_list/)]);
    expect(await failures(sdJwt({ payload: { status: {} } }))).toEqual([expect.stringMatching(/^sdjwt\.status/)]);
  });

  it('never throws on input that is not an SD-JWT at all', async () => {
    for (const junk of ['', 'not-a-jwt', '~', 'a.b.c~', bytes.base64UrlEncode(new Uint8Array(64))]) {
      const r = await verify(junk);
      expect([r.valid, r.trusted]).toEqual([false, false]);
    }
  });
});
