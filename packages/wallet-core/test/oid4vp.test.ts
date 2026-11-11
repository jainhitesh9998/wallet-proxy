/** OpenID4VP 1.0: request authentication per client identifier prefix, DCQL evaluation, and what a presentation contains. */
import { describe, expect, it } from 'vitest';
import { decodeJws, parseCertificate, verifyJws } from '@vctrust/trust-client/primitives';
import { disclosureDigest, evaluateDcql, presentSdJwt, resolveAuthorizationRequest, selectDisclosures, decodeDisclosure, SoftwareKey,
  type AuthorizationRequest, type DcqlQuery, type StoredCredential } from '../src/index.js';
import { b64, enc, entity, es256, fakeFetch, pem, pinnedTrust } from './support.js';

const rpHash = parseCertificate(pem('rp')).sha256;
const trust = pinnedTrust([{ domain: 'verifier-access', certificate: pem('rp-ca') }], [
  entity('bank', ['VERIFIER'], [{ type: 'DNS', value: 'verifier.example' }], { display: [{ locale: 'en', name: 'Bank of Utopia', logoUri: 'https://verifier.example/logo.png' }] }),
]);
const base = (clientId: string, extra: Record<string, unknown> = {}) => ({ client_id: clientId, response_type: 'vp_token', response_mode: 'direct_post', nonce: 'n-0S6_WzA2Mj',
  response_uri: 'https://verifier.example/post', dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] } }] },
  client_metadata: { client_name: 'Totally a bank', logo_uri: 'https://evil.example/logo.png' }, ...extra });
const signed = (payload: object, key = 'rp', header: Record<string, unknown> = {}) => es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))], ...header }, payload, key);
const serve = (jwt: string) => fakeFetch({ 'https://verifier.example/req/1': () => new Response(jwt, { headers: { 'Content-Type': 'application/oauth-authz-req+jwt' } }) });
const uri = (clientId: string, requestUri = 'https://verifier.example/req/1') => `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`;
const resolve = (clientId: string, jwt: string, t = trust) => resolveAuthorizationRequest(uri(clientId), t, serve(jwt));

describe('request authentication', () => {
  it('accepts x509_hash and x509_san_dns requests signed by a certificate under a verifier anchor', async () => {
    for (const cid of [`x509_hash:${rpHash}`, 'x509_san_dns:verifier.example']) {
      const { request, verifier } = await resolve(cid, signed(base(cid)));
      expect(request).toMatchObject({ nonce: 'n-0S6_WzA2Mj', signed: true, responseUri: 'https://verifier.example/post' });
      expect(verifier.trust.decision).toBe('TRUSTED');
      expect(verifier.refusal).toBeUndefined();
    }
  });

  it('shows the registry\'s name and logo for a verifier it knows, and never fetches an unknown party\'s logo', async () => {
    const known = (await resolve('x509_san_dns:verifier.example', signed(base('x509_san_dns:verifier.example')))).verifier;
    expect(known).toMatchObject({ name: 'Bank of Utopia', logoUri: 'https://verifier.example/logo.png' });
    expect(known.nameSelfDeclared).toBeUndefined();
    const stranger = (await resolve('x509_san_dns:verifier.example', signed(base('x509_san_dns:verifier.example')), pinnedTrust([]))).verifier;
    expect(stranger).toMatchObject({ name: 'Totally a bank', nameSelfDeclared: true });
    expect(stranger.logoUri).toBeUndefined();
    expect(stranger.refusal).toMatch(/does not chain to a trusted verifier CA/);
  });

  it('rejects a hash mismatch, a wrong typ, a client_id mismatch, a forged signature and presentation_definition', async () => {
    await expect(resolve('x509_hash:AAAA', signed(base('x509_hash:AAAA')))).rejects.toThrow(/x509_hash/);
    await expect(resolve(`x509_hash:${rpHash}`, signed(base(`x509_hash:${rpHash}`), 'rp', { typ: 'JWT' }))).rejects.toThrow(/typ/);
    await expect(resolve('x509_san_dns:verifier.example', signed(base(`x509_hash:${rpHash}`)))).rejects.toThrow(/client_id/);
    await expect(resolve(`x509_hash:${rpHash}`, signed(base(`x509_hash:${rpHash}`, { presentation_definition: {} })))).rejects.toThrow(/presentation_definition/);
    await expect(resolve('x509_san_dns:verifier.example', signed(base('x509_san_dns:verifier.example'), 'ds'))).rejects.toThrow(/signature/);
    await expect(resolve('x509_san_dns:other.example', signed(base('x509_san_dns:other.example')))).rejects.toThrow(/no SAN dNSName/);
  });

  it('refuses a response_uri on another host than an unregistered x509_san_dns verifier\'s', async () => {
    const anchorsOnly = pinnedTrust([{ domain: 'verifier-access', certificate: pem('rp-ca') }]);
    const { verifier } = await resolve('x509_san_dns:verifier.example', signed(base('x509_san_dns:verifier.example', { response_uri: 'https://collector.example/post' })), anchorsOnly);
    expect(verifier.trust.decision).toBe('NOT_TRUSTED');
    expect(verifier.refusal).toMatch(/response_uri host/);
  });

  it('fetches request objects and posts responses over https only', async () => {
    const cid = `x509_hash:${rpHash}`;
    await expect(resolveAuthorizationRequest(uri(cid, 'http://verifier.example/req/1'), trust, serve(signed(base(cid))))).rejects.toThrow(/request_uri must be an https URL/);
    await expect(resolve(cid, signed(base(cid, { response_uri: 'http://verifier.example/post' })))).rejects.toThrow(/response_uri must be an https URL/);
    // Development hosts are named explicitly.
    const local = fakeFetch({ 'http://localhost:8792/req/1': () => new Response(signed(base(cid, { response_uri: 'http://localhost:8792/post' })), { headers: { 'Content-Type': 'application/oauth-authz-req+jwt' } }) });
    const { request } = await resolveAuthorizationRequest(uri(cid, 'http://localhost:8792/req/1'), trust, local, ['localhost']);
    expect(request.responseUri).toBe('http://localhost:8792/post');
  });

  it('refuses a DCQL query it cannot read exactly: an empty claims path would disclose a whole credential', async () => {
    const cid = `x509_hash:${rpHash}`;
    const withQuery = (credentials: unknown, extra: Record<string, unknown> = {}) => resolve(cid, signed(base(cid, { dcql_query: { credentials, ...extra } })));
    const pid = { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] } };
    await expect(withQuery([{ ...pid, claims: [{ path: [] }] }])).rejects.toThrow(/dcql_query is not valid: .*a claim has no path/);
    await expect(withQuery([{ ...pid, claims: [] }])).rejects.toThrow(/claims must be a non-empty list/);
    await expect(withQuery([{ ...pid, claims: [{ path: ['a', -1] }] }])).rejects.toThrow(/claims path holds something other/);
    await expect(withQuery([{ ...pid, claims: [{ path: ['a', {}] }] }])).rejects.toThrow(/claims path holds something other/);
    await expect(withQuery([{ id: 'mdl', format: 'mso_mdoc', claims: [{ path: ['org.iso.18013.5.1'] }] }])).rejects.toThrow(/mdoc claims path is a namespace and an element identifier/);
    await expect(withQuery([pid, pid])).rejects.toThrow(/used twice/);
    await expect(withQuery([])).rejects.toThrow(/credentials must be a non-empty list/);
    await expect(withQuery([{ ...pid, claims: [{ id: 'a', path: ['x'] }], claim_sets: [['b']] }])).rejects.toThrow(/claim_sets must list ids of its claims/);
    await expect(withQuery([pid], { credential_sets: [{ options: [['other']] }] })).rejects.toThrow(/credential set must list options/);
    expect((await withQuery([{ ...pid, claims: [{ path: ['address', null, 'street'] }] }])).request.dcqlQuery.credentials).toHaveLength(1);
  });

  it('refuses requests it cannot answer as OpenID4VP 1.0 requires', async () => {
    const cid = `x509_hash:${rpHash}`;
    const bad = async (extra: Record<string, unknown>) => resolve(cid, signed(base(cid, extra)));
    await expect(bad({ response_type: 'code' })).rejects.toMatchObject({ code: 'unsupported_response_type' });
    await expect(bad({ nonce: undefined })).rejects.toThrow(/nonce is required/);
    await expect(bad({ dcql_query: undefined })).rejects.toThrow(/dcql_query is required/);
    await expect(bad({ scope: 'pid' })).rejects.toThrow(/must not both be present/);
    await expect(bad({ response_mode: 'fragment' })).rejects.toThrow(/Unsupported response_mode/);
    await expect(bad({ transaction_data: ['x'] })).rejects.toMatchObject({ code: 'invalid_transaction_data' });
    await expect(bad({ redirect_uri: 'https://verifier.example/cb' })).rejects.toThrow(/redirect_uri must not be present/);
    await expect(bad({ response_mode: 'direct_post.jwt' })).rejects.toThrow(/no P-256 key with alg ECDH-ES/);
    await expect(bad({ exp: 1000 })).rejects.toThrow(/expired/);
  });
});

describe('DCQL and presentations', () => {
  const holder = SoftwareKey.generate();
  const disclosures = [['s1', 'given_name', 'Erika'], ['s2', 'family_name', 'Mustermann'], ['s3', 'birthdate', '1984-01-26']].map(enc);
  const credential = (cnf: unknown = { jwk: holder.publicJwk }) => `${es256({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [b64(pem('rp'))] },
    { vct: 'urn:eudi:pid:1', _sd_alg: 'sha-256', _sd: disclosures.map(disclosureDigest), cnf }, 'rp')}~${disclosures.join('~')}~`;
  const stored = (id: string, extra: Partial<StoredCredential> = {}): StoredCredential => ({ id, format: 'dc+sd-jwt', configurationId: 'pid', credential: credential(),
    credentialIssuer: 'https://issuer.example', holderKeyId: holder.id, holderJwk: holder.publicJwk, issuedAt: new Date().toISOString(),
    report: { valid: true, credentialType: 'urn:eudi:pid:1' } as never, ...extra });
  const pid = { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claims: [{ path: ['given_name'] }] };

  it('selects one option per required credential set and leaves optional sets to the user', async () => {
    const query: DcqlQuery = { credentials: [pid, { ...pid, id: 'age', claims: [{ path: ['birthdate'] }] }, { id: 'none', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' } }],
      credential_sets: [{ options: [['none'], ['pid']] }, { options: [['age']], required: false }, { options: [['none']], required: false }] };
    const r = await evaluateDcql(query, [stored('c1')]);
    expect(r).toMatchObject({ satisfied: true, selected: ['pid'], optional: ['age'] });
    const unsatisfied = await evaluateDcql({ credentials: [{ ...pid, claims: [{ path: ['not_there'] }] }] }, [stored('c1')]);
    expect(unsatisfied).toMatchObject({ satisfied: false, reason: 'No matching credential for pid' });
  });

  it('never offers a credential that failed its last verification, is pending, or whose issuer is no longer trusted', async () => {
    const candidates = async (c: StoredCredential) => (await evaluateDcql({ credentials: [pid] }, [c])).matches[0]!.candidates.length;
    expect(await candidates(stored('ok'))).toBe(1);
    expect(await candidates(stored('revoked', { report: { valid: false, credentialType: 'urn:eudi:pid:1' } as never }))).toBe(0);
    expect(await candidates(stored('distrusted', { report: { valid: true, credentialType: 'urn:eudi:pid:1', trust: { decision: 'NOT_TRUSTED' } } as never }))).toBe(0);
    expect(await candidates(stored('pending', { credential: undefined, pending: { transactionId: 't', interval: 5 } }))).toBe(0);
  });

  it('requires cryptographic holder binding unless the verifier waives it', async () => {
    const bearer = stored('bearer', { credential: credential(undefined), unbound: true });
    expect((await evaluateDcql({ credentials: [pid] }, [bearer])).satisfied).toBe(false);
    expect((await evaluateDcql({ credentials: [{ ...pid, require_cryptographic_holder_binding: false }] }, [bearer])).satisfied).toBe(true);
  });

  it('matches claim values and claim sets', async () => {
    const withValues = { ...pid, claims: [{ path: ['given_name'], values: ['Erika', 'Max'] }] };
    expect((await evaluateDcql({ credentials: [withValues] }, [stored('c1')])).satisfied).toBe(true);
    expect((await evaluateDcql({ credentials: [{ ...pid, claims: [{ path: ['given_name'], values: ['Max'] }] }] }, [stored('c1')])).satisfied).toBe(false);
    const sets = { ...pid, claims: [{ id: 'a', path: ['nickname'] }, { id: 'b', path: ['given_name'] }, { id: 'c', path: ['family_name'] }], claim_sets: [['a'], ['b', 'c']] };
    const r = await evaluateDcql({ credentials: [sets] }, [stored('c1')]);
    expect(r.matches[0]!.claims.map((c) => c.id)).toEqual(['b', 'c']);
  });

  const request = { clientId: 'x509_san_dns:verifier.example', nonce: 'nonce-1', responseUri: 'https://verifier.example/post', responseMode: 'direct_post',
    clientMetadata: {} } as unknown as AuthorizationRequest;

  it('presents an SD-JWT VC with only the requested disclosures and a key binding JWT over them', async () => {
    const vp = await presentSdJwt(stored('c1'), [{ path: ['given_name'] }], request, holder);
    const parts = vp.split('~');
    expect(parts).toHaveLength(3);
    expect(decodeDisclosure(parts[1]!).name).toBe('given_name');
    const kb = decodeJws(parts[2]!);
    expect(kb.header.typ).toBe('kb+jwt');
    expect(kb.payload).toMatchObject({ aud: 'x509_san_dns:verifier.example', nonce: 'nonce-1' });
    expect(kb.payload.sd_hash).toBe(disclosureDigest(`${parts[0]}~${parts[1]}~`));
    expect(verifyJws(kb, holder.publicJwk)).toBe(true);
  });

  it('discloses nothing when no claims are requested', async () => {
    const vp = await presentSdJwt(stored('c1'), [], request, holder);
    expect(vp.split('~')).toHaveLength(2);
    const payload = decodeJws<Record<string, unknown>>(credential().split('~')[0]!).payload;
    expect(selectDisclosures(payload, disclosures.map(decodeDisclosure), [{ path: ['given_name'] }, { path: ['birthdate'] }]).map((d) => d.name)).toEqual(['given_name', 'birthdate']);
  });
});
