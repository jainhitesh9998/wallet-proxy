/**
 * Offline HAIP 1.0 / OpenID4VCI 1.0 / OpenID4VP 1.0 conformance details: credential request/response encryption,
 * refusing invalid credentials, notification timing, attestation proofs, minimal disclosure, holder binding,
 * verifier trust enforcement and error responses.
 */
import { describe, expect, it } from 'vitest';
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { bytes, createTrustClient, decodeJws, parseCertificate } from '@vctrust/trust-client';
import { decryptJwe, disclosureDigest, encryptJwe, evaluateDcql, IssuanceError, KeyValueCredentialStore, MemoryCredentialStore, pickInstance, PresentationRequestError, presentSdJwt,
  reportPresentationError, resolveAuthorizationRequest, selectDisclosures, decodeDisclosure, SoftwareKey, SoftwareKeyStore, verifierRefusal, Wallet,
  type DcqlClaim, type StoredCredential, type JweEnc } from '../src/index.js';
import { demoAttester } from './wallet-provider.js';

const PKI = new URL('../../trust-client/test/fixtures/pki/', import.meta.url);
const pem = (n: string) => readFileSync(new URL(`${n}.pem`, PKI), 'utf8');
const b64 = (p: string) => p.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
const enc = (o: unknown) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(o)));
function es256(header: object, payload: object, keyName: string): string {
  const input = `${enc(header)}.${enc(payload)}`;
  const sig = createSign('SHA256').update(input).sign({ key: createPrivateKey(readFileSync(new URL(`${keyName}.key`, PKI))), dsaEncoding: 'ieee-p1363' });
  return `${input}.${bytes.base64UrlEncode(new Uint8Array(sig))}`;
}
const disclosure = (...d: unknown[]) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(d)));

/** An SD-JWT VC from the rp key (credential-issuer domain under rp-ca) with nested and array disclosures. */
function sdJwt(holder?: SoftwareKey, opts: { signer?: string; typ?: string } = {}) {
  const street = disclosure('s4', 'street', 'Main St 1');
  const nat = [disclosure('s5', 'DE'), disclosure('s6', 'FR')];
  const top = [disclosure('s1', 'given_name', 'Erika'), disclosure('s2', 'family_name', 'Mustermann'),
    disclosure('s3', 'address', { locality: 'Berlin', _sd: [disclosureDigest(street)] })];
  const payload = { iss: 'https://issuer.example', vct: 'urn:eudi:pid:1', iat: Math.floor(Date.now() / 1000), _sd_alg: 'sha-256',
    _sd: top.map(disclosureDigest), nationalities: [{ '...': 'decoy-digest-without-a-disclosure' }, ...nat.map((d) => ({ '...': disclosureDigest(d) }))], ...(holder ? { cnf: { jwk: holder.publicJwk } } : {}) };
  const jwt = es256({ alg: 'ES256', typ: opts.typ ?? 'dc+sd-jwt', x5c: [b64(pem(opts.signer ?? 'rp'))] }, payload, opts.signer ?? 'rp');
  return `${jwt}~${[...top, street, ...nat].join('~')}~`;
}

// ---- issuance --------------------------------------------------------------------------------------------------

const ISSUER = 'https://issuer.example';

interface MockIssuer { fetch: typeof fetch; notifications: string[]; requests: { contentType: string; body: Record<string, unknown> }[] }

function mockIssuer(opts: { requestEnc?: boolean; responseEnc?: boolean; credential: (holderJwk: Record<string, unknown>, configId: string, n: number) => string;
  proofTypes?: Record<string, unknown>; tokenAuthMethods?: string[]; zip?: boolean; batchSize?: number; deferred?: number }): MockIssuer {
  const issuerKey = SoftwareKey.generate();
  const notifications: string[] = [];
  const requests: MockIssuer['requests'] = [];
  let deferredLeft = opts.deferred ?? 0;
  let deferredKeys: Record<string, unknown>[] = [];
  const metadata: Record<string, unknown> = {
    credential_issuer: ISSUER, credential_endpoint: `${ISSUER}/credential`, nonce_endpoint: `${ISSUER}/nonce`, notification_endpoint: `${ISSUER}/notification`,
    deferred_credential_endpoint: `${ISSUER}/deferred`,
    credential_configurations_supported: Object.fromEntries(['pid', 'pid2'].map((id) => [id, { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:1',
      cryptographic_binding_methods_supported: ['jwk'], proof_types_supported: opts.proofTypes ?? { jwt: { proof_signing_alg_values_supported: ['ES256'] } } }])),
    ...(opts.requestEnc ? { credential_request_encryption: { jwks: { keys: [{ ...issuerKey.publicJwk, alg: 'ECDH-ES', use: 'enc', kid: 'req-key' }] },
      enc_values_supported: ['A128GCM'], encryption_required: true } } : {}),
    ...(opts.responseEnc ? { credential_response_encryption: { alg_values_supported: ['ECDH-ES'], enc_values_supported: ['A256GCM'], encryption_required: true } } : {}),
    ...(opts.batchSize ? { batch_credential_issuance: { batch_size: opts.batchSize } } : {}),
  };
  const f = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u === `${ISSUER}/.well-known/openid-credential-issuer`) return Response.json(metadata);
    if (u === `${ISSUER}/.well-known/oauth-authorization-server`) {
      return Response.json({ issuer: ISSUER, token_endpoint: `${ISSUER}/token`, 'pre-authorized_grant_anonymous_access_supported': true,
        ...(opts.tokenAuthMethods ? { token_endpoint_auth_methods_supported: opts.tokenAuthMethods } : {}) });
    }
    if (u === `${ISSUER}/token`) {
      const headers = new Headers(init?.headers);
      requests.push({ contentType: 'token', body: { attested: headers.has('OAuth-Client-Attestation'), ...Object.fromEntries(new URLSearchParams(String(init?.body))) } });
      return Response.json({ access_token: 'at', token_type: 'Bearer' });
    }
    if (u === `${ISSUER}/nonce`) return Response.json({ c_nonce: 'cn-1' });
    if (u === `${ISSUER}/notification`) { notifications.push(JSON.parse(String(init?.body)).event); return new Response(null, { status: 204 }); }
    if (u === `${ISSUER}/deferred`) {
      const auth = new Headers(init?.headers).get('Authorization');
      requests.push({ contentType: 'deferred', body: { auth, ...JSON.parse(String(init?.body)) } });
      if (auth !== 'Bearer at' || JSON.parse(String(init?.body)).transaction_id !== 't-1') return Response.json({ error: 'invalid_transaction_id' }, { status: 400 });
      if (deferredLeft-- > 0) return Response.json({ interval: 1 }, { status: 202 });
      return Response.json({ credentials: deferredKeys.map((k, i) => ({ credential: opts.credential(k, 'pid', i) })), notification_id: 'n-2' });
    }
    if (u === `${ISSUER}/credential`) {
      const contentType = new Headers(init?.headers).get('Content-Type') ?? '';
      const body = contentType === 'application/jwt'
        ? JSON.parse(bytes.utf8Decode(decryptJwe(String(init?.body), (peer) => issuerKey.ecdh(peer)).plaintext)) as Record<string, unknown>
        : JSON.parse(String(init?.body)) as Record<string, unknown>;
      requests.push({ contentType, body });
      // One credential per key: each jwt proof's key, or every key a key attestation lists (OID4VCI F.1, F.3).
      const proofs = body.proofs as { jwt?: string[]; attestation?: string[] };
      const keys = proofs.jwt ? proofs.jwt.flatMap((p) => {
        const h = decodeJws(p).header;
        return h.key_attestation ? decodeJws(String(h.key_attestation)).payload.attested_keys as Record<string, unknown>[] : [h.jwk as Record<string, unknown>];
      }) : decodeJws(proofs.attestation![0]!).payload.attested_keys as Record<string, unknown>[];
      if (keys.length > (opts.batchSize ?? 1)) return Response.json({ error: 'invalid_proof', error_description: 'batch too large' }, { status: 400 });
      if (opts.deferred !== undefined) { deferredKeys = keys; return Response.json({ transaction_id: 't-1', interval: 1 }, { status: 202 }); }
      // Answered in reverse order: the response need not follow the proofs.
      const answer = { credentials: keys.map((k, i) => ({ credential: opts.credential(k, String(body.credential_configuration_id), i) })).reverse(), notification_id: 'n-1' };
      const re = body.credential_response_encryption as { jwk: never; enc: JweEnc } | undefined;
      if (re) {
        const plain = bytes.utf8Encode(JSON.stringify(answer));
        return new Response(opts.zip ? encryptJwe(new Uint8Array(deflateRawSync(plain)), re.jwk, re.enc, { zip: 'DEF' }) : encryptJwe(plain, re.jwk, re.enc),
          { headers: { 'Content-Type': 'application/jwt' } });
      }
      return Response.json(answer);
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
  return { fetch: f, notifications, requests };
}

const offerFor = (ids: string[]) => `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify({ credential_issuer: ISSUER,
  credential_configuration_ids: ids, grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'pac' } } }))}`;
const offer = offerFor(['pid']);

function walletFor(issuer: MockIssuer, extra: Partial<ConstructorParameters<typeof Wallet>[0]> = {}) {
  const trust = createTrustClient({ fetch: issuer.fetch, fallback: { localAnchors: [{ domain: 'credential-issuer', certificate: pem('rp-ca') }] } });
  return new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), fetch: issuer.fetch, redirectUri: 'https://wallet.example/cb', ...extra });
}
/** An SD-JWT VC bound (cnf) to the key in the wallet's proof. */
const issueFor = (jwk: Record<string, unknown>, opts: { signer?: string; typ?: string } = {}) => sdJwt({ publicJwk: jwk } as unknown as SoftwareKey, opts);

describe('issuance (OID4VCI 1.0 / HAIP)', () => {
  it('encrypts the credential request and asks for an encrypted response when the issuer requires it', async () => {
    const issuer = mockIssuer({ requestEnc: true, responseEnc: true, credential: (jwk) => issueFor(jwk) });
    const wallet = walletFor(issuer);
    const [cred] = await (await wallet.receive(offer)).acceptPreAuthorized();
    const req = issuer.requests.find((r) => r.contentType !== 'token')!;
    expect(req.contentType).toBe('application/jwt');
    expect(req.body.credential_response_encryption).toMatchObject({ enc: 'A256GCM', jwk: { kty: 'EC', crv: 'P-256', alg: 'ECDH-ES' } });
    expect(cred!.report?.valid).toBe(true);
    expect(cred!.report?.trusted).toBe(true);
  });

  it('sends credential_accepted only once the credential is stored, credential_deleted when discarded', async () => {
    const issuer = mockIssuer({ credential: (jwk) => issueFor(jwk) });
    const wallet = walletFor(issuer);
    const issued = await (await wallet.receive(offer)).acceptPreAuthorized();
    expect(issuer.notifications).toEqual([]);
    expect(JSON.stringify(issued[0])).not.toMatch(/notify/);
    await wallet.store(issued);
    expect(issuer.notifications).toEqual(['credential_accepted']);
    await wallet.discard(await (await wallet.receive(offer)).acceptPreAuthorized());
    expect(issuer.notifications).toEqual(['credential_accepted', 'credential_deleted']);
  });

  it('refuses a credential that fails verification or whose x5c issuer is untrusted, and tells the issuer', async () => {
    const tampered = mockIssuer({ credential: (jwk) => issueFor(jwk).replace(/^([^.]+\.[^.]+\.)./, '$1A') });
    const err = await (await walletFor(tampered).receive(offer)).acceptPreAuthorized().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IssuanceError);
    expect((err as IssuanceError).code).toBe('invalid_credential');
    expect((err as IssuanceError).report?.valid).toBe(false);
    expect(tampered.notifications).toEqual(['credential_failure']);

    const untrusted = mockIssuer({ credential: (jwk) => issueFor(jwk, { signer: 'rogue-ds' }) });
    await expect((await walletFor(untrusted).receive(offer)).acceptPreAuthorized()).rejects.toThrow(/issuer certificate is not trusted/);
    const typ = mockIssuer({ credential: (jwk) => issueFor(jwk, { typ: 'vc+sd-jwt' }) });
    await expect((await walletFor(typ).receive(offer)).acceptPreAuthorized()).rejects.toThrow(/dc\+sd-jwt is required/);
  });

  it('uses an attestation proof when the issuer only accepts key attestations, and refuses non-ES256 jwt proofs', async () => {
    const issuer = mockIssuer({ proofTypes: { attestation: { proof_signing_alg_values_supported: ['ES256'] } }, credential: (jwk) => issueFor(jwk) });
    await (await walletFor(issuer, { attester: demoAttester() }).receive(offer)).acceptPreAuthorized();
    const req = issuer.requests.find((r) => r.contentType !== 'token')!;
    expect(decodeJws((req.body.proofs as { attestation: string[] }).attestation[0]!).header.typ).toBe('key-attestation+jwt');
    const rsaOnly = mockIssuer({ proofTypes: { jwt: { proof_signing_alg_values_supported: ['RS256'] } }, credential: (jwk) => issueFor(jwk) });
    await expect((await walletFor(rsaOnly).receive(offer)).acceptPreAuthorized()).rejects.toThrow(/signs with ES256/);
  });

  it('refuses compressed responses it did not ask for, falls back to attestation proofs, keeps credentials issued before a failure', async () => {
    const zipped = mockIssuer({ requestEnc: true, responseEnc: true, zip: true, credential: (jwk) => issueFor(jwk) });
    await expect((await walletFor(zipped).receive(offer)).acceptPreAuthorized()).rejects.toThrow(/compressed/);
    const mixed = mockIssuer({ proofTypes: { jwt: { proof_signing_alg_values_supported: ['RS256'] }, attestation: { proof_signing_alg_values_supported: ['ES256'] } },
      credential: (jwk) => issueFor(jwk) });
    await (await walletFor(mixed, { attester: demoAttester() }).receive(offer)).acceptPreAuthorized();
    expect(Object.keys(mixed.requests.find((r) => r.contentType !== 'token')!.body.proofs as object)).toEqual(['attestation']);
    const partial = mockIssuer({ credential: (jwk, id) => (id === 'pid2' ? issueFor(jwk, { signer: 'rogue-ds' }) : issueFor(jwk)) });
    const err = await (await walletFor(partial).receive(offerFor(['pid', 'pid2']))).acceptPreAuthorized().catch((e: unknown) => e) as IssuanceError;
    expect(err.code).toBe('invalid_credential');
    expect(err.issued.map((c) => c.configurationId)).toEqual(['pid']);
  });

  it('authenticates with the wallet attestation wherever the AS supports it, even when anonymous access is allowed', async () => {
    const issuer = mockIssuer({ tokenAuthMethods: ['attest_jwt_client_auth'], credential: (jwk) => issueFor(jwk) });
    await (await walletFor(issuer, { attester: demoAttester() }).receive(offer)).acceptPreAuthorized();
    expect(issuer.requests.find((r) => r.contentType === 'token')!.body).toMatchObject({ attested: true, client_id: 'https://wallet.vctrust.dev' });
    const anonymous = mockIssuer({ credential: (jwk) => issueFor(jwk) });
    await (await walletFor(anonymous, { attester: demoAttester() }).receive(offer)).acceptPreAuthorized();
    expect(anonymous.requests.find((r) => r.contentType === 'token')!.body.attested).toBe(false);
  });
});

describe('batch issuance (OID4VCI §8.2, HAIP §4)', () => {
  const keyOf = (c: { credential: unknown }) => (decodeJws(String(c.credential).split('~')[0]!).payload.cnf as { jwk: { x: string } }).jwk.x;

  it('asks for up to batch_size instances in one request, each bound to its own key, and pairs them with their keys', async () => {
    const issuer = mockIssuer({ batchSize: 3, credential: (jwk) => issueFor(jwk) });
    const [cred] = await (await walletFor(issuer, { batchSize: 5 }).receive(offer)).acceptPreAuthorized();
    const req = issuer.requests.filter((r) => r.contentType !== 'token');
    expect(req).toHaveLength(1);
    const proofs = (req[0]!.body.proofs as { jwt: string[] }).jwt;
    expect(proofs).toHaveLength(3);
    expect(new Set(proofs.map((p) => (decodeJws(p).header.jwk as { x: string }).x)).size).toBe(3);
    expect(cred!.instances).toHaveLength(2);
    for (const x of [cred!, ...cred!.instances!]) {
      expect(keyOf(x)).toBe(x.holderJwk.x);
      expect(x.report?.valid).toBe(true);
    }
    expect(new Set([cred!, ...cred!.instances!].map((x) => x.holderKeyId)).size).toBe(3);
  });

  it('requests one instance when the issuer has no batch support, whatever the wallet asks for', async () => {
    const issuer = mockIssuer({ credential: (jwk) => issueFor(jwk) });
    const [cred] = await (await walletFor(issuer, { batchSize: 3 }).receive(offer)).acceptPreAuthorized();
    expect((issuer.requests.find((r) => r.contentType !== 'token')!.body.proofs as { jwt: string[] }).jwt).toHaveLength(1);
    expect(cred!.instances).toBeUndefined();
  });

  it('attests every key of the batch in one key attestation (HAIP §4.5.1)', async () => {
    const jwtIssuer = mockIssuer({ batchSize: 3, credential: (jwk) => issueFor(jwk) });
    const [a] = await (await walletFor(jwtIssuer, { batchSize: 3, attester: demoAttester(), keyAttestation: 'always' }).receive(offer)).acceptPreAuthorized();
    const jwts = (jwtIssuer.requests.find((r) => r.contentType !== 'token')!.body.proofs as { jwt: string[] }).jwt;
    expect(jwts).toHaveLength(1);
    const attested = decodeJws(String(decodeJws(jwts[0]!).header.key_attestation)).payload.attested_keys as unknown[];
    expect(attested).toHaveLength(3);
    expect(a!.instances).toHaveLength(2);
    const attIssuer = mockIssuer({ batchSize: 3, proofTypes: { attestation: { proof_signing_alg_values_supported: ['ES256'] } }, credential: (jwk) => issueFor(jwk) });
    const [b] = await (await walletFor(attIssuer, { batchSize: 3, attester: demoAttester() }).receive(offer)).acceptPreAuthorized();
    expect((attIssuer.requests.find((r) => r.contentType !== 'token')!.body.proofs as { attestation: string[] }).attestation).toHaveLength(1);
    expect(b!.instances).toHaveLength(2);
  });

  it('refuses the whole batch when one instance fails, with one credential_failure', async () => {
    const issuer = mockIssuer({ batchSize: 3, credential: (jwk, _id, n) => (n === 1 ? issueFor(jwk, { signer: 'rogue-ds' }) : issueFor(jwk)) });
    const err = await (await walletFor(issuer, { batchSize: 3 }).receive(offer)).acceptPreAuthorized().catch((e: unknown) => e) as IssuanceError;
    expect(err.code).toBe('invalid_credential');
    expect(err.message).toMatch(/one of 3 batch instances/);
    expect(issuer.notifications).toEqual(['credential_failure']);
  });

  it('refuses an instance bound to a key the wallet did not send', async () => {
    const stranger = SoftwareKey.generate().publicJwk as unknown as Record<string, unknown>;
    const issuer = mockIssuer({ batchSize: 2, credential: (jwk, _id, n) => issueFor(n === 0 ? stranger : jwk) });
    await expect((await walletFor(issuer, { batchSize: 2 }).receive(offer)).acceptPreAuthorized()).rejects.toThrow(/not this wallet's key/);
  });

  it('presents a different instance to each verifier until the batch is used up', async () => {
    const issuer = mockIssuer({ batchSize: 2, credential: (jwk) => issueFor(jwk) });
    const wallet = walletFor(issuer, { batchSize: 2 });
    const [stored] = await wallet.store(await (await wallet.receive(offer)).acceptPreAuthorized());
    const rpHash = parseCertificate(pem('rp')).sha256;
    const presented: string[] = [];
    const verifierFetch = (async (url: string, init?: RequestInit) => {
      if (String(url) === 'https://verifier.example/post') {
        const vp = JSON.parse(new URLSearchParams(String(init?.body)).get('vp_token')!) as { pid: string[] };
        presented.push((decodeJws(vp.pid[0]!.split('~')[0]!).payload.cnf as { jwk: { x: string } }).jwk.x);
        return Response.json({});
      }
      return new Response(es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, { client_id: `x509_hash:${rpHash}`,
        response_type: 'vp_token', response_mode: 'direct_post', nonce: 'n', response_uri: 'https://verifier.example/post',
        dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] }, claims: [{ path: ['given_name'] }] }] } }, 'rp'));
    }) as typeof fetch;
    const trust = createTrustClient({ fetch: verifierFetch, fallback: { localAnchors: [{ domain: 'credential-issuer', certificate: pem('rp-ca') },
      { domain: 'verifier-access', certificate: pem('rp-ca') }] } });
    const presenter = new Wallet({ ...wallet.opts, trust, fetch: verifierFetch });
    const uri = `openid4vp://?client_id=${encodeURIComponent(`x509_hash:${rpHash}`)}&request_uri=${encodeURIComponent('https://verifier.example/req')}`;
    for (let i = 0; i < 3; i++) await (await presenter.startPresentation(uri)).respond();
    expect(presented[0]).not.toBe(presented[1]);
    expect(presented[2]).toBe(presented[0]);
    const after = (await wallet.list()).find((c) => c.id === stored!.id)!;
    expect([after.presentations, after.instances![0]!.presentations]).toEqual([2, 1]);
    expect(pickInstance(after)).toMatchObject({ index: 1, fresh: false, total: 2 });
  });
});

describe('deferred issuance (OID4VCI §9)', () => {
  it('keeps what it needs to ask again later, then completes, verifies and stores the credential under the same id', async () => {
    const issuer = mockIssuer({ deferred: 1, batchSize: 2, credential: (jwk) => issueFor(jwk) });
    const wallet = walletFor(issuer, { batchSize: 2 });
    (wallet.oid4vci.opts as { deferredWaitSeconds?: number }).deferredWaitSeconds = 0;
    const [pending] = await wallet.store(await (await wallet.receive(offer)).acceptPreAuthorized());
    expect(pending!.pending).toMatchObject({ transactionId: 't-1', accessToken: 'at', holderKeyIds: expect.any(Array) });
    expect(pending!.pending!.holderKeyIds).toHaveLength(2);
    expect(issuer.notifications).toEqual([]);
    const still = await wallet.retrieveDeferred(pending!.id);
    expect(still.pending).toBeDefined();
    const done = await wallet.retrieveDeferred(pending!.id);
    expect(done.id).toBe(pending!.id);
    expect(done.pending).toBeUndefined();
    expect(done.report?.trusted).toBe(true);
    expect(done.instances).toHaveLength(1);
    expect(issuer.notifications).toEqual(['credential_accepted']);
    expect(issuer.requests.filter((r) => r.contentType === 'deferred').map((r) => r.body.auth)).toEqual(['Bearer at', 'Bearer at']);
    const stored = await wallet.list();
    expect(stored).toHaveLength(1);
    expect(stored[0]!.pending).toBeUndefined();
  });
});

describe('credential store', () => {
  it('keeps one entry per credential and migrates the single-entry layout', async () => {
    const data = new Map<string, string>([['credentials', JSON.stringify([{ id: 'a', issuedAt: '2026-01-01' }, { id: 'b', issuedAt: '2026-02-01' }])]]);
    const kv = { get: async (k: string) => data.get(k) ?? null, set: async (k: string, v: string) => { data.set(k, v); }, remove: async (k: string) => { data.delete(k); } };
    const store = new KeyValueCredentialStore(kv);
    expect((await store.list()).map((c) => c.id)).toEqual(['b', 'a']);
    expect(JSON.parse(data.get('credentials')!)).toEqual(['a', 'b']);
    await store.save({ id: 'c', issuedAt: '2026-03-01' } as StoredCredential);
    await store.remove('a');
    expect((await store.list()).map((c) => c.id)).toEqual(['c', 'b']);
    expect([...data.keys()].sort()).toEqual(['credentials', 'credentials:b', 'credentials:c']);
    expect(await store.get('a')).toBeUndefined();
  });
});

// ---- presentation ----------------------------------------------------------------------------------------------

describe('minimal disclosure (OpenID4VP §6.4)', () => {
  const holder = SoftwareKey.generate();
  const cred = sdJwt(holder);
  const [jwt, ...rest] = cred.split('~');
  const decoded = rest.filter(Boolean).map(decodeDisclosure);
  const payload = decodeJws<Record<string, unknown>>(jwt!).payload;
  const names = (claims: DcqlClaim[]) => selectDisclosures(payload, decoded, claims).map((d) => d.name ?? `[${String(d.value)}]`);

  it('discloses exactly the requested paths, whole subtrees at the leaf, and nothing without claims', () => {
    expect(names([])).toEqual([]);
    expect(names([{ path: ['given_name'] }])).toEqual(['given_name']);
    expect(names([{ path: ['address'] }])).toEqual(['address', 'street']);
    expect(names([{ path: ['address', 'locality'] }])).toEqual(['address']);
    expect(names([{ path: ['nationalities', null] }])).toEqual(['[DE]', '[FR]']);
    expect(names([{ path: ['nationalities', 1] }])).toEqual(['[FR]']);
    expect(names([{ path: ['nationalities', null], values: ['FR'] }])).toEqual(['[FR]']);
    expect(names([{ path: ['not_there'] }])).toEqual([]);
    expect(names([{ path: ['toString'] }])).toEqual([]);
  });

  it('presents only the issuer JWT and KB-JWT when no claims are requested; no KB-JWT without cnf', async () => {
    const req = { clientId: 'x509_hash:abc', nonce: 'n', responseMode: 'direct_post', clientMetadata: {} } as never;
    const sc = { id: 'c', format: 'dc+sd-jwt', credential: cred } as StoredCredential;
    expect((await presentSdJwt(sc, [], req, holder)).split('~')).toHaveLength(2);
    const bearer = sdJwt();
    expect((await presentSdJwt({ ...sc, credential: bearer }, [{ path: ['given_name'] }], req, holder)).endsWith('~')).toBe(true);
  });

  it('skips credentials without holder binding unless the query allows it, and keeps claim sets per candidate', async () => {
    const mk = (id: string, c: string) => ({ id, format: 'dc+sd-jwt', credential: c, report: { credentialType: 'urn:eudi:pid:1' } } as unknown as StoredCredential);
    const q = (binding?: boolean) => ({ credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] },
      ...(binding === undefined ? {} : { require_cryptographic_holder_binding: binding }) }] });
    expect((await evaluateDcql(q(), [mk('b', sdJwt())])).satisfied).toBe(false);
    expect((await evaluateDcql(q(false), [mk('b', sdJwt())])).satisfied).toBe(true);
    const sets = { credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['urn:eudi:pid:1'] },
      claims: [{ id: 'a', path: ['nickname'] }, { id: 'b', path: ['given_name'] }], claim_sets: [['a'], ['b']] }] };
    const r = await evaluateDcql(sets, [mk('x', cred)]);
    expect(r.matches[0]!.claimsFor.x!.map((c) => c.id)).toEqual(['b']);
    const legacy = { ...mk('l', cred), format: 'vc+sd-jwt' } as StoredCredential;
    expect((await evaluateDcql({ credentials: [{ id: 'q', format: 'vc+sd-jwt', meta: { vct_values: ['urn:other'] } }] }, [legacy])).satisfied).toBe(false);
  });
});

describe('verifier trust and error responses (OpenID4VP §5.9.3, §8.2, §8.4)', () => {
  const rpHash = parseCertificate(pem('rp')).sha256;
  const cid = `x509_hash:${rpHash}`;
  const base = { client_id: cid, response_type: 'vp_token', response_mode: 'direct_post', nonce: 'n-1', state: 's-1', response_uri: 'https://verifier.example/post',
    dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] } };
  const posted: string[] = [];
  const serve = (claims: Record<string, unknown>) => (async (url: string, init?: RequestInit) => {
    if (String(url) === 'https://verifier.example/post') { posted.push(String(init?.body)); return new Response('{}'); }
    return new Response(es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [b64(pem('rp'))] }, claims, 'rp'));
  }) as typeof fetch;
  const uri = (clientId = cid) => `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent('https://verifier.example/req')}`;
  const trusted = createTrustClient({ fetch: (async () => { throw new TypeError('offline'); }) as typeof fetch, fallback: { localAnchors: [{ domain: 'verifier-access', certificate: pem('rp-ca') }] } });
  const untrusted = createTrustClient({ fetch: (async () => { throw new TypeError('offline'); }) as typeof fetch });

  it('refuses to present to an x509 verifier whose chain is not trusted', async () => {
    expect((await resolveAuthorizationRequest(uri(), trusted, serve(base))).verifier.refusal).toBeUndefined();
    const { verifier } = await resolveAuthorizationRequest(uri(), untrusted, serve(base));
    expect(verifier.refusal).toMatch(/does not chain to a trusted verifier CA/);
    expect(verifierRefusal('redirect_uri', verifier.trust)).toBeUndefined();
  });

  it('requires client_id with request_uri and rejects expired request objects', async () => {
    await expect(resolveAuthorizationRequest(`openid4vp://?request_uri=${encodeURIComponent('https://verifier.example/req')}`, trusted, serve(base))).rejects.toThrow(/client_id is required/);
    await expect(resolveAuthorizationRequest(uri(), trusted, serve({ ...base, exp: 1000 }))).rejects.toThrow(/expired/);
  });

  it('lets the user return invalid_request / invalid_transaction_data to an authenticated verifier', async () => {
    const e1 = await resolveAuthorizationRequest(uri(), trusted, serve({ ...base, redirect_uri: 'https://verifier.example/cb' })).catch((e: unknown) => e) as PresentationRequestError;
    expect(e1.reportTo).toEqual({ responseUri: 'https://verifier.example/post', state: 's-1' });
    expect(await reportPresentationError(e1, serve(base))).toBe(200);
    expect(posted.at(-1)).toMatch(/^error=invalid_request&error_description=.+&state=s-1$/);
    const e2 = await resolveAuthorizationRequest(uri(), trusted, serve({ ...base, transaction_data: ['x'] })).catch((e: unknown) => e) as PresentationRequestError;
    expect(e2.code).toBe('invalid_transaction_data');
    const forged = await resolveAuthorizationRequest(uri('x509_hash:AAAA'), trusted, serve({ ...base, client_id: 'x509_hash:AAAA' })).catch((e: unknown) => e) as PresentationRequestError;
    expect(forged.reportTo).toBeUndefined();
    const refused = await resolveAuthorizationRequest(uri(), untrusted, serve({ ...base, transaction_data: ['x'] })).catch((e: unknown) => e) as PresentationRequestError;
    expect(refused.code).toBe('invalid_transaction_data');
    expect(refused.reportTo).toBeUndefined();                       // never sent to a verifier the wallet does not trust
  });

  it('binds a decentralized_identifier client to its own DID, not to a DID that merely starts with it', async () => {
    const did = 'did:web:bank.example';
    const spoof = (async () => new Response(es256({ alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: `${did}.evil.example#k` },
      { ...base, client_id: `decentralized_identifier:${did}` }, 'rp'))) as typeof fetch;
    await expect(resolveAuthorizationRequest(uri(`decentralized_identifier:${did}`), trusted, spoof)).rejects.toThrow(/key of that DID/);
  });

  it('needs an ECDH-ES key with alg for direct_post.jwt', async () => {
    const jwks = (alg?: string) => ({ keys: [{ ...SoftwareKey.generate().publicJwk, kid: 'k', ...(alg ? { alg } : {}) }] });
    const jwtMode = (alg?: string) => serve({ ...base, response_mode: 'direct_post.jwt', client_metadata: { jwks: jwks(alg) } });
    await expect(resolveAuthorizationRequest(uri(), trusted, jwtMode())).rejects.toThrow(/alg ECDH-ES/);
    expect((await resolveAuthorizationRequest(uri(), trusted, jwtMode('ECDH-ES'))).request.responseMode).toBe('direct_post.jwt');
  });
});
