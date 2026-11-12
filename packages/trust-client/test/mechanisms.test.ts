/**
 * The operator's trust mechanisms on the device: read strictly from a format 5 snapshot (and from the app's own option),
 * refused in a format 4 one, and in force like the other rules: those of the snapshot a decision is made from, without a
 * usable one those of the last snapshot that verified, and the app's own only while no snapshot ever verified. How a
 * governed question is decided is held equal to the service by the second pair of evaluation vectors (vectors.test.ts).
 */
import { describe, expect, it } from 'vitest';
import { createTrustClient, MemoryCacheStore, TrustIntegrityError, type TrustClientConfig, type TrustMechanism, type TrustQuery } from '../src/index.js';
import { jwkThumbprint, MechanismError, parseMechanisms, selectMechanism } from '../src/primitives.js';
import { b64, down, es256Key, fakeFetch, json, pem, signJwt } from './helpers.js';

const BASE = 'https://trust.example';
const HOUR = 3600_000;
const GRACE = 24 * HOUR;
const serviceKey = es256Key();
const serviceJwk = { ...serviceKey.jwk, kty: 'EC', kid: 'svc-1', alg: 'ES256' };
const LENIENT = { frameworks: ['utopia'], strictAuthorization: false, requireRevocationStatus: false, requireSignedIssuerMetadata: false };
const IACA_ANCHOR = { id: 'a1', domain: 'mdoc-iaca', frameworkId: 'utopia', status: 'ACTIVE', constraints: {}, certificate: b64(pem('iaca')) };

/** The example of the configuration guide, in the form of the claim. */
const NATIONAL_ID = {
  id: 'national-id',
  for: { role: 'issuer', formats: ['mso_mdoc'], types: ['org.example.id.*'] },
  keys: ['x5c'],
  x509: {
    domain: 'national-id',
    profile: {
      leaf: { ca: false, keyUsage: ['digitalSignature'], extendedKeyUsage: ['1.3.6.1.4.1.99999.1.1'], sameCountryAsAnchor: true, maxValidityDays: 1100,
        crlDistributionPoint: true },
      maxIntermediates: 0,
    },
    revocation: 'required',
  },
} as const;

/** Governs every mDL question: its revocation status must be known. */
const MDL_REVOCATION = { id: 'mdl-revocation', for: { role: 'issuer', formats: ['mso_mdoc'], types: ['org.iso.18013.5.1.mDL'] },
  x509: { revocation: 'required' } } as const;
/** The app's own: every mdoc signer must be listed under a domain of the app's naming. */
const APP_MDOC = { id: 'app-mdoc', for: { role: 'issuer', formats: ['mso_mdoc'] }, x509: { domain: 'app-iaca' } } as const;

/** A Document Signer with no distribution point: no revocation status can be had for it. */
const ds: TrustQuery = { role: 'issuer', subject: { x5c: [b64(pem('ds'))] }, context: { credentialFormat: 'mso_mdoc', credentialType: 'org.iso.18013.5.1.mDL' } };

type Tree = Record<string, unknown>;
function set(tree: Tree, path: string, value: unknown): Tree {
  const copy = structuredClone(tree);
  const parts = path.split('.');
  let at = copy;
  for (const p of parts.slice(0, -1)) at = at[p] as Tree;
  if (value === undefined) delete at[parts[parts.length - 1]!];
  else at[parts[parts.length - 1]!] = value;
  return copy;
}

describe('the mechanisms claim is read strictly', () => {
  it('reads the example of the guide as it is', () => {
    expect(parseMechanisms([NATIONAL_ID])).toEqual([NATIONAL_ID]);
    // What is read is frozen: no one changes the rules in force by changing an object.
    expect(Object.isFrozen(parseMechanisms([NATIONAL_ID])[0]!.x509!.profile!.leaf)).toBe(true);
  });

  it('refuses a member or a value it does not know, and names the mechanism', () => {
    const n = NATIONAL_ID as unknown as Tree;
    const broken: Array<[string, unknown]> = [
      ['unknown member at the top', set(n, 'x5c', ['x'])],
      ['unknown member of for', set(n, 'for.issuer', 'https://x.example')],
      ['unknown member of x509', set(n, 'x509.anchors', ['a'])],
      ['unknown member of the profile', set(n, 'x509.profile.root', { ca: true })],
      ['unknown member of the leaf', set(n, 'x509.profile.leaf.policy', '1.2.3')],
      ['kebab-case member', set(set(n, 'x509.profile.leaf.keyUsage', undefined), 'x509.profile.leaf.key-usage', ['digitalSignature'])],
      ['unknown role', set(n, 'for.role', 'holder')],
      ['role as the API also spells it', set(n, 'for.role', 'credential_issuer')],
      // A credential's format and types belong to questions about its issuer, and a question about anyone else names neither.
      ['formats and types for a verifier', set(n, 'for.role', 'verifier')],
      ['types for a wallet provider', { id: 'national-id', for: { role: 'wallet_provider', types: ['org.example.id.*'] } }],
      ['types for a status list provider', { id: 'national-id', for: { role: 'status_list_provider', types: ['x'] } }],
      ['formats for an authorization server', { id: 'national-id', for: { role: 'authorization_server', formats: ['ldp_vc'] } }],
      ['no role', set(n, 'for.role', undefined)],
      ['no for', set(n, 'for', undefined)],
      ['unknown format', set(n, 'for.formats', ['mdoc'])],
      ['a format not in its canonical spelling', set(n, 'for.formats', ['vc+sd-jwt'])],
      ['empty formats', set(n, 'for.formats', [])],
      ['formats not a list', set(n, 'for.formats', 'mso_mdoc')],
      ['type with * inside', set(n, 'for.types', ['org.*.id'])],
      ['type that is only *', set(n, 'for.types', ['*'])],
      ['type with a space', set(n, 'for.types', ['org example'])],
      ['type twice', set(n, 'for.types', ['a', 'a'])],
      ['unknown key kind', set(n, 'keys', ['x5c', 'cose'])],
      ['empty keys', set(n, 'keys', [])],
      ['x509 when keys does not accept x5c', set(n, 'keys', ['did'])],
      ['did when keys does not accept did', { id: 'national-id', for: { role: 'issuer' }, keys: ['x5c'], did: { methods: ['web'] } }],
      ['did without methods', { id: 'national-id', for: { role: 'issuer' }, did: {} }],
      ['did method in upper case', { id: 'national-id', for: { role: 'issuer' }, did: { methods: ['Web'] } }],
      ['empty x509', set(n, 'x509', {})],
      ['empty profile', set(n, 'x509.profile', {})],
      ['empty leaf', set(n, 'x509.profile.leaf', {})],
      ['domain in upper case', set(n, 'x509.domain', 'National-ID')],
      ['revocation other than required', set(n, 'x509.revocation', 'optional')],
      ['leaf.ca true', set(n, 'x509.profile.leaf.ca', true)],
      ['leaf.ca as text', set(n, 'x509.profile.leaf.ca', 'false')],
      ['unknown key usage', set(n, 'x509.profile.leaf.keyUsage', ['signing'])],
      ['key usage this parser does not read', set(n, 'x509.profile.leaf.keyUsage', ['encipherOnly'])],
      ['extended key usage that is not an OID', set(n, 'x509.profile.leaf.extendedKeyUsage', ['serverAuth'])],
      ['sameCountryAsAnchor false', set(n, 'x509.profile.leaf.sameCountryAsAnchor', false)],
      ['crlDistributionPoint false', set(n, 'x509.profile.leaf.crlDistributionPoint', false)],
      ['maxValidityDays 0', set(n, 'x509.profile.leaf.maxValidityDays', 0)],
      ['maxValidityDays as text', set(n, 'x509.profile.leaf.maxValidityDays', '1100')],
      ['maxValidityDays a fraction', set(n, 'x509.profile.leaf.maxValidityDays', 1.5)],
      ['maxIntermediates beyond a chain', set(n, 'x509.profile.maxIntermediates', 10)],
      ['a null member', set(n, 'keys', null)],
    ];
    for (const [name, m] of broken) {
      expect(() => parseMechanisms([m]), name).toThrow(MechanismError);
      expect(() => parseMechanisms([m]), name).toThrow(/^Trust mechanism mechanisms\[0\] \('national-id'\): /);
    }
    expect(() => parseMechanisms([NATIONAL_ID, NATIONAL_ID])).toThrow("Trust mechanism mechanisms[1] ('national-id'): the id is already used by mechanisms[0]");
    expect(() => parseMechanisms({ 0: NATIONAL_ID })).toThrow('mechanisms must be a list');
    expect(() => parseMechanisms([{ ...NATIONAL_ID, id: 'national id' }])).toThrow(/mechanisms\[0\]: id must be/);
  });

  it('selects the first mechanism that governs a question', () => {
    const list = parseMechanisms([
      { id: 'exact', for: { role: 'issuer', formats: ['ldp_vc'], types: ['UniversityDegreeCredential'] } },
      { id: 'prefix', for: { role: 'issuer', types: ['org.example.id.*'] } },
      { id: 'any-ldp', for: { role: 'issuer', formats: ['ldp_vc'] } },
      { id: 'verifiers', for: { role: 'verifier' } },
    ]);
    const pick = (role: string | undefined, format: string | undefined, ...types: string[]) => selectMechanism(list, role, format, types)?.id;
    expect(pick('issuer', 'ldp_vc', 'UniversityDegreeCredential')).toBe('exact');
    expect(pick('issuer', 'ldp_vc', 'UniversityDegreeCredential2')).toBe('any-ldp');
    expect(pick('issuer', 'mso_mdoc', 'org.example.id.card')).toBe('prefix');
    expect(pick('issuer', 'mso_mdoc', 'org.example.idcard')).toBeUndefined();
    expect(pick('issuer', 'ldp_vc')).toBe('any-ldp');
    expect(pick('issuer', undefined)).toBeUndefined();
    expect(pick('verifier', undefined)).toBe('verifiers');
    expect(pick('wallet_provider', undefined)).toBeUndefined();
    expect(pick(undefined, 'ldp_vc', 'UniversityDegreeCredential')).toBeUndefined();
    expect(pick('issuer', 'ldp_vc', 'OtherCredential', 'UniversityDegreeCredential')).toBe('exact');
    expect(pick('issuer', 'jwt_vc_json', 'OtherCredential', 'org.example.id.x')).toBe('prefix');
  });

  it('governs an authorization server too', () => {
    const list = parseMechanisms([{ id: 'as', for: { role: 'authorization_server' }, keys: ['x5c'] }, { id: 'issuers', for: { role: 'issuer' } }]);
    expect(list[0]).toEqual({ id: 'as', for: { role: 'authorization_server' }, keys: ['x5c'] });
    expect(selectMechanism(list, 'authorization_server', undefined, [])?.id).toBe('as');
    expect(selectMechanism(list, 'issuer', 'ldp_vc', [])?.id).toBe('issuers');
    expect(selectMechanism(list, 'verifier', undefined, [])).toBeUndefined();
  });
});

/**
 * A service that signs snapshots of a given format, with or without mechanisms, and that can go away; a clock the test
 * moves; one storage that every client of the world shares, as an app does across restarts.
 */
function world(claims: Tree) {
  const w = { online: true, now: Date.now(), claims, storage: new MemoryCacheStore() };
  const snapshot = () => {
    const iat = Math.floor(w.now / 1000);
    return signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: 'svc-1' }, { iss: BASE, aud: 'wallet-1', iat, exp: iat + 3600, policy: LENIENT,
      frameworks: [{ id: 'utopia', name: 'Utopia' }], entities: [], anchors: [IACA_ANCHOR], ...w.claims }, serviceKey.privateKey);
  };
  const { fetch } = fakeFetch({
    [`${BASE}/api/v1/snapshot`]: () => (w.online ? new Response(snapshot(), { headers: { 'Content-Type': 'application/jwt' } }) : down()),
    [`${BASE}/.well-known/jwks.json`]: () => (w.online ? json({ keys: [serviceJwk] }) : down()),
  }, down);
  const client = (extra: Partial<TrustClientConfig> = {}) => createTrustClient({
    service: { url: BASE, clientId: 'wallet-1', keys: { thumbprints: [jwkThumbprint(serviceJwk)] } },
    pinned: { anchors: [{ domain: 'mdoc-iaca', certificate: pem('iaca') }] },
    storage: w.storage, clock: () => new Date(w.now), snapshot: { graceMs: GRACE, retryMs: 0 },
    ...extra, http: { fetch, retries: 0, timeoutMs: 500 } });
  /** The service goes away, and the snapshot held runs past its expiry and its grace period. */
  const lapse = () => { w.online = false; w.now += HOUR + GRACE + 60_000; };
  return { w, client, lapse };
}

describe('snapshot formats', () => {
  it('reads format 4 as before: no mechanisms', async () => {
    const c = world({ format: 4 }).client();
    expect((await c.sync()).mechanisms).toBe(0);
    expect((await c.status()).mechanisms).toEqual([]);
    const d = await c.evaluate(ds);
    expect([d.decision, d.evidence?.mechanism]).toEqual(['TRUSTED', undefined]);
    expect(d.evidence && 'mechanism' in d.evidence).toBe(false);
  });

  it('reads the mechanisms of format 5 and decides under them', async () => {
    const c = world({ format: 5, mechanisms: [NATIONAL_ID, MDL_REVOCATION] }).client();
    expect((await c.sync()).mechanisms).toBe(2);
    expect((await c.status()).mechanisms?.map((m) => m.id)).toEqual(['national-id', 'mdl-revocation']);
    const d = await c.evaluate(ds);
    expect([d.decision, d.source, d.evidence?.mechanism]).toEqual(['NOT_TRUSTED', 'snapshot', 'mdl-revocation']);
    expect(d.reasons.find((r) => r.severity === 'ERROR')?.code).toBe('x509.revocation_unknown');
  });

  const refused: Array<[string, Tree, RegExp]> = [
    ['a format 4 snapshot that carries mechanisms', { format: 4, mechanisms: [MDL_REVOCATION] }, /format 4 snapshot carries no trust mechanisms/],
    ['a format 4 snapshot that carries an empty list', { format: 4, mechanisms: [] }, /format 4 snapshot carries no trust mechanisms/],
    ['a format 5 snapshot without the claim', { format: 5 }, /mechanisms must be a list.*update the client/],
    ['a member this client does not know', { format: 5, mechanisms: [set(NATIONAL_ID as unknown as Tree, 'x509.profile.leaf.policies', ['1.2.3'])] },
      /x509\.profile\.leaf\.policies is not a member this client knows.*update the client/],
    ['a value this client does not know', { format: 5, mechanisms: [{ ...MDL_REVOCATION, keys: ['cose'] }] }, /'cose' is not one of.*update the client/],
    ['a format this client does not read', { format: 6, mechanisms: [] }, /Snapshot format 6 is not a format this client reads \(4, 5\): update the client/],
  ];
  for (const [name, claims, message] of refused) {
    it(`refuses ${name}`, async () => {
      const { client } = world(claims);
      const c = client();
      await expect(c.sync()).rejects.toThrow(TrustIntegrityError);
      await expect(c.sync()).rejects.toThrow(message);
      // Nothing of it is used: the client decides from what is pinned, under no mechanism.
      const d = await c.evaluate(ds);
      expect([d.source, d.evidence?.mechanism]).toEqual(['pinned', undefined]);
    });
  }
});

describe('the mechanisms in force', () => {
  it("a snapshot's mechanisms stay in force for pinned trust once it is past its grace, also after a restart", async () => {
    const { client, lapse } = world({ format: 5, mechanisms: [MDL_REVOCATION] });
    await client().sync();
    lapse();
    for (const c of [client(), client()]) {
      const d = await c.evaluate(ds);
      expect([d.decision, d.source, d.evidence?.mechanism]).toEqual(['NOT_TRUSTED', 'pinned', 'mdl-revocation']);
      expect((await c.status()).mechanisms?.map((m) => m.id)).toEqual(['mdl-revocation']);
    }
  });

  it("the app's own are in force only while no snapshot has verified", async () => {
    const { w, client, lapse } = world({ format: 4 });
    w.online = false;
    const own = { mechanisms: [APP_MDOC as unknown as TrustMechanism] };
    // No snapshot ever: the app's mechanism routes the mdoc signer to a domain nothing is pinned in.
    const before = await client(own).evaluate(ds);
    expect([before.decision, before.source, before.evidence?.mechanism]).toEqual(['UNKNOWN', 'pinned', 'app-mdoc']);
    expect((await client(own).status()).mechanisms?.map((m) => m.id)).toEqual(['app-mdoc']);

    // The service speaks once, with no mechanisms: its list is the list, also after the snapshot has lapsed.
    w.online = true;
    await client(own).sync();
    expect((await client(own).evaluate(ds)).evidence?.mechanism).toBeUndefined();
    lapse();
    const after = await client(own).evaluate(ds);
    expect([after.decision, after.source, after.evidence?.mechanism]).toEqual(['TRUSTED', 'pinned', undefined]);
    expect((await client(own).status()).mechanisms).toEqual([]);
  });

  it("a stored snapshot that no longer verifies states none, and the app's own are in force again", async () => {
    const { w, client, lapse } = world({ format: 5, mechanisms: [MDL_REVOCATION] });
    await client().sync();
    const stored = JSON.parse((await w.storage.get('snapshot'))!) as { jwt: string };
    const [h, p, s] = stored.jwt.split('.');
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString()) as Tree;
    await w.storage.set('snapshot', JSON.stringify({ ...stored, jwt: [h, Buffer.from(JSON.stringify({ ...claims, mechanisms: [] })).toString('base64url'), s].join('.') }));
    lapse();
    const d = await client({ mechanisms: [APP_MDOC as unknown as TrustMechanism] }).evaluate(ds);
    expect([d.source, d.evidence?.mechanism]).toEqual(['pinned', 'app-mdoc']);
  });

  it('reports the rule flags in status().rules and the mechanisms next to them, not among them', async () => {
    const c = world({ format: 5, mechanisms: [NATIONAL_ID, MDL_REVOCATION] }).client({ policy: { strictAuthorization: true } });
    await c.sync();
    const s = await c.status();
    // Code that lists the flags in force (each key that is true, or truthy) lists flags and nothing else.
    expect(s.rules).toEqual({ requireRevocationStatus: false, strictAuthorization: true, requireSignedIssuerMetadata: false });
    expect(Object.keys(s.rules ?? {}).filter((k) => (s.rules as unknown as Record<string, unknown>)[k])).toEqual(['strictAuthorization']);
    expect(s.mechanisms?.map((m) => m.id)).toEqual(['national-id', 'mdl-revocation']);
  });

  const handedOut: Array<[string, Tree, Partial<TrustClientConfig>, boolean]> = [
    ['a format 4 snapshot', { format: 4 }, {}, true],
    ['a format 5 snapshot', { format: 5, mechanisms: [NATIONAL_ID] }, {}, true],
    ["the app's own, no snapshot ever", { format: 4 }, { mechanisms: [APP_MDOC as unknown as TrustMechanism] }, false],
    ['none at all, no snapshot ever', { format: 4 }, {}, false],
  ];
  for (const [name, claims, extra, online] of handedOut) {
    it(`hands out the mechanisms in force frozen (${name}): changing them puts nothing in force`, async () => {
      const { w, client } = world(claims);
      w.online = online;
      const c = client(extra);
      if (online) await c.sync();
      const before = (await c.evaluate(ds)).evidence?.mechanism;
      const list = (await c.status()).mechanisms as TrustMechanism[];
      expect(Object.isFrozen(list)).toBe(true);
      for (const m of list) expect(Object.isFrozen(m.for)).toBe(true);
      expect(() => list.push(MDL_REVOCATION as unknown as TrustMechanism)).toThrow(TypeError);
      expect((await c.evaluate(ds)).evidence?.mechanism).toBe(before);
    });
  }

  it("refuses an app's mechanism it does not understand, at construction", () => {
    const f = fakeFetch({}).fetch;
    expect(() => createTrustClient({ http: { fetch: f }, mechanisms: [{ ...APP_MDOC, x509: { domain: 'app-iaca', revocation: 'yes' } }] as never }))
      .toThrow("Trust mechanism mechanisms[0] ('app-mdoc'): x509.revocation must be 'required', or absent to let the client profile decide");
    expect(() => createTrustClient({ http: { fetch: f }, mechanisms: APP_MDOC as never })).toThrow('mechanisms must be a list');
    expect(() => createTrustClient({ http: { fetch: f }, mechanisms: [APP_MDOC as unknown as TrustMechanism] })).not.toThrow();
  });
});
