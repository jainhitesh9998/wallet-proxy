/**
 * The wallet against the reference issuer and verifier: OpenID4VCI 1.0 issuance of every format, verification of what
 * was issued, and OpenID4VP 1.0 presentation, which the reference verifier checks with its own (third-party)
 * implementations. The ecosystem runs as a process of its own. Trust is pinned in the client: no trust service runs
 * here (proxy.live.test.ts covers that).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TrustClient } from '@vctrust/trust-client';
import { IssuanceError, verifyLdpVc, type IssuedCredential, type Wallet } from '../src/index.js';
import { CONFIGURATIONS, entities, pinnedTrust, start, walletWith, type Ecosystem } from './ecosystem.js';

let eco: Ecosystem;
let trust: TrustClient;
let wallet: Wallet;

beforeAll(async () => {
  eco = await start();
  trust = await pinnedTrust(eco);
  wallet = walletWith(trust);
});
afterAll(() => eco?.stop());


const failed = (c: IssuedCredential) => c.report?.checks.filter((x) => x.status === 'fail').map((x) => `${x.id}: ${x.detail}`);

async function issue(configurationId: string, w = wallet, options: Record<string, unknown> = {}): Promise<IssuedCredential> {
  const offer = await eco.issuer.createOffer({ configurationIds: [configurationId], ...options });
  const session = await w.receive(offer.credentialOfferUri);
  const issued = await session.acceptPreAuthorized(offer.txCode);
  await w.store(issued);
  return issued[0]!;
}

describe('issuance from the reference issuer', () => {
  it('knows the issuer through the trust client before asking it for anything', async () => {
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.mdl] });
    const session = await wallet.receive(offer.credentialOfferUri);
    expect(session.issuerTrust).toMatchObject({ decision: 'TRUSTED', source: 'pinned', entity: { id: 'reference-issuer' } });
    expect(session.needsConfirmation).toBe(false);
    expect(session.metadata.source).toBe('direct');
  });

  for (const [name, id] of Object.entries(CONFIGURATIONS)) {
    it(`issues, verifies and trusts ${id}`, async () => {
      const c = await issue(id);
      expect(failed(c)).toEqual([]);
      expect(c.report).toMatchObject({ valid: true, trusted: true });
      expect(c.report!.checks.filter((x) => x.status === 'warn').map((x) => `${x.id}: ${x.detail}`)).toEqual(name === 'ecdsa' || name === 'eddsa'
        ? [expect.stringMatching(/^ldp\.contexts: Not vouched for by the trust service: http:\/\/localhost:\d+\/contexts\/reference\/v1$/)] : []);
      expect(c.report!.checks.map((x) => x.id)).toEqual(expect.arrayContaining(['issuer.trust', {
        ecdsa: 'ldp.status', eddsa: 'ldp.status', mdl: 'mdoc.digests', identity: 'sdjwt.status' }[name]]));
    });
  }

  it('checks a W3C credential against the configuration that was asked for', async () => {
    const c = await issue(CONFIGURATIONS.ecdsa);
    const vc = c.credential as Record<string, unknown>;
    expect(vc['@context']).toEqual(['https://www.w3.org/ns/credentials/v2', `${eco.issuerUrl}/contexts/reference/v1`]);
    expect(c.report!.checks.find((x) => x.id === 'ldp.requested')).toMatchObject({ status: 'pass' });
    expect(c.report!.checks.find((x) => x.id === 'ldp.signature')?.detail).toMatch(/ecdsa-rdfc-2019 by did:web:localhost/);
    expect(c.holderDid).toMatch(/^did:jwk:/);
    expect((vc.credentialSubject as { id: string }).id).toBe(c.holderDid);
  });

  it('issues with a transaction code, and a batch with one key per instance', async () => {
    const withCode = await issue(CONFIGURATIONS.identity, wallet, { txCode: true });
    expect(withCode.report?.trusted).toBe(true);
    const batchWallet = walletWith(trust, { batchSize: 3 });
    const batch = await issue(CONFIGURATIONS.identity, batchWallet);
    expect(batch.instances).toHaveLength(2);
    expect(new Set([batch.holderKeyId, ...batch.instances!.map((x) => x.holderKeyId)]).size).toBe(3);
    expect(batch.instances!.every((x) => x.report?.valid)).toBe(true);
  });

  it('pairs each W3C credential of a batch with the DID it is bound to', async () => {
    const batch = await issue(CONFIGURATIONS.eddsa, walletWith(trust, { batchSize: 2 }));
    expect(batch.instances).toHaveLength(1);
    for (const x of [batch, ...batch.instances!]) {
      expect(((x.credential as Record<string, unknown>).credentialSubject as { id: string }).id).toBe(x.holderDid);
      expect(x.report?.valid).toBe(true);
    }
    expect(batch.holderDid).not.toBe(batch.instances![0]!.holderDid);
  });

  it('runs the authorization code flow with PAR and PKCE', async () => {
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.mdl], grant: 'authorization_code' });
    const session = await wallet.receive(offer.credentialOfferUri);
    const { authorizationUrl } = await session.beginAuthorization();
    // The reference authorization server asks nobody: it redirects straight back with the code.
    const redirect = await fetch(authorizationUrl, { redirect: 'manual' });
    expect(redirect.status).toBe(302);
    const [credential] = await session.completeAuthorization(redirect.headers.get('Location')!);
    expect(credential!.report).toMatchObject({ valid: true, trusted: true });
  });

  it('picks up a deferred credential', async () => {
    const w = walletWith(trust, { deferredWaitSeconds: 0 });
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.identity], deferSeconds: 1 });
    const [pending] = await (await w.receive(offer.credentialOfferUri)).acceptPreAuthorized();
    expect(pending!.pending?.transactionId).toBeTruthy();
    await w.store([pending!]);
    await new Promise((r) => setTimeout(r, 1200));
    const done = await w.retrieveDeferred(pending!.id);
    expect(done.pending).toBeUndefined();
    expect(done.report).toMatchObject({ valid: true, trusted: true });
  });
});

describe('a signed W3C credential, altered', () => {
  let vc: Record<string, unknown>;
  let holderDid: string;
  beforeAll(async () => {
    const c = await issue(CONFIGURATIONS.ecdsa);
    [vc, holderDid] = [c.credential as Record<string, unknown>, c.holderDid!];
  });
  const check = async (altered: Record<string, unknown>, options: Record<string, unknown> = {}) => {
    const r = await verifyLdpVc(altered, { trust, holderDid, ...options });
    return { valid: r.valid, failed: r.checks.filter((x) => x.status === 'fail').map((x) => `${x.id}: ${x.detail}`).join('\n') };
  };
  const subject = () => vc.credentialSubject as Record<string, unknown>;
  const proof = () => vc.proof as Record<string, unknown>;

  it('verifies as issued', async () => {
    expect(await check(vc)).toEqual({ valid: true, failed: '' });
    // Also by a device whose clock is a little behind the issuer's; not by one for which the credential lies ahead.
    const from = Date.parse(String(vc.validFrom));
    expect(await check(vc, { now: new Date(from - 30_000) })).toEqual({ valid: true, failed: '' });
    expect((await check(vc, { now: new Date(from - 3_600_000) })).failed).toMatch(/ldp\.validity: Not valid before/);
  });

  it('is refused with a claim that no context defines: such a claim would not be covered by the signature', async () => {
    const { valid, failed } = await check({ ...vc, credentialSubject: { ...subject(), clearance: 'top secret' } });
    expect(valid).toBe(false);
    // Refused by the JSON-LD processor's safe mode, before any signature is checked: dropped silently, the claim would
    // leave the signature valid and the wallet showing a claim the issuer never made.
    expect(failed).toMatch(/^ldp\.signature: Safe mode validation error/);
    // The same holds at the top level.
    expect((await check({ ...vc, approvedBy: 'nobody' })).valid).toBe(false);
  });

  it('is refused when a signed statement is respelled so that a reader of the JSON would not see it', async () => {
    // The same RDF, so the signature still verifies; but the wallet reads validUntil and credentialStatus by name.
    const { validUntil, credentialStatus, ...rest } = vc;
    const respelled = { ...rest, 'https://www.w3.org/2018/credentials#validUntil': { '@value': validUntil, '@type': 'http://www.w3.org/2001/XMLSchema#dateTime' },
      'https://www.w3.org/2018/credentials#credentialStatus': credentialStatus };
    const r = await check(respelled);
    expect(r.valid).toBe(false);
    expect(r.failed).toMatch(/ldp\.signature: The member .* is not written in the terms of the document's contexts/);
    // A context of its own on a member below the top could rename the claims beneath it.
    const nested = { ...vc, credentialSubject: { ...subject(), '@context': { name: 'https://schema.org/alternateName' } } };
    expect((await check(nested)).failed).toMatch(/ldp\.model: .*carries its own @context/);
    // A member with no value says nothing in RDF: it is not signed, so it is not accepted.
    expect((await check({ ...vc, credentialSubject: { ...subject(), nickname: null } })).valid).toBe(false);
  });

  it('must be bound to the key the wallet proved when it proved a key rather than a DID', async () => {
    const key = (await import('../src/index.js')).SoftwareKey.generate().publicJwk;
    const other = await verifyLdpVc(vc, { trust, holderJwk: key });
    expect(other.checks.find((x) => x.id === 'ldp.holder')).toMatchObject({ status: 'fail', detail: expect.stringMatching(/is not this wallet's key/) });
    const { didPublicKey } = await import('../src/crypto/did-key.js');
    const own = await verifyLdpVc(vc, { trust, holderJwk: didPublicKey(holderDid)! });
    expect(own.checks.find((x) => x.id === 'ldp.holder')).toMatchObject({ status: 'pass' });
  });

  it('is refused when a signed claim changes', async () => {
    const name = Object.keys(subject()).find((k) => k !== 'id' && typeof subject()[k] === 'string')!;
    expect(await check({ ...vc, credentialSubject: { ...subject(), [name]: 'Someone Else' } })).toMatchObject({ valid: false, failed: expect.stringMatching(/signature does not verify/) });
  });

  it('is refused with a context given inline, or a context list that does not start with the VCDM context', async () => {
    const contexts = vc['@context'] as string[];
    expect((await check({ ...vc, '@context': [...contexts, { clearance: 'https://example.org/clearance' }] })).failed).toMatch(/ldp\.model: .*inline context/);
    expect((await check({ ...vc, '@context': [...contexts].reverse() })).failed).toMatch(/ldp\.model: @context must be an array starting with/);
  });

  it('is refused when the proof is not the issuer\'s own assertion', async () => {
    const other = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect((await check({ ...vc, proof: { ...proof(), verificationMethod: `${other}#${other.slice(8)}` } })).failed).toMatch(/belongs to did:key:.*, not to the issuer did:web/);
    expect((await check({ ...vc, proof: { ...proof(), proofPurpose: 'authentication' } })).failed).toMatch(/proofPurpose must be assertionMethod/);
    expect((await check({ ...vc, proof: { ...proof(), cryptosuite: 'made-up-2026' } })).failed).toMatch(/Unsupported proof/);
    expect((await check({ ...vc, proof: [proof(), { ...proof(), proofValue: 'z3hQ' }] })).failed).toMatch(/ldp\.signature/);
    const { proof: _none, ...unsigned } = vc;
    expect((await check(unsigned)).failed).toMatch(/ldp\.signature: The credential has no proof/);
  });

  it('is refused outside its validity period, for another holder, or as another credential than asked for', async () => {
    expect((await check({ ...vc, validUntil: '2020-01-01T00:00:00Z' })).failed).toMatch(/ldp\.validity: Expired 2020/);
    expect((await check(vc, { holderDid: 'did:jwk:someone-else' })).failed).toMatch(/ldp\.holder: credentialSubject\.id .* is not this wallet's DID/);
    expect((await check(vc, { expected: { type: ['VerifiableCredential', 'DriverLicenseCredential'] } })).failed).toMatch(/ldp\.requested: The credential lacks the requested type DriverLicenseCredential/);
    expect((await check(vc, { expected: { context: ['https://www.w3.org/ns/credentials/v2'] } })).failed).toMatch(/ldp\.requested: The credential's @context is not the one/);
    expect((await check({ ...vc, issuanceDate: '2026-01-01T00:00:00Z' })).failed).toMatch(/ldp\.model: issuanceDate/);
  });
});

describe('what the trust layer says decides what the wallet does', () => {
  it('asks the user before dealing with an issuer the trust layer does not know, and still refuses credentials it cannot attribute', async () => {
    const stranger = walletWith(await pinnedTrust(eco, {}, false));
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.mdl] });
    const session = await stranger.receive(offer.credentialOfferUri);
    expect(session.issuerTrust.decision).toBe('UNKNOWN');
    expect(session.needsConfirmation).toBe(true);
    await expect(session.acceptPreAuthorized()).rejects.toMatchObject({ code: 'issuer_unknown' });
    session.confirmUnknownIssuer();
    // An mdoc signed under an IACA nobody vouches for proves nothing: refused even after the user's confirmation.
    await expect(session.acceptPreAuthorized()).rejects.toThrow(/does not chain to a trusted anchor/);
    expect(await stranger.list()).toEqual([]);
    expect((await eco.issuer.notifications()).at(-1)).toMatchObject({ event: 'credential_failure' });
  });

  it('keeps a W3C credential of an unknown issuer only after the user confirmed, marked as not trusted', async () => {
    const stranger = walletWith(await pinnedTrust(eco, {}, false));
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.eddsa] });
    const session = await stranger.receive(offer.credentialOfferUri);
    session.confirmUnknownIssuer();
    const [c] = await session.acceptPreAuthorized();
    expect(c!.report).toMatchObject({ valid: true, trusted: false, trust: { decision: 'UNKNOWN' } });
  });

  it('holds a signer the registry does not know to the same rule whether the credential comes at once or later', async () => {
    // The issuer's URL is listed; the DID its W3C credentials are signed with is not.
    const [issuer] = entities(eco);
    const urlOnly = { ...issuer!, identifiers: issuer!.identifiers.filter((i) => i.type === 'URL') };
    const w = walletWith(await pinnedTrust(eco, { pinned: { anchors: [], entities: [urlOnly] } }), { deferredWaitSeconds: 0 });
    const now = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.eddsa] });
    const session = await w.receive(now.credentialOfferUri);
    expect(session.needsConfirmation).toBe(false);
    await expect(session.acceptPreAuthorized()).rejects.toThrow(/unknown to the trust service/);
    const later = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.eddsa], deferSeconds: 1 });
    const [pending] = await w.store(await (await w.receive(later.credentialOfferUri)).acceptPreAuthorized());
    expect(pending!.pending).toBeDefined();
    await new Promise((r) => setTimeout(r, 1200));
    await expect(w.retrieveDeferred(pending!.id)).rejects.toThrow(/unknown to the trust service/);
  });

  it('turns away an issuer the trust layer refuses before fetching anything from it', async () => {
    const [issuer] = entities(eco);
    const calls: string[] = [];
    const recording = ((input: string | URL | Request, init?: RequestInit) => {
      calls.push(String(input instanceof Request ? input.url : input));
      return fetch(input, init);
    }) as typeof fetch;
    const revoked = walletWith(await pinnedTrust(eco, { pinned: { entities: [{ ...issuer!, status: 'REVOKED' }] }, http: { fetch: recording } }), { fetch: recording });
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.identity] });
    await expect(revoked.receive(offer.credentialOfferUri)).rejects.toMatchObject({ name: 'IssuanceError', code: 'issuer_not_trusted' });
    expect(calls).toEqual([]);
  });

  it('refuses an offer or an issuer over plain http outside the hosts named for development', async () => {
    const strict = walletWith(trust, { insecureHosts: [] });
    const offer = await eco.issuer.createOffer({ configurationIds: [CONFIGURATIONS.identity] });
    await expect(strict.receive(offer.credentialOfferUri)).rejects.toThrow(/must be an https URL/);
    expect(IssuanceError).toBeDefined();
  });
});

describe('status and revocation', () => {
  it('sees a revoked W3C credential and a revoked SD-JWT VC on re-verification', async () => {
    for (const id of [CONFIGURATIONS.ecdsa, CONFIGURATIONS.identity]) {
      // A fresh trust client: status lists are cached for their time to live.
      const w = walletWith(await pinnedTrust(eco));
      const c = await issue(id, w);
      const record = (await eco.issuer.credentials()).at(-1)!;
      await eco.issuer.revokeCredential(record.id);
      const again = walletWith(await pinnedTrust(eco), { credentials: w.opts.credentials, keyStore: w.opts.keyStore });
      const report = await again.reverify(c.id);
      expect(report.valid, id).toBe(false);
      expect(report.checks.find((x) => x.id.endsWith('.status')), id).toMatchObject({ status: 'fail', detail: expect.stringMatching(/revoked/i) });
    }
  });
});

describe('presentation to the reference verifier', () => {
  const present = async (credentials: Array<Record<string, unknown>>, responseMode?: string) => {
    const request = await eco.verifier.createRequest({ credentials, ...(responseMode ? { responseMode } : {}) });
    const session = await wallet.startPresentation(request.authorizationRequestUri);
    return { request, session };
  };

  it('authenticates the verifier through the trust client', async () => {
    const { session } = await present([{ format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL', claims: [['org.iso.18013.5.1', 'family_name']] }]);
    expect(session.verifier).toMatchObject({ prefix: 'x509_hash', trust: { decision: 'TRUSTED' }, name: 'Reference verifier' });
    expect(session.verifier.refusal).toBeUndefined();
  });

  it('presents an mdoc, an SD-JWT VC and a W3C credential, each accepted by the verifier', async () => {
    const queries: Array<Record<string, unknown>> = [
      { format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL', claims: [['org.iso.18013.5.1', 'family_name'], ['org.iso.18013.5.1', 'birth_date']] },
      { format: 'dc+sd-jwt', vct: 'urn:reference:identity:1', claims: [['given_name']] },
      { format: 'ldp_vc', type: ['https://www.w3.org/2018/credentials#VerifiableCredential'] },
    ];
    for (const query of queries) {
      for (const mode of ['direct_post.jwt', 'direct_post']) {
        const { request, session } = await present([query], mode);
        expect(session.dcql.satisfied, `${String(query.format)} ${session.dcql.reason ?? ''}`).toBe(true);
        const result = await session.respond();
        const state = await eco.verifier.requestState(request.id);
        expect([result.status, state.status, state.error], `${String(query.format)} ${mode}`).toEqual([200, 'verified', undefined]);
      }
    }
  });

  it('discloses only what was asked for', async () => {
    const { request, session } = await present([{ format: 'dc+sd-jwt', vct: 'urn:reference:identity:1', claims: [['given_name']] }]);
    await session.respond();
    const [shown] = Object.values((await eco.verifier.requestState(request.id)).credentials!)[0]!;
    expect(shown!.claims).toHaveProperty('given_name');
    expect(shown!.claims).not.toHaveProperty('family_name');
  });

  it('declines by telling the verifier', async () => {
    const { request, session } = await present([{ format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL' }]);
    await session.decline();
    expect((await eco.verifier.requestState(request.id)).status).toBe('rejected');
  });

  it('refuses a verifier whose certificate chains to no trusted verifier CA', async () => {
    const stranger = walletWith(await pinnedTrust(eco, {}, false), { credentials: wallet.opts.credentials, keyStore: wallet.opts.keyStore });
    const request = await eco.verifier.createRequest({ credentials: [{ format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL' }] });
    const session = await stranger.startPresentation(request.authorizationRequestUri);
    expect(session.verifier.refusal).toMatch(/does not chain to a trusted verifier CA/);
    await expect(session.respond()).rejects.toThrow(/trusted verifier CA/);
  });
});
