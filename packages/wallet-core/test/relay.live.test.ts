/**
 * Live: the trust service's relays. A CRL (Animo's IACA CRL) and a credential status list (MOSIP Land) are fetched
 * through the service and verified on the device as if fetched directly: the relay is not trusted.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyX509Signature } from '@vctrust/trust-client';
import { liveTrust } from './live-trust.js';
import { verifyLdpVc } from '../src/index.js';

const LAND = JSON.parse(readFileSync(new URL('../../trust-client/test/fixtures/Land-LandStatementCredential_VCDM2.0.json', import.meta.url), 'utf8'));
const land = (LAND.credentials?.[0]?.credential ?? LAND.credential) as Record<string, unknown>;

const trust = await liveTrust({ lookups: { crl: 'service', statusLists: 'service' } });

describe('trust service relays', () => {
  it('relays the Animo IACA CRL; the device verifies it against the Animo root from the snapshot', async () => {
    const { crls, failures } = await trust.fetchCrls(['https://playground.animo.id/crl']);
    expect(failures).toEqual({});
    expect(crls[0]).toMatchObject({ source: 'trust-service', url: 'https://playground.animo.id/crl' });
    const root = (await trust.syncSnapshot()).anchors.find((a) => a.certificate.subject === crls[0]!.crl.issuer);
    expect(root).toBeDefined();
    expect(verifyX509Signature(crls[0]!.crl, root!.certificate.publicKey)).toBe(true);
  }, 30_000);

  it('relays a status list without the issuer seeing the device, and the device still verifies the list', async () => {
    const entry = land.credentialStatus as { statusListCredential: string };
    const r = await trust.fetchStatusList(entry.statusListCredential, 'application/vc+ld+json, application/json');
    expect(r.source).toBe('trust-service');
    expect((JSON.parse(new TextDecoder().decode(r.body)) as { type: string[] }).type).toContain('BitstringStatusListCredential');
    // MOSIP signs this list with a key that is not in its DID document, so its status cannot be relied on.
    const report = await verifyLdpVc(land, { trust, credentialIssuer: 'https://injicertify-landregistry.collab.mosip.net' });
    expect(report.checks.find((c) => c.id === 'ldp.status')).toMatchObject({ status: 'warn', detail: expect.stringMatching(/does not verify/) });
  }, 60_000);
});
