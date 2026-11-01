/** SD-JWT VC (HAIP format) issuance + presentation with the Animo playground. */
import { expect, it } from 'vitest';
import { createTrustClient } from '@vctrust/trust-client';
import { MemoryCredentialStore, SoftwareKeyStore, Wallet } from '../src/index.js';

const PLAYGROUND = 'https://playground.animo.id';
const log = (s: string) => process.stderr.write(`${s}\n`);

it('issues an EUDI PID SD-JWT VC and presents selected claims', async () => {
  const trust = createTrustClient({ baseUrl: process.env.TRUST_URL ?? 'http://localhost:8090', apiKey: 'demo-wallet-key', clientId: 'demo-wallet' });
  const wallet = new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.vctrust.dev/cb' });
  const offer = (await (await fetch(`${PLAYGROUND}/api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: ['eudi-pid-sd-jwt-utopia'], authorization: 'none', deferBy: 'none', requireDpop: true,
      requireWalletAttestation: false, requireKeyAttestation: false }) })).json() as { credentialOffer: string }).credentialOffer;
  const [cred] = await wallet.store(await (await wallet.receive(offer)).acceptPreAuthorized());
  log(`== PID sd-jwt valid=${cred!.report?.valid} trusted=${cred!.report?.trusted}`);
  for (const c of cred!.report!.checks) log(`  [${c.status}] ${c.label}: ${c.detail ?? ''}`.slice(0, 180));
  expect(cred!.report!.valid).toBe(true);
  expect(cred!.report!.trusted).toBe(true);

  const req = await (await fetch(`${PLAYGROUND}/api/requests/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request: { credentials: [{ id: 'eudi-pid', formats: ['dc+sd-jwt'], attributes: ['given_name', 'family_name'] }], combination: 'all' },
      requestScheme: 'openid4vp://', responseMode: 'direct_post.jwt', requestSignerType: 'x5c', transactionAuthorizationType: 'none' }) })).json() as
    { authorizationRequestUri: string; verificationSessionId: string };
  const p = await wallet.startPresentation(req.authorizationRequestUri);
  expect(p.dcql.satisfied).toBe(true);
  expect((await p.respond()).status).toBe(200);
  let status = '';
  for (let i = 0; i < 10 && !['ResponseVerified', 'Error'].includes(status); i++) {
    status = String(((await (await fetch(`${PLAYGROUND}/api/requests/${req.verificationSessionId}`)).json()) as Record<string, unknown>).responseStatus);
    if (!['ResponseVerified', 'Error'].includes(status)) await new Promise((r) => setTimeout(r, 1000));
  }
  log(`verifier: ${status}`);
  expect(status).toBe('ResponseVerified');
}, 90_000);
