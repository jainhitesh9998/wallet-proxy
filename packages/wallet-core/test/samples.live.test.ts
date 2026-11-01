import { it } from 'vitest';
import { liveTrust } from './live-trust.js';
import { readFileSync } from 'node:fs';
import { verifyCredential } from '../src/verify/index.js';
it('samples', async () => {
  const trust = await liveTrust();
  const S = 'tools/mosip-issuance/samples/';
  for (const [file, fmt, iss] of [['Land-LandStatementCredential_VCDM2.0.json', 'ldp_vc', 'https://injicertify-landregistry.collab.mosip.net'],
    ['Farmer-FarmerCredential_VCDM2.0.json', 'ldp_vc', 'https://injicertify-farmer.collab.mosip.net'],
    ['MockMdl-DrivingLicenseCredential.json', 'mso_mdoc', 'https://injicertify-mdl.collab.mosip.net']] as const) {
    const j = JSON.parse(readFileSync(S + file, 'utf8'));
    const cred = j.credentials?.[0]?.credential ?? j.credential;
    const r = await verifyCredential(fmt, cred, { trust, credentialIssuer: iss, now: new Date() });
    process.stderr.write("\n" + `\n=== ${file}: valid=${r.valid} trusted=${r.trusted} type=${r.credentialType}`);
    for (const c of r.checks) process.stderr.write("\n" + `  [${c.status}] ${c.label}: ${c.detail ?? ''}`.slice(0, 220));
  }
}, 120000);
