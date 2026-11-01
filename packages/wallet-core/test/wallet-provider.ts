import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { SoftwareKey, WalletAttester, type SigningKey } from '../src/index.js';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'wallet-provider');
const pemBody = (p: string) => readFileSync(join(dir, p), 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s/g, '');

/** {@code highAssurance} simulates a certified WSCD (demo only: keys are software keys). */
export function demoAttester(instanceKey: SigningKey = SoftwareKey.generate(), highAssurance = false): WalletAttester {
  const jwk = createPrivateKey(readFileSync(join(dir, 'wp-signer.key'))).export({ format: 'jwk' });
  return new WalletAttester({
    issuer: 'https://wallet.vctrust.dev', clientId: 'https://wallet.vctrust.dev', walletName: 'VC Trust Demo Wallet',
    walletLink: 'https://wallet.vctrust.dev',
    ...(highAssurance ? { keyStorage: ['iso_18045_high'], userAuthentication: ['iso_18045_high'] } : {}),
    signingKey: SoftwareKey.fromJwk(jwk as never), x5c: [pemBody('wp-signer.pem')],
  }, instanceKey);
}
