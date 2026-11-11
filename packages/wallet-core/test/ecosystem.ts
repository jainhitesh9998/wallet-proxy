/**
 * The reference ecosystem (test-ecosystem/: an issuer and a verifier built on third-party OpenID4VC, Data Integrity,
 * mdoc and SD-JWT libraries), run as a process of its own and driven over HTTP like any issuer or verifier, and a
 * wallet that knows it only through a trust client.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTrustClient, MemoryCacheStore, type EntityView, type TrustClient, type TrustClientConfig } from '@vctrust/trust-client';
import { MemoryCredentialStore, SoftwareKeyStore, Wallet, type WalletOptions } from '../src/index.js';

export const LOOPBACK = ['localhost', '127.0.0.1'];

export const CONFIGURATIONS = {
  ecdsa: 'UniversityDegree_ldp_vc_ecdsa-rdfc-2019',
  eddsa: 'UniversityDegree_ldp_vc_eddsa-rdfc-2022',
  mdl: 'mDL_mso_mdoc',
  identity: 'Identity_dc_sd_jwt',
} as const;

export interface Offer { offerId: string; credentialOfferUri: string; credentialOffer: Record<string, unknown>; txCode?: string }
export interface RequestState { id: string; status: 'pending' | 'verified' | 'failed' | 'rejected' | 'expired'; error?: string;
  credentials?: Record<string, Array<{ format: string; issuer?: string; type: string | string[]; claims: Record<string, unknown> }>> }

export interface Ecosystem {
  issuerUrl: string;
  verifierUrl: string;
  issuer: {
    did: string;
    createOffer(options: { configurationIds: string[]; grant?: 'pre-authorized_code' | 'authorization_code'; txCode?: boolean | string;
      claims?: Record<string, unknown>; deferSeconds?: number }): Promise<Offer>;
    credentials(): Promise<Array<{ id: string; configurationId: string; format: string; revoked: boolean }>>;
    revokeCredential(id: string): Promise<void>;
    revokeDocumentSigner(): Promise<void>;
    notifications(): Promise<Array<{ event: string; event_description?: string }>>;
  };
  verifier: {
    clientId: string;
    createRequest(options: { credentials: Array<Record<string, unknown>>; responseMode?: string }): Promise<{ id: string; authorizationRequestUri: string }>;
    requestState(id: string): Promise<RequestState>;
  };
  stop(): Promise<void>;
}

const freePort = () => new Promise<number>((resolve, reject) => {
  const s = createServer();
  s.once('error', reject);
  s.listen(0, 'localhost', () => {
    const { port } = s.address() as { port: number };
    s.close(() => resolve(port));
  });
});

async function call<T>(url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
  return await r.json() as T;
}

/** Starts the ecosystem on free loopback ports, with its data in a temporary directory. */
export async function start(): Promise<Ecosystem> {
  const [issuerPort, verifierPort] = [await freePort(), await freePort()];
  const dataDir = mkdtempSync(join(tmpdir(), 'reference-ecosystem-'));
  const entry = createRequire(import.meta.url).resolve('@vctrust/reference-ecosystem');
  const child: ChildProcess = spawn(process.execPath, [entry], { stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, ISSUER_PORT: String(issuerPort), VERIFIER_PORT: String(verifierPort), DATA_DIR: dataDir } });
  let output = '';
  child.stdout!.on('data', (d: Buffer) => { output += d.toString(); });
  child.stderr!.on('data', (d: Buffer) => { output += d.toString(); });
  const stop = async () => {
    if (child.exitCode === null) {
      await new Promise<void>((resolve) => { child.once('exit', () => resolve()); child.kill('SIGTERM'); });
    }
    rmSync(dataDir, { recursive: true, force: true });
  };
  // The program prints its addresses once both servers answer.
  const deadline = Date.now() + 30_000;
  while (!/client_id\s+\S+/.test(output)) {
    if (child.exitCode !== null || Date.now() > deadline) {
      await stop();
      throw new Error(`The reference ecosystem did not start: ${output.slice(-600)}`);
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  const issuerUrl = `http://localhost:${issuerPort}`;
  const verifierUrl = `http://localhost:${verifierPort}`;
  return {
    issuerUrl, verifierUrl, stop,
    issuer: {
      did: /issuer DID\s+(\S+)/.exec(output)![1]!,
      createOffer: (options) => call(`${issuerUrl}/api/offers`, options),
      credentials: () => call(`${issuerUrl}/api/credentials`),
      revokeCredential: async (id) => { await call(`${issuerUrl}/api/revoke`, { id }); },
      revokeDocumentSigner: async () => { await call(`${issuerUrl}/api/revoke-document-signer`, {}); },
      notifications: () => call(`${issuerUrl}/api/notifications`),
    },
    verifier: {
      clientId: /client_id\s+(\S+)/.exec(output)![1]!,
      createRequest: (options) => call(`${verifierUrl}/api/requests`, options),
      requestState: (id) => call(`${verifierUrl}/api/requests/${id}`),
    },
  };
}

const pem = async (url: string) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
};

/** The ecosystem's parties as a registry would list them: the issuer by its URL and DID, the verifier by its client identifier. */
export function entities(eco: Ecosystem): EntityView[] {
  return [
    { id: 'reference-issuer', frameworkId: 'reference', roles: ['CREDENTIAL_ISSUER'], status: 'ACTIVE', display: [{ locale: 'en', name: 'Reference issuer' }],
      identifiers: [{ type: 'URL', value: eco.issuerUrl }, { type: 'DID', value: eco.issuer.did }], authorizations: [] },
    { id: 'reference-verifier', frameworkId: 'reference', roles: ['VERIFIER'], status: 'ACTIVE', display: [{ locale: 'en', name: 'Reference verifier' }],
      identifiers: [{ type: 'CLIENT_ID', value: eco.verifier.clientId }], authorizations: [] },
  ] as EntityView[];
}

/** The ecosystem's trust anchors, by trust domain. */
export async function anchors(eco: Ecosystem) {
  return [
    { domain: 'mdoc-iaca', frameworkId: 'reference', certificate: await pem(`${eco.issuerUrl}/pki/iaca.pem`) },
    { domain: 'credential-issuer', frameworkId: 'reference', certificate: await pem(`${eco.issuerUrl}/pki/issuer-ca.pem`) },
    { domain: 'verifier-access', frameworkId: 'reference', certificate: await pem(`${eco.verifierUrl}/pki/verifier-ca.pem`) },
  ];
}

/** A trust client without a service: the ecosystem's anchors and parties pinned, every lookup by the standard mechanism. */
export async function pinnedTrust(eco: Ecosystem, config: Partial<TrustClientConfig> = {}, known = true): Promise<TrustClient> {
  return createTrustClient({ pinned: known ? { anchors: await anchors(eco), entities: entities(eco) } : {}, storage: new MemoryCacheStore(),
    ...config, http: { insecureHosts: LOOPBACK, ...config.http } });
}

export function walletWith(trust: TrustClient, options: Partial<WalletOptions> = {}): Wallet {
  return new Wallet({ trust, keyStore: new SoftwareKeyStore(), credentials: new MemoryCredentialStore(), redirectUri: 'https://wallet.example/callback',
    clientId: 'reference-wallet', insecureHosts: LOOPBACK, ...options });
}
