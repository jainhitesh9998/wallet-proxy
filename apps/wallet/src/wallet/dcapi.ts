/** What the wallet registers with Android Credential Manager for Digital Credentials API requests. */
import { credentialClaims, type StoredCredential } from '@vctrust/wallet-core';
import type { DcApiEntry } from '../../modules/dc-api';
import { claimNames, credentialView, humanize, nameFor } from './display';

const MAX_VALUE = 64;

function shown(v: unknown): string | undefined {
  if (typeof v === 'string') return v.length > MAX_VALUE ? undefined : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return undefined;
}

/** Leaf claims of an SD-JWT VC (nested objects flattened into paths; arrays and binary values are not listed). */
function leaves(o: Record<string, unknown>, prefix: string[] = []): [string[], unknown][] {
  const out: [string[], unknown][] = [];
  for (const [k, v] of Object.entries(o)) {
    if (['iss', 'iat', 'nbf', 'exp', 'vct', 'cnf', 'status', '_sd_alg', 'vct#integrity'].includes(k) && !prefix.length) continue;
    if (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array)) out.push(...leaves(v as Record<string, unknown>, [...prefix, k]));
    else out.push([[...prefix, k], v]);
  }
  return out;
}

/**
 * Registry entries for the credentials the DC API can carry (mso_mdoc, dc+sd-jwt). W3C JSON-LD credentials have no
 * DC API protocol binding in OpenID4VP 1.0's matcher, so they are presented through the redirect flow only.
 */
export function dcApiEntries(credentials: StoredCredential[]): DcApiEntry[] {
  const out: DcApiEntry[] = [];
  for (const c of credentials) {
    if (c.pending || c.report?.valid === false || !c.report?.credentialType) continue;
    const format = c.format === 'mso_mdoc' ? 'mso_mdoc' : c.format === 'dc+sd-jwt' ? 'dc+sd-jwt' : undefined;
    if (!format) continue;
    let claims: Record<string, unknown>;
    try { claims = credentialClaims(c); } catch { continue; }
    const names = claimNames(c.claimMetadata);
    const paths: [string[], unknown][] = format === 'mso_mdoc'
      ? Object.entries(claims).flatMap(([ns, items]) => Object.entries(items as Record<string, unknown>).map(([el, v]) => [[ns, el], v] as [string[], unknown]))
      : leaves(claims);
    const v = credentialView(c);
    out.push({ id: c.id, format, type: c.report.credentialType, title: v.title, subtitle: v.issuer,
      claims: paths.map(([path, value]) => ({ path, name: nameFor(names, path) ?? humanize(path[path.length - 1]!), value: shown(value) })) });
  }
  return out;
}
