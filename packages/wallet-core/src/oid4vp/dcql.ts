/** DCQL (OpenID4VP 1.0 §6) evaluation against stored credentials. */
import { cbor, decodeIssuerSigned, type TrustClient } from '@vctrust/trust-client';
import { issuerSignedItems } from '../verify/mdoc.js';
import { parseSdJwt, decodeDisclosure, reconstruct } from '../verify/sdjwt.js';
import { decodeJws } from '@vctrust/trust-client';
import type { StoredCredential } from '../store/credentials.js';
import type { DcqlClaim, DcqlCredentialQuery, DcqlQuery } from './request.js';

export interface CredentialMatch {
  query: DcqlCredentialQuery;
  candidates: StoredCredential[];
  /** claims selected for disclosure for the first candidate (resolved claim set) */
  claims: DcqlClaim[];
  /** claims selected for disclosure per candidate credential id: each candidate may satisfy a different claim set */
  claimsFor: Record<string, DcqlClaim[]>;
}

export interface DcqlResult {
  satisfied: boolean;
  matches: CredentialMatch[];
  /** query ids to present (one option per required credential set) */
  selected: string[];
  reason?: string;
}

export function credentialClaims(c: StoredCredential): Record<string, unknown> {
  if (c.format === 'mso_mdoc') {
    const { issuerSigned } = decodeIssuerSigned(String(c.credential));
    const out: Record<string, Record<string, unknown>> = {};
    for (const [ns, items] of issuerSignedItems(issuerSigned)) {
      out[ns] = Object.fromEntries(items.map((i) => [i.elementIdentifier, i.elementValue]));
    }
    return out;
  }
  if (c.format === 'dc+sd-jwt' || c.format === 'vc+sd-jwt') {
    const p = parseSdJwt(String(c.credential));
    return reconstruct(decodeJws(p.issuerJwt).payload as Record<string, unknown>, p.disclosures.map(decodeDisclosure)).claims;
  }
  const vc = (typeof c.credential === 'string' ? JSON.parse(c.credential) : c.credential) as Record<string, unknown>;
  return { ...vc, credentialSubject: vc.credentialSubject };
}

function credentialType(c: StoredCredential): { doctype?: string; vct?: string; types: string[] } {
  if (c.format === 'mso_mdoc') return { doctype: c.report?.credentialType, types: [] };
  if (c.format === 'dc+sd-jwt' || c.format === 'vc+sd-jwt') return { vct: c.report?.credentialType, types: [] };
  const vc = (typeof c.credential === 'string' ? JSON.parse(c.credential) : c.credential) as { type?: string[] };
  return { types: vc.type ?? [] };
}

function pathValues(root: unknown, path: (string | number | null)[]): unknown[] {
  let current: unknown[] = [root];
  for (const seg of path) {
    const next: unknown[] = [];
    for (const v of current) {
      if (seg === null && Array.isArray(v)) next.push(...v);
      else if (typeof seg === 'number' && Array.isArray(v) && seg < v.length) next.push(v[seg]);
      else if (typeof seg === 'string' && v && typeof v === 'object' && !Array.isArray(v) && Object.prototype.hasOwnProperty.call(v, seg)) next.push((v as Record<string, unknown>)[seg]);
    }
    current = next;
  }
  return current;
}

function claimSatisfied(claims: Record<string, unknown>, c: DcqlClaim, format: string): boolean {
  const path = format === 'ldp_vc' || format === 'jwt_vc_json' ? c.path : c.path;
  const vals = pathValues(claims, path).map((v) => (v instanceof cbor.Tagged ? v.value : v));
  if (vals.length === 0) return false;
  if (!c.values) return true;
  return vals.some((v) => c.values!.some((w) => w === v));
}

function typeMatches(q: DcqlCredentialQuery, c: StoredCredential): boolean {
  if (q.format !== c.format) return false;
  const t = credentialType(c);
  const meta = q.meta ?? {};
  if (q.format === 'mso_mdoc') return !meta.doctype_value || meta.doctype_value === t.doctype;
  if (q.format === 'dc+sd-jwt' || q.format === 'vc+sd-jwt') return !Array.isArray(meta.vct_values) || (meta.vct_values as string[]).includes(t.vct ?? '');
  const alternatives = meta.type_values as string[][] | undefined;
  if (!alternatives) return true;
  // type_values are fully expanded IRIs; compare by IRI or by the term's local name.
  return alternatives.some((alt) => alt.every((iri) => t.types.some((ty) => ty === iri || iri.endsWith(`/${ty}`) || iri.endsWith(`#${ty}`))));
}

/** Can the holder prove possession? SD-JWT VCs need a cnf key; mdocs carry a device key, ldp VPs are signed by the holder. */
function holderBound(c: StoredCredential): boolean {
  if (c.format !== 'dc+sd-jwt' && c.format !== 'vc+sd-jwt') return true;
  const payload = decodeJws<Record<string, unknown>>(parseSdJwt(String(c.credential)).issuerJwt).payload;
  return !!(payload.cnf as { jwk?: unknown } | undefined)?.jwk;
}

export async function evaluateDcql(query: DcqlQuery, credentials: StoredCredential[], trust?: TrustClient): Promise<DcqlResult> {
  const matches: CredentialMatch[] = [];
  for (const q of query.credentials) {
    const candidates: StoredCredential[] = [];
    const claimsFor: Record<string, DcqlClaim[]> = {};
    for (const c of credentials) {
      // Deferred credentials still pending have nothing to present yet.
      if (c.pending || c.credential === undefined || c.credential === null) continue;
      if (!typeMatches(q, c)) continue;
      // require_cryptographic_holder_binding defaults to true (OpenID4VP §6.1).
      if (q.require_cryptographic_holder_binding !== false && !holderBound(c)) continue;
      const claims = credentialClaims(c);
      let chosenClaims: DcqlClaim[] = q.claims ?? [];
      let ok = true;
      if (q.claims && q.claims.length) {
        if (q.claim_sets?.length) {
          const byId = new Map(q.claims.map((x) => [x.id, x]));
          const set = q.claim_sets.find((s) => s.every((id) => { const cl = byId.get(id); return cl && claimSatisfied(claims, cl, q.format); }));
          ok = !!set;
          if (set) chosenClaims = set.map((id) => byId.get(id)!);
        } else ok = q.claims.every((cl) => claimSatisfied(claims, cl, q.format));
      }
      if (ok && q.trusted_authorities?.length && trust) {
        const r = await trust.evaluateCredential(c.credential, c.format, { credentialIssuer: c.credentialIssuer, trustedAuthorities: q.trusted_authorities });
        ok = (r.decision.evidence?.trustedAuthorities ?? []).some((m) => m.matched);
      }
      if (ok) { candidates.push(c); claimsFor[c.id] = chosenClaims; }
    }
    matches.push({ query: q, candidates, claims: candidates[0] ? claimsFor[candidates[0].id]! : q.claims ?? [], claimsFor });
  }
  const has = (id: string) => (matches.find((m) => m.query.id === id)?.candidates.length ?? 0) > 0;
  if (!query.credential_sets?.length) {
    const missing = matches.filter((m) => m.candidates.length === 0).map((m) => m.query.id);
    return { satisfied: missing.length === 0, matches, selected: matches.map((m) => m.query.id),
      reason: missing.length ? `No matching credential for ${missing.join(', ')}` : undefined };
  }
  const selected: string[] = [];
  for (const set of query.credential_sets) {
    const option = set.options.find((opt) => opt.every(has));
    if (option) selected.push(...option);
    else if (set.required !== false) return { satisfied: false, matches, selected, reason: 'A required credential set cannot be satisfied' };
  }
  return { satisfied: true, matches, selected: [...new Set(selected)] };
}
