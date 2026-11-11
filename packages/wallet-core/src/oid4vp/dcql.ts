/** DCQL (OpenID4VP 1.0 §6) evaluation against stored credentials. */
import type { TrustClient } from '@vctrust/trust-client';
import { cbor, decodeJws, extractIssuerInfo, issuerTrustQuery } from '@vctrust/trust-client/primitives';
import { decodeIssuedMdoc, issuerSignedItems } from '../verify/mdoc.js';
import { parseSdJwt, decodeDisclosure, reconstruct } from '../verify/sdjwt.js';
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
  /** query ids to present: every query, or one option of each required credential set */
  selected: string[];
  /** query ids of satisfiable credential sets the verifier marked as not required: presented only when the user adds them */
  optional: string[];
  reason?: string;
}

const ID = /^[A-Za-z0-9_-]+$/;

/**
 * What is wrong with a DCQL query's structure (OpenID4VP 1.0 §6), or undefined. A query the wallet cannot read
 * exactly is refused rather than answered loosely: a claims path that selects everything, for one, would disclose
 * a whole credential.
 */
export function dcqlProblem(query: unknown): string | undefined {
  const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
  if (!isObject(query) || !Array.isArray(query.credentials) || query.credentials.length === 0) return 'credentials must be a non-empty list';
  const ids = new Set<string>();
  for (const q of query.credentials as unknown[]) {
    if (!isObject(q) || typeof q.id !== 'string' || !ID.test(q.id)) return 'a credential query has no valid id';
    if (ids.has(q.id)) return `credential query id ${q.id} is used twice`;
    ids.add(q.id);
    if (typeof q.format !== 'string' || !q.format) return `credential query ${q.id} has no format`;
    if (q.meta !== undefined && !isObject(q.meta)) return `credential query ${q.id}: meta is not an object`;
    const claimIds = new Set<string>();
    if (q.claims !== undefined) {
      if (!Array.isArray(q.claims) || q.claims.length === 0) return `credential query ${q.id}: claims must be a non-empty list`;
      for (const c of q.claims as unknown[]) {
        if (!isObject(c) || !Array.isArray(c.path) || c.path.length === 0) return `credential query ${q.id}: a claim has no path`;
        if (!c.path.every((p) => typeof p === 'string' || p === null || (Number.isInteger(p) && (p as number) >= 0))) return `credential query ${q.id}: a claims path holds something other than a name, an index or null`;
        // ISO mdoc: a namespace and a data element identifier (Appendix B.2.4).
        if (q.format === 'mso_mdoc' && !(c.path.length === 2 && c.path.every((p) => typeof p === 'string'))) return `credential query ${q.id}: an mdoc claims path is a namespace and an element identifier`;
        if (c.id !== undefined) {
          if (typeof c.id !== 'string' || !ID.test(c.id) || claimIds.has(c.id)) return `credential query ${q.id}: a claim id is invalid or used twice`;
          claimIds.add(c.id);
        }
        if (c.values !== undefined && !(Array.isArray(c.values) && c.values.length > 0 && c.values.every((v) => ['string', 'number', 'boolean'].includes(typeof v)))) {
          return `credential query ${q.id}: claim values must be a non-empty list of strings, numbers or booleans`;
        }
      }
    }
    if (q.claim_sets !== undefined) {
      if (!Array.isArray(q.claims)) return `credential query ${q.id}: claim_sets without claims`;
      const sets = q.claim_sets as unknown[];
      if (!Array.isArray(sets) || sets.length === 0 || !sets.every((s) => Array.isArray(s) && s.length > 0 && s.every((id) => typeof id === 'string' && claimIds.has(id)))) {
        return `credential query ${q.id}: claim_sets must list ids of its claims`;
      }
    }
  }
  if (query.credential_sets !== undefined) {
    const sets = query.credential_sets as unknown[];
    if (!Array.isArray(sets) || sets.length === 0) return 'credential_sets must be a non-empty list';
    for (const s of sets) {
      if (!isObject(s) || !Array.isArray(s.options) || s.options.length === 0
        || !s.options.every((o) => Array.isArray(o) && o.length > 0 && o.every((id) => typeof id === 'string' && ids.has(id)))) return 'a credential set must list options of credential query ids';
      if (s.required !== undefined && typeof s.required !== 'boolean') return 'credential_sets: required must be true or false';
    }
  }
  return undefined;
}

export function credentialClaims(c: StoredCredential): Record<string, unknown> {
  if (c.format === 'mso_mdoc') {
    const issuerSigned = decodeIssuedMdoc(String(c.credential));
    const out: Record<string, Record<string, unknown>> = {};
    for (const [ns, items] of issuerSignedItems(issuerSigned)) {
      out[ns] = Object.fromEntries(items.map((i) => [i.elementIdentifier, i.elementValue]));
    }
    return out;
  }
  if (c.format === 'dc+sd-jwt') {
    const p = parseSdJwt(String(c.credential));
    return reconstruct(decodeJws(p.issuerJwt).payload as Record<string, unknown>, p.disclosures.map(decodeDisclosure)).claims;
  }
  const vc = (typeof c.credential === 'string' ? JSON.parse(c.credential) : c.credential) as Record<string, unknown>;
  return { ...vc, credentialSubject: vc.credentialSubject };
}

function credentialType(c: StoredCredential): { doctype?: string; vct?: string; types: string[] } {
  if (c.format === 'mso_mdoc') return { doctype: c.report?.credentialType, types: [] };
  if (c.format === 'dc+sd-jwt') return { vct: c.report?.credentialType, types: [] };
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

function claimSatisfied(claims: Record<string, unknown>, c: DcqlClaim): boolean {
  if (!Array.isArray(c.path) || c.path.length === 0) return false;
  const vals = pathValues(claims, c.path).map((v) => (v instanceof cbor.Tagged ? v.value : v));
  if (vals.length === 0) return false;
  if (!c.values) return true;
  return vals.some((v) => c.values!.some((w) => w === v));
}

function typeMatches(q: DcqlCredentialQuery, c: StoredCredential): boolean {
  if (q.format !== c.format) return false;
  const t = credentialType(c);
  const meta = q.meta ?? {};
  if (q.format === 'mso_mdoc') return !meta.doctype_value || meta.doctype_value === t.doctype;
  if (q.format === 'dc+sd-jwt') return !Array.isArray(meta.vct_values) || (meta.vct_values as string[]).includes(t.vct ?? '');
  const alternatives = meta.type_values as string[][] | undefined;
  if (!alternatives) return true;
  // type_values are fully expanded IRIs; compare by IRI or by the term's local name.
  return alternatives.some((alt) => alt.every((iri) => t.types.some((ty) => ty === iri || iri.endsWith(`/${ty}`) || iri.endsWith(`#${ty}`))));
}

/** Can the holder prove possession? SD-JWT VCs need a cnf key; mdocs carry a device key, ldp VPs are signed by the holder. */
function holderBound(c: StoredCredential): boolean {
  if (c.unbound) return false;
  if (c.format !== 'dc+sd-jwt') return true;
  const payload = decodeJws<Record<string, unknown>>(parseSdJwt(String(c.credential)).issuerJwt).payload;
  return !!(payload.cnf as { jwk?: unknown } | undefined)?.jwk;
}

/**
 * Which stored credentials answer the query. A credential whose last verification failed (invalid, expired, revoked)
 * is never a candidate: the wallet does not present what it would itself refuse.
 */
export async function evaluateDcql(query: DcqlQuery, credentials: StoredCredential[], trust?: TrustClient): Promise<DcqlResult> {
  const matches: CredentialMatch[] = [];
  for (const q of query.credentials) {
    const candidates: StoredCredential[] = [];
    const claimsFor: Record<string, DcqlClaim[]> = {};
    for (const c of credentials) {
      // Deferred credentials still pending have nothing to present yet.
      if (c.pending || c.credential === undefined || c.credential === null) continue;
      if (c.report?.valid === false || c.report?.trust?.decision === 'NOT_TRUSTED') continue;
      if (!typeMatches(q, c)) continue;
      // require_cryptographic_holder_binding defaults to true (OpenID4VP §6.1).
      if (q.require_cryptographic_holder_binding !== false && !holderBound(c)) continue;
      const claims = credentialClaims(c);
      let chosenClaims: DcqlClaim[] = q.claims ?? [];
      let ok = true;
      if (q.claims && q.claims.length) {
        if (q.claim_sets?.length) {
          const byId = new Map(q.claims.map((x) => [x.id, x]));
          const set = q.claim_sets.find((s) => s.every((id) => { const cl = byId.get(id); return cl && claimSatisfied(claims, cl); }));
          ok = !!set;
          if (set) chosenClaims = set.map((id) => byId.get(id)!);
        } else ok = q.claims.every((cl) => claimSatisfied(claims, cl));
      }
      if (ok && q.trusted_authorities?.length && trust) {
        // §6.1.1: the credential's issuer must match one of the trusted authorities; the trust layer knows which it matches.
        const trustQuery = issuerTrustQuery(extractIssuerInfo(c.credential, c.format), 'oid4vp');
        const d = await trust.evaluate({ ...trustQuery, context: { ...trustQuery.context, trustedAuthorities: q.trusted_authorities } });
        ok = (d.evidence?.trustedAuthorities ?? []).some((m) => m.matched);
      }
      if (ok) { candidates.push(c); claimsFor[c.id] = chosenClaims; }
    }
    matches.push({ query: q, candidates, claims: candidates[0] ? claimsFor[candidates[0].id]! : q.claims ?? [], claimsFor });
  }
  const has = (id: string) => (matches.find((m) => m.query.id === id)?.candidates.length ?? 0) > 0;
  if (!query.credential_sets?.length) {
    const missing = matches.filter((m) => m.candidates.length === 0).map((m) => m.query.id);
    return { satisfied: missing.length === 0, matches, selected: matches.map((m) => m.query.id), optional: [],
      reason: missing.length ? `No matching credential for ${missing.join(', ')}` : undefined };
  }
  const selected: string[] = [];
  const optional: string[] = [];
  for (const set of query.credential_sets) {
    const option = set.options.find((opt) => opt.every(has));
    if (option) (set.required === false ? optional : selected).push(...option);
    else if (set.required !== false) return { satisfied: false, matches, selected, optional, reason: 'A required credential set cannot be satisfied' };
  }
  const required = [...new Set(selected)];
  return { satisfied: true, matches, selected: required, optional: [...new Set(optional)].filter((id) => !required.includes(id)) };
}
