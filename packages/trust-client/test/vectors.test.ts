/**
 * The service's evaluator is the reference; this library must reach the same outcomes from the snapshot the service
 * signs. conformance/evaluation/vectors.json holds those snapshots (for a lenient and a strict client) and, for
 * each query, what the service itself decided (EvaluationVectorsTest.java generates it and fails when it is stale).
 * conformance/evaluation/mechanisms.vectors.json is the second pair, from a service with the operator's trust mechanisms
 * (MechanismVectorsTest.java): its snapshots are format 5, and each outcome also names the mechanism that governed it.
 * Offline: the only requests are for the snapshot and the service's keys.
 */
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { describe, expect, it } from 'vitest';
import { createTrustClient, MemoryCacheStore, type TrustDecision, type TrustQuery } from '../src/index.js';
import { jwkThumbprint } from '../src/primitives.js';
import { es256Key, fakeFetch, json, signJwt } from './helpers.js';

interface Outcome { decision: string; errors: string[]; warnings: string[]; entity: string | null;
  x509: { valid: boolean; anchorFound: boolean; revocation: string[] } | null; trustedAuthorities: Array<string | null>; framework: string | null; matched: string[];
  /** only in the second pair: the mechanism that governed the query, null when none did */
  mechanism?: string | null }
interface Vectors {
  snapshots: Record<string, Record<string, unknown>>;
  cases: Array<{ name: string; query: TrustQuery; expect: Record<string, Outcome> }>;
}
const read = (file: string) => JSON.parse(readFileSync(new URL(`../../../conformance/evaluation/${file}`, import.meta.url), 'utf8')) as Vectors;
const PAIRS: Array<{ file: string; vectors: Vectors; withMechanism: boolean }> = [
  { file: 'vectors.json', vectors: read('vectors.json'), withMechanism: false },
  { file: 'mechanisms.vectors.json', vectors: read('mechanisms.vectors.json'), withMechanism: true },
];

const BASE = 'https://trust.test';
const key = es256Key();
const jwk = { ...key.jwk, kty: 'EC', kid: 'vectors', alg: 'ES256' };

/** What must agree; reasons about where the decision was made (local.*, snapshot.*) are not part of it. */
function outcome(d: TrustDecision, withMechanism: boolean): Outcome {
  const codes = (severity: string) => [...new Set(d.reasons.filter((r) => r.severity === severity).map((r) => r.code)
    .filter((c) => !c.startsWith('local.') && !c.startsWith('snapshot.')))].sort();
  return {
    decision: d.decision, errors: codes('ERROR'), warnings: codes('WARNING'), entity: d.entity?.id ?? null,
    x509: d.evidence?.x509 ? { valid: d.evidence.x509.valid, anchorFound: d.evidence.x509.anchorFound,
      revocation: (d.evidence.x509.revocation ?? []).map((r) => r.status) } : null,
    trustedAuthorities: (d.evidence?.trustedAuthorities ?? []).map((t) => (t.matched ? t.matchedValue ?? null : null)),
    framework: d.framework?.id ?? null,
    matched: [...(d.evidence?.matchedIdentifiers ?? [])].sort(),
    ...(withMechanism ? { mechanism: d.evidence?.mechanism ?? null } : {}),
  };
}

for (const { file, vectors, withMechanism } of PAIRS) {
  describe(`evaluation vectors (${file}): the device decides as the service does`, () => {
    // Also with the registry listed backwards: no outcome may depend on the order a snapshot lists entities and anchors in.
    for (const [profile, order] of Object.keys(vectors.snapshots).flatMap((p) => [[p, 'as listed'], [p, 'reversed']] as const)) {
      it(`${profile} client, registry ${order}: ${vectors.cases.length} queries`, async () => {
        const listed = vectors.snapshots[profile]!;
        const claims = order === 'reversed' ? { ...listed, entities: [...(listed.entities as unknown[])].reverse(), anchors: [...(listed.anchors as unknown[])].reverse() } : listed;
        const now = Math.floor(Date.now() / 1000);
        const snapshot = signJwt({ alg: 'ES256', typ: 'trust-snapshot+jwt', kid: 'vectors' }, { ...claims, iss: BASE, aud: profile, iat: now, exp: now + 3600 }, key.privateKey);
        const { fetch, calls } = fakeFetch({
          [`${BASE}/api/v1/snapshot`]: () => new Response(snapshot, { headers: { 'Content-Type': 'application/jwt' } }),
          [`${BASE}/.well-known/jwks.json`]: () => json({ keys: [jwk] }),
        });
        const client = createTrustClient({ service: { url: BASE, clientId: profile, keys: { thumbprints: [jwkThumbprint(jwk)] } },
          // As the service ran when the vectors were generated: no CRL is fetched beyond those the snapshot carries.
          lookups: { crl: 'none' }, http: { fetch, retries: 0 }, storage: new MemoryCacheStore() });
        // The mechanisms decided under are the snapshot's, in the order the service stated them.
        await client.sync();
        expect((await client.status()).rules?.mechanisms.map((m) => m.id)).toEqual(((listed.mechanisms ?? []) as Array<{ id: string }>).map((m) => m.id));
        const differences: string[] = [];
        for (const c of vectors.cases) {
          const got = outcome(await client.evaluate(c.query), withMechanism);
          const want = c.expect[profile]!;
          // Why a path is invalid (x509.path.*): the service's validator stops at the first broken rule, this one
          // reports every rule it finds broken. The device must name what the service names; it may name more.
          const detail = (codes: string[]) => codes.filter((code) => code.startsWith('x509.path.'));
          const named = detail(want.errors).every((code) => got.errors.includes(code)) && (detail(want.errors).length > 0) === (detail(got.errors).length > 0);
          const rest = (o: Outcome) => ({ ...o, errors: o.errors.filter((code) => !code.startsWith('x509.path.')) });
          if (!named || !isDeepStrictEqual(rest(got), rest(want))) {
            differences.push(`${c.name}\n  service: ${JSON.stringify(want)}\n  device:  ${JSON.stringify(got)}`);
          }
        }
        expect(differences, `\n${differences.join('\n')}\n`).toEqual([]);
        expect(calls.filter((x) => !x.includes(BASE))).toEqual([]);
      });
    }
  });
}
