/**
 * Conformance of the path validator against the C2SP x509-limbo suite (https://github.com/C2SP/x509-limbo, Apache-2.0).
 * Opt-in: it runs only when LIMBO_JSON points at limbo.json, so the normal test run stays offline.
 *
 *   LIMBO_JSON="$(sh scripts/fetch-limbo.sh)" npx vitest run test/x509-limbo.conformance.test.ts --reporter=default
 *
 * The counts are printed (the default reporter shows them also when the test passes); LIMBO_REPORT=/some/file.json
 * additionally writes them, with the outcome of every case.
 *
 * How a testcase is mapped onto this validator, which is not a Web PKI validator and does not build paths:
 *  - trusted_certs are the trust anchors; one that this library cannot parse cannot be configured, so it is left out;
 *  - the validator takes an x5c-style chain, leaf first. The harness plays the presenter: from peer_certificate it
 *    follows issuer = subject through untrusted_intermediates up to a certificate issued by (or equal to) a trusted
 *    one, and presents every such order. A SUCCESS case passes when one order validates, a FAILURE case when none
 *    does. When the pool holds no order at all the case is not applicable (but the pool as given must still not
 *    validate when FAILURE is expected);
 *  - validation_time is the time (now when the case states none); no certificate profile is selected, so the
 *    case's peer name, key usage and extended key usage are not checked: cases that fail only for those are out of
 *    scope (see x509-limbo.scope.ts);
 *  - when the case supplies CRLs, revocation is checked with them and a status that cannot be determined is an error.
 *
 * The hard requirement: no in-scope case that expects FAILURE validates. In-scope SUCCESS cases must validate,
 * except the ones listed in STRICTER_BY_DESIGN, which this validator refuses on purpose.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseCertificate, parseCrl, validateCertificateChain, type Certificate, type HeldCrl, type LocalAnchor } from '../src/primitives.js';
import { outOfScope, STRICTER_BY_DESIGN, type LimboCase } from './x509-limbo.scope.js';

const file = process.env.LIMBO_JSON;
const NO_ORDER = 'no order of the pool leads from the leaf to a trusted certificate (not applicable to a validator that is handed an ordered chain)';

const pemToDer = (pem: string): Uint8Array => new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/**
 * Issuer and subject of a certificate, read with a lenient TLV walk that is independent of the library under test:
 * the presenter must be able to order certificates the library would refuse to parse.
 */
function names(der: Uint8Array): { issuer: string; subject: string } | null {
  const tlv = (p: number) => {
    let len = der[p + 1]!;
    let v = p + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + der[v++]!;
    }
    return { tag: der[p]!, v, end: v + len };
  };
  try {
    const tbs = tlv(tlv(0).v);
    let p = tbs.v;
    if (der[p] === 0xa0) p = tlv(p).end; // version
    p = tlv(p).end; // serialNumber
    p = tlv(p).end; // signature
    const issuer = tlv(p);
    const validity = tlv(issuer.end);
    const subject = tlv(validity.end);
    if (subject.end > der.length) return null;
    return { issuer: hex(der.subarray(p, issuer.end)), subject: hex(der.subarray(validity.end, subject.end)) };
  } catch {
    return null;
  }
}

interface Node { der: Uint8Array; issuer: string; subject: string }

/** Every order [leaf, …] through the pool whose last certificate is issued by, or is, a trusted certificate. */
function orders(peer: Uint8Array, pool: Uint8Array[], trusted: Uint8Array[]): Uint8Array[][] {
  const node = (der: Uint8Array): Node | null => { const n = names(der); return n ? { der, ...n } : null; };
  const leaf = node(peer);
  if (!leaf) return [];
  const candidates = pool.map(node).filter((n): n is Node => n !== null);
  const trustedSubjects = new Set(trusted.map((t) => names(t)?.subject).filter(Boolean));
  const trustedDer = new Set(trusted.map(hex));
  const out: Uint8Array[][] = [];
  let budget = 20_000;
  const walk = (chain: Node[]): void => {
    if (out.length >= 64 || budget-- <= 0) return;
    const top = chain[chain.length - 1]!;
    if (trustedSubjects.has(top.issuer) || trustedDer.has(hex(top.der))) out.push(chain.map((c) => c.der));
    if (chain.length >= 10) return;
    for (const c of candidates) if (c.subject === top.issuer && !chain.includes(c)) walk([...chain, c]);
  };
  walk([leaf]);
  return out;
}

interface Outcome { accepted: boolean; why: string }

function validateOrder(chain: Uint8Array[], anchors: LocalAnchor[], tc: LimboCase, time: Date): Outcome {
  let parsed: Certificate[];
  try {
    parsed = chain.map((c) => parseCertificate(c));
  } catch (e) {
    return { accepted: false, why: `parse: ${(e as Error).message}` };
  }
  let crls: HeldCrl[] | undefined;
  if (tc.crls.length > 0) {
    crls = [];
    for (const pem of tc.crls) {
      try { crls.push({ crl: parseCrl(pem), source: 'limbo' }); } catch { /* a CRL that does not parse is not held */ }
    }
  }
  const r = validateCertificateChain(parsed, anchors, { time, ...(crls ? { revocation: { crls, require: true } } : {}) });
  return { accepted: r.valid, why: r.valid ? 'valid' : r.issues.filter((i) => i.severity === 'ERROR').map((i) => i.code).join(',') };
}

interface Result { id: string; expected: 'SUCCESS' | 'FAILURE'; scope: string; accepted: boolean; why: string }

function run(tc: LimboCase): Result {
  const anchors: LocalAnchor[] = [];
  const unusableAnchors: string[] = [];
  const trusted = tc.trusted_certs.map(pemToDer);
  for (const der of trusted) {
    try { anchors.push({ certificate: parseCertificate(der), domain: 'limbo' }); } catch (e) { unusableAnchors.push((e as Error).message); }
  }
  const time = tc.validation_time ? new Date(tc.validation_time) : new Date();
  const peer = pemToDer(tc.peer_certificate);
  const pool = tc.untrusted_intermediates.map(pemToDer);
  const candidates = orders(peer, pool, trusted);
  const skip = outOfScope(tc);
  let outcome: Outcome = { accepted: false, why: 'no order' };
  for (const chain of candidates) {
    outcome = validateOrder(chain, anchors, tc, time);
    if (outcome.accepted) break;
  }
  if (candidates.length === 0) {
    // Not applicable, but the pool as it stands must not validate either.
    outcome = validateOrder([peer, ...pool], anchors, tc, time);
    if (!outcome.accepted) outcome = validateOrder([peer], anchors, tc, time);
  }
  if (!outcome.accepted && unusableAnchors.length > 0) outcome.why += ` [trusted certificate not usable: ${unusableAnchors[0]}]`;
  return { id: tc.id, expected: tc.expected_result, scope: skip ?? (candidates.length === 0 ? NO_ORDER : 'in'), accepted: outcome.accepted, why: outcome.why };
}

describe.skipIf(!file)('x509-limbo conformance', () => {
  it('accepts no in-scope chain the suite expects to fail, and every in-scope chain it expects to succeed', () => {
    const suite = JSON.parse(readFileSync(file!, 'utf8')) as { testcases: LimboCase[] };
    const results = suite.testcases.map(run);

    const inScope = results.filter((r) => r.scope === 'in');
    const skipped = new Map<string, number>();
    for (const r of results) if (r.scope !== 'in') skipped.set(r.scope, (skipped.get(r.scope) ?? 0) + 1);
    // Fail-open: an in-scope FAILURE case that validated. A case with no order in the pool is not applicable, yet a
    // chain the suite expects to fail must not validate there either, unless a rule put the case out of scope.
    const failOpen = results.filter((r) => r.expected === 'FAILURE' && r.accepted && (r.scope === 'in' || r.scope === NO_ORDER));
    const failClosed = inScope.filter((r) => r.expected === 'SUCCESS' && !r.accepted);
    const unexpectedFailClosed = failClosed.filter((r) => !(r.id in STRICTER_BY_DESIGN));
    const staleStricter = Object.keys(STRICTER_BY_DESIGN).filter((id) => !failClosed.some((r) => r.id === id));
    const passed = inScope.length - failClosed.length - failOpen.filter((r) => r.scope === 'in').length;

    const lines = [
      `x509-limbo: ${results.length} cases, ${inScope.length} in scope, ${passed} passed`,
      `  in scope: ${inScope.filter((r) => r.expected === 'FAILURE').length} expect FAILURE, ${inScope.filter((r) => r.expected === 'SUCCESS').length} expect SUCCESS`,
      `  fail-open (expected FAILURE, validated): ${failOpen.length}`,
      ...failOpen.map((r) => `    ${r.id}`),
      `  in-scope SUCCESS cases refused: ${failClosed.length} (${failClosed.length - unexpectedFailClosed.length} by design)`,
      ...failClosed.map((r) => `    ${r.id}: ${r.why}${r.id in STRICTER_BY_DESIGN ? ` — by design: ${STRICTER_BY_DESIGN[r.id]}` : ''}`),
      `  out of scope: ${results.length - inScope.length}`,
      ...[...skipped].sort((a, b) => b[1] - a[1]).map(([reason, n]) => `    ${String(n).padStart(5)}  ${reason}`),
    ];
    console.log(lines.join('\n'));
    if (process.env.LIMBO_REPORT) {
      writeFileSync(process.env.LIMBO_REPORT, JSON.stringify({
        total: results.length, inScope: inScope.length, passed, failOpen: failOpen.map((r) => r.id),
        refusedSuccess: failClosed.map((r) => ({ id: r.id, why: r.why, byDesign: STRICTER_BY_DESIGN[r.id] ?? null })),
        outOfScope: Object.fromEntries(skipped), results,
      }, null, 1));
    }

    expect(failOpen.map((r) => r.id), 'chains the suite expects to fail were accepted').toEqual([]);
    expect(unexpectedFailClosed.map((r) => `${r.id}: ${r.why}`), 'in-scope chains the suite expects to succeed were refused').toEqual([]);
    expect(staleStricter, 'STRICTER_BY_DESIGN lists cases that are not refused in scope any more').toEqual([]);
    expect(inScope.length).toBeGreaterThan(0);
  }, 600_000);
});
