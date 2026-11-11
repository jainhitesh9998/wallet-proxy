/**
 * Scope of the x509-limbo conformance run (test/x509-limbo.conformance.test.ts).
 *
 * The validator under test is an RFC 5280 path validator for wallet trust decisions, not a Web PKI validator. A case
 * is run unless a rule below puts it out of scope; every rule states why. Rules are matched in order, by the suite's
 * feature tags, by id prefix (or a full id), by expected result, and, for name constraints, by whether any certificate
 * of the case carries the extension. Nothing is skipped to hide a result: a case that expects FAILURE for a reason the
 * validator enforces stays in scope, and must fail.
 */
export interface LimboCase {
  id: string;
  features: string[];
  description: string;
  validation_kind: 'SERVER' | 'CLIENT';
  trusted_certs: string[];
  untrusted_intermediates: string[];
  peer_certificate: string;
  validation_time: string | null;
  key_usage: string[];
  extended_key_usage: string[];
  expected_result: 'SUCCESS' | 'FAILURE';
  expected_peer_name: { kind: string; value: string } | null;
  max_chain_depth: number | null;
  crls: string[];
}

interface ScopeRule {
  /** a feature tag of the suite; a trailing * matches a prefix */
  feature?: string;
  /** an id prefix; a full id when it does not end in "::" */
  id?: string | string[];
  expected?: 'SUCCESS' | 'FAILURE';
  /** whether some certificate of the case (peer, intermediates, trusted) carries a nameConstraints extension */
  nameConstraints?: boolean;
  reason: string;
}

const PEDANTIC = 'marked pedantic by the suite (stricter than RFC 5280 requires of a validator)';
const WEBPKI = 'tests a Web PKI / CA-Browser Forum rule, which this validator does not claim';
const SERVER_NAME = 'fails only by server-name matching: no certificate profile is selected, so no peer name is checked';
const ISSUER_CONFORMANCE = 'an RFC 5280 requirement on the issuer that changes nothing about what the certificate or CRL permits '
  + '(a missing key identifier or CRL number, the critical flag of an extension the validator processes): not enforced';

export const OUT_OF_SCOPE: ScopeRule[] = [
  // Features the validator does not have.
  { feature: 'max-chain-depth', reason: 'the validator has no maximum chain depth parameter (path length comes from the certificates)' },
  { feature: 'has-mldsa', reason: 'ML-DSA (RFC 9881) is not implemented: nothing verifies under an unsupported algorithm' },
  { feature: 'pedantic-*', reason: PEDANTIC },

  // Name constraints: present means refuse. A chain that is valid under its constraints is therefore refused too;
  // the cases that expect FAILURE stay in scope and must be refused.
  { expected: 'SUCCESS', nameConstraints: true,
    reason: 'name constraints are not evaluated: a chain carrying them is refused, so a chain that satisfies them is refused too (fail-closed)' },
  { id: 'bettertls::nameconstraints::', expected: 'FAILURE', nameConstraints: false, reason: SERVER_NAME },

  // Web PKI. The cases that expect SUCCESS stay in scope: an RFC 5280 validator must accept them.
  { id: 'webpki::', expected: 'FAILURE', reason: WEBPKI },
  { id: ['bettertls::pathbuilding::tc5', 'bettertls::pathbuilding::tc12', 'bettertls::pathbuilding::tc38', 'bettertls::pathbuilding::tc44',
    'bettertls::pathbuilding::tc71', 'bettertls::pathbuilding::tc77'], expected: 'FAILURE',
    reason: 'an intermediate\'s extendedKeyUsage (OCSPSigning) is taken to limit what it may issue: a Web PKI convention, not RFC 5280 path validation' },

  // Server names and key purposes are checked by certificate profiles, and the harness selects none.
  { id: ['rfc5280::san::underscore-dns', 'rfc5280::san::ip-in-dns', 'rfc5280::ca-as-leaf-wrong-san'], expected: 'FAILURE', reason: SERVER_NAME },
  { id: 'rfc5280::eku::ee-wrong-eku', expected: 'FAILURE',
    reason: 'fails only by the key purpose the relying party asks for: extended key usage is checked by certificate profiles, and none is selected' },

  // Issuer conformance.
  { id: ['rfc5280::aki::leaf-missing-aki', 'rfc5280::aki::intermediate-missing-aki', 'rfc5280::ski::root-missing-ski',
    'rfc5280::ski::intermediate-missing-ski', 'rfc5280::root-non-critical-basic-constraints', 'crl::crlnumber-missing', 'crl::crlnumber-critical'],
  expected: 'FAILURE', reason: ISSUER_CONFORMANCE },
];

/**
 * In-scope cases that expect SUCCESS and that this validator refuses on purpose. The harness fails when one of them
 * starts to validate (the entry is stale) or when another SUCCESS case is refused.
 */
export const STRICTER_BY_DESIGN: Record<string, string> = {
  'rfc5280::validity::notafter-fractional': 'the suite calls the case ambiguous: 5 ms after notAfter is after notAfter here (times are compared '
    + 'as instants, as on the server), where the suite prefers truncating the validation time to whole seconds',
};

const NAME_CONSTRAINTS_OID = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x1e]);
const carriesNameConstraints = (tc: LimboCase): boolean => [tc.peer_certificate, ...tc.untrusted_intermediates, ...tc.trusted_certs]
  .some((pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64').includes(NAME_CONSTRAINTS_OID));

/** Why a case is out of scope, or null when it is run. */
export function outOfScope(tc: LimboCase): string | null {
  for (const rule of OUT_OF_SCOPE) {
    if (rule.expected && rule.expected !== tc.expected_result) continue;
    if (rule.feature && !tc.features.some((f) => (rule.feature!.endsWith('*') ? f.startsWith(rule.feature!.slice(0, -1)) : f === rule.feature))) continue;
    if (rule.id && ![rule.id].flat().some((id) => (id.endsWith('::') ? tc.id.startsWith(id) : tc.id === id))) continue;
    if (rule.nameConstraints !== undefined && rule.nameConstraints !== carriesNameConstraints(tc)) continue;
    return rule.reason;
  }
  return null;
}
