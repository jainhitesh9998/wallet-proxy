/**
 * Which rules decisions are made under. This is the one place that answers it; the evaluator (through the trust data
 * the client hands it) and the signed-metadata check both ask here.
 *
 * Two parties can tighten a rule, and neither the absence of data nor its age relaxes one:
 *
 * - the app states its own minimum (the client option {@code policy}). It holds for every decision this client makes,
 *   with or without a snapshot;
 * - the service states the client profile in every snapshot ({@code policy}). The rules of the most recent snapshot
 *   that verified stay in force once its data can no longer be used (past its expiry and grace period), also after a
 *   restart: otherwise a strict profile would turn lenient exactly when the service has been out of reach for long.
 *
 * Each rule in force is the stricter of the two: a snapshot adds strictness, it never removes the app's. Rules are taken
 * only from a snapshot whose signature and audience verified against the pinned service keys (SnapshotManager verifies
 * the stored one again when it loads it); stored data that does not verify states nothing, and with no snapshot at all
 * the app's minimum alone is in force.
 */
import type { SnapshotRules } from '../snapshot/snapshot.js';

/** The rules in force. Each one is a strictness: true means the stricter behaviour. */
export interface TrustRules {
  /** A certificate whose revocation status cannot be determined is not trusted ({@code x509.revocation_unknown} is an error). */
  requireRevocationStatus: boolean;
  /** An entity that lists no authorizations is authorized for nothing. */
  strictAuthorization: boolean;
  /** Issuer metadata must be signed under a {@code credential-issuer} anchor: {@code issuerMetadata.signed} is then 'require'. */
  requireSignedIssuerMetadata: boolean;
}

/** The app's own minimum: a rule set to true holds whatever a snapshot says; false or absent leaves the rule to the service. */
export type MinimumRules = Partial<TrustRules>;

const RULE_NAMES: ReadonlyArray<keyof TrustRules> = ['requireRevocationStatus', 'strictAuthorization', 'requireSignedIssuerMetadata'];

const NO_RULES: TrustRules = { requireRevocationStatus: false, strictAuthorization: false, requireSignedIssuerMetadata: false };

/**
 * The app's minimum as configured. A key this client does not know, or a value that is not a boolean, is refused: a
 * misspelt rule would otherwise leave the client lenient without a word.
 */
export function minimumRules(policy: unknown): TrustRules {
  if (policy === undefined || policy === null) return { ...NO_RULES };
  if (typeof policy !== 'object' || Array.isArray(policy)) throw new Error(`policy must be an object with some of: ${RULE_NAMES.join(', ')}`);
  const rules = { ...NO_RULES };
  for (const [name, value] of Object.entries(policy)) {
    if (!(RULE_NAMES as readonly string[]).includes(name)) throw new Error(`Unknown rule policy.${name}: the rules are ${RULE_NAMES.join(', ')}`);
    if (value !== undefined && typeof value !== 'boolean') throw new Error(`policy.${name} must be true or false`);
    rules[name as keyof TrustRules] = value === true;
  }
  return rules;
}

/** Each rule is in force when either party states it. Anything but {@code true} from a snapshot states nothing. */
export function strictest(minimum: TrustRules, stated: Partial<TrustRules> | null | undefined): TrustRules {
  const rules = { ...minimum };
  for (const name of RULE_NAMES) rules[name] = minimum[name] || stated?.[name] === true;
  return rules;
}

export class RulesInForce {
  /**
   * @param minimum the app's own minimum ({@link minimumRules})
   * @param lastStated the rules of the most recent snapshot that verified, usable or not; null when none did
   */
  constructor(private readonly minimum: TrustRules, private readonly lastStated: () => Promise<SnapshotRules | null>) {}

  /**
   * The rules in force now. {@code decidingFrom} is the snapshot a decision is being made from, so that its data and
   * its rules are one snapshot's; without one, the rules of the last snapshot that verified hold, whether or not its
   * data can still be used. A store that cannot be read states nothing: the app's minimum stays in force.
   */
  async now(decidingFrom?: SnapshotRules | null): Promise<TrustRules> {
    const stated = decidingFrom ?? await this.lastStated().catch(() => null);
    return strictest(this.minimum, stated?.policy);
  }
}
