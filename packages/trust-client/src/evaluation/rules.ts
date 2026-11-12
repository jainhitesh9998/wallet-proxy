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
 * Each flag in force is the stricter of the two: a snapshot adds strictness, it never removes the app's. Rules are taken
 * only from a snapshot whose signature and audience verified against the pinned service keys (SnapshotManager verifies
 * the stored one again when it loads it); stored data that does not verify states nothing, and with no snapshot at all
 * the app's minimum alone is in force.
 *
 * The operator's trust mechanisms (evaluation/mechanisms.ts) are rules of the same kind, with one difference: an ordered
 * list in which the first match governs has no "stricter of the two" that is both simple and safe, so it does not
 * combine. The mechanisms of the snapshot a decision is made from govern it; without a usable snapshot, those of the last
 * snapshot that verified (a snapshot without mechanisms states an empty list); the app's own (the client option
 * {@code mechanisms}) only while no snapshot has ever verified. Once the service has spoken, its list is the list.
 */
import type { SnapshotRules } from '../snapshot/snapshot.js';
import type { TrustMechanism } from './mechanisms.js';

/** The rules in force. Each flag is a strictness: true means the stricter behaviour. */
export interface TrustRules {
  /** A certificate whose revocation status cannot be determined is not trusted ({@code x509.revocation_unknown} is an error). */
  requireRevocationStatus: boolean;
  /** An entity that lists no authorizations is authorized for nothing. */
  strictAuthorization: boolean;
  /** Issuer metadata must be signed under a {@code credential-issuer} anchor: {@code issuerMetadata.signed} is then 'require'. */
  requireSignedIssuerMetadata: boolean;
  /** The trust mechanisms in force, in the order they are tried; empty when none is. */
  mechanisms: readonly TrustMechanism[];
}

/** The rules that are flags, each of which the app can make stricter. */
export type RuleFlags = Omit<TrustRules, 'mechanisms'>;

/** The app's own minimum: a rule set to true holds whatever a snapshot says; false or absent leaves the rule to the service. */
export type MinimumRules = Partial<RuleFlags>;

const RULE_NAMES: ReadonlyArray<keyof RuleFlags> = ['requireRevocationStatus', 'strictAuthorization', 'requireSignedIssuerMetadata'];

const NO_RULES: RuleFlags = { requireRevocationStatus: false, strictAuthorization: false, requireSignedIssuerMetadata: false };

/**
 * The app's minimum as configured. A key this client does not know, or a value that is not a boolean, is refused: a
 * misspelt rule would otherwise leave the client lenient without a word.
 */
export function minimumRules(policy: unknown): RuleFlags {
  if (policy === undefined || policy === null) return { ...NO_RULES };
  if (typeof policy !== 'object' || Array.isArray(policy)) throw new Error(`policy must be an object with some of: ${RULE_NAMES.join(', ')}`);
  const rules = { ...NO_RULES };
  for (const [name, value] of Object.entries(policy)) {
    if (!(RULE_NAMES as readonly string[]).includes(name)) throw new Error(`Unknown rule policy.${name}: the rules are ${RULE_NAMES.join(', ')}`);
    if (value !== undefined && typeof value !== 'boolean') throw new Error(`policy.${name} must be true or false`);
    rules[name as keyof RuleFlags] = value === true;
  }
  return rules;
}

/** Each flag is in force when either party states it. Anything but {@code true} from a snapshot states nothing. */
export function strictest(minimum: RuleFlags, stated: Partial<RuleFlags> | null | undefined): RuleFlags {
  const rules = { ...minimum };
  for (const name of RULE_NAMES) rules[name] = minimum[name] || stated?.[name] === true;
  return rules;
}

export class RulesInForce {
  /**
   * @param minimum the app's own minimum ({@link minimumRules})
   * @param lastStated the rules of the most recent snapshot that verified, usable or not; null when none did
   * @param appMechanisms the app's own trust mechanisms, already read strictly: in force only while no snapshot has verified
   */
  constructor(private readonly minimum: RuleFlags, private readonly lastStated: () => Promise<SnapshotRules | null>,
              private readonly appMechanisms: readonly TrustMechanism[] = []) {}

  /**
   * The rules in force now. {@code decidingFrom} is the snapshot a decision is being made from, so that its data and
   * its rules are one snapshot's; without one, the rules of the last snapshot that verified hold, whether or not its
   * data can still be used. A store that cannot be read states nothing: the app's minimum, and its mechanisms, are then
   * in force.
   */
  async now(decidingFrom?: SnapshotRules | null): Promise<TrustRules> {
    const stated = decidingFrom ?? await this.lastStated().catch(() => null);
    return { ...strictest(this.minimum, stated?.policy), mechanisms: stated ? stated.mechanisms : this.appMechanisms };
  }
}
