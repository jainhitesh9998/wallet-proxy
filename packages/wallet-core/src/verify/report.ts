import type { TrustDecision } from '@vctrust/trust-client';
import type { IssuerInfo } from '@vctrust/trust-client/primitives';

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'skip';

export interface Check {
  id: string;
  label: string;
  status: CheckStatus;
  detail?: string;
}

/** Result of verifying a credential: cryptographic checks plus the issuer trust decision. */
export interface VerificationReport {
  format: string;
  /** All cryptographic / integrity / validity checks passed (warnings allowed). Trust is reported separately. */
  valid: boolean;
  /** valid && issuer TRUSTED */
  trusted: boolean;
  checks: Check[];
  issuer: IssuerInfo;
  trust: TrustDecision | null;
  claims: Record<string, unknown>;
  credentialType?: string;
  validFrom?: string;
  validUntil?: string;
}

export class Checks {
  readonly list: Check[] = [];
  pass(id: string, label: string, detail?: string) { this.list.push({ id, label, status: 'pass', detail }); }
  fail(id: string, label: string, detail?: string) { this.list.push({ id, label, status: 'fail', detail }); }
  warn(id: string, label: string, detail?: string) { this.list.push({ id, label, status: 'warn', detail }); }
  skip(id: string, label: string, detail?: string) { this.list.push({ id, label, status: 'skip', detail }); }
  get ok(): boolean { return !this.list.some((c) => c.status === 'fail'); }
}

export function finish(format: string, checks: Checks, issuer: IssuerInfo, trust: TrustDecision | null,
                       claims: Record<string, unknown>, extra: Partial<VerificationReport> = {}): VerificationReport {
  if (trust) {
    const status = trust.decision === 'TRUSTED' ? 'pass' : trust.decision === 'UNKNOWN' ? 'warn' : 'fail';
    checks.list.push({ id: 'issuer.trust', label: 'Issuer trust', status, detail: `${trust.decision} (${trust.source}): ${trust.summary}` });
  }
  const valid = !checks.list.some((c) => c.status === 'fail' && c.id !== 'issuer.trust');
  return { format, valid, trusted: valid && trust?.decision === 'TRUSTED', checks: checks.list, issuer, trust, claims, ...extra };
}
