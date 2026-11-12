/**
 * How one CRL is read, and how several for one certificate decide, exactly as conformance/revocation/crl-cases.json says.
 * The device's rule (checkRevocation) is the one the file writes down; the service's RevocationChecker is held to the same
 * file (CrlCasesTest.java), so that a verifier backend asking the service gets no laxer answer than a device.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { checkRevocation, parseCertificate, parseCrl, type HeldCrl } from '../src/primitives.js';

interface Case {
  name: string;
  about: string;
  certificate: string;
  issuer: string;
  crls: string[];
  expect: { status: string; reason: string | null; crl: number | null };
}
interface Cases { at: string; certificates: Record<string, string>; cases: Case[] }

const file = JSON.parse(readFileSync(new URL('../../../conformance/revocation/crl-cases.json', import.meta.url), 'utf8')) as Cases;
const der = (b64: string) => new Uint8Array(Buffer.from(b64, 'base64'));
const certificates = Object.fromEntries(Object.entries(file.certificates).map(([name, b64]) => [name, parseCertificate(der(b64))]));
/** Each CRL is held under a URL naming its position, so that the outcome tells which one decided. */
const heldUrl = (i: number) => `https://crl.test/held/${i}`;

describe('shared CRL cases', () => {
  it('has cases', () => expect(file.cases.length).toBeGreaterThan(0));

  it.each(file.cases.map((c) => [c.name, c] as const))('%s', (_, c) => {
    const held: HeldCrl[] = c.crls.map((b64, i) => ({ crl: parseCrl(der(b64)), url: heldUrl(i), source: 'conformance' }));
    const { statuses } = checkRevocation([certificates[c.certificate]!], certificates[c.issuer]!, new Date(file.at), { crls: held });
    const s = statuses[0]!;
    const decided = s.status !== 'UNKNOWN';
    expect({
      status: s.status,
      reason: s.status === 'REVOKED' || s.status === 'ON_HOLD' ? s.reason ?? null : null,
      crl: decided ? held.findIndex((h) => h.url === s.crlUrl) : null,
    }, `${c.about}${decided ? '' : ` (${s.reason})`}`).toEqual(c.expect);
  });
});
