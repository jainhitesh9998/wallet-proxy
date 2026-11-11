/**
 * Builds an ISO 18013-5 mDL IssuerSigned member by member, signed with the test PKI's Document Signer, so a test can
 * break exactly one rule of the standard.
 */
import type { Jwk } from '@vctrust/trust-client';
import { bytes, cbor, digest } from '@vctrust/trust-client/primitives';
import { jwkToCoseKey, sigStructure } from '../src/index.js';
import { der, sign } from './support.js';

const { Tagged } = cbor;
export const NS = 'org.iso.18013.5.1';
export const MDL = 'org.iso.18013.5.1.mDL';
export const STATUS_URI = 'https://issuer.example/status/mdl';
export const tdate = (d: Date) => new Tagged(0, d.toISOString().replace(/\.\d+Z$/, 'Z'));

export function coseSign1(keyName: string, payload: Uint8Array, protectedHeader: Map<number, unknown>, chain: Uint8Array | Uint8Array[] = der(keyName)): unknown[] {
  const p = cbor.encode(protectedHeader);
  return [p, new Map([[33, chain]]), payload, sign(keyName, sigStructure(p, payload))];
}

export interface Parts {
  /** IssuerSignedItems as maps; wrapped in tag 24 unless {@code rawItems} */
  items?: Array<Map<string, unknown>>;
  rawItems?: boolean;
  mso?: (mso: Map<string, unknown>) => void;
  /** how the MSO becomes the COSE payload (default: tag 24 over its encoding) */
  payload?: (mso: Map<string, unknown>) => Uint8Array;
  signer?: string;
  wrap?: (issuerSigned: Map<string, unknown>) => unknown;
  status?: number;
}

export const item = (digestID: number, name: string, value: unknown, random = new Uint8Array(16).fill(digestID + 1)) =>
  new Map<string, unknown>([['digestID', digestID], ['random', random], ['elementIdentifier', name], ['elementValue', value]]);

/** An mDL IssuerSigned as OpenID4VCI issues it, signed by the test Document Signer (issued by the test IACA). */
export function buildMdoc(holder: { publicJwk: Jwk }, parts: Parts = {}): string {
  const items = parts.items ?? [item(0, 'given_name', 'Ada'), item(1, 'family_name', 'Lovelace')];
  const encoded = items.map((i) => new Tagged(24, cbor.encode(i)));
  const mso = new Map<string, unknown>([['version', '1.0'], ['digestAlgorithm', 'SHA-256'],
    ['valueDigests', new Map([[NS, new Map(items.map((i, n) => [i.get('digestID') as number, digest('SHA-256', cbor.encode(encoded[n]!))]))]])],
    ['deviceKeyInfo', new Map([['deviceKey', jwkToCoseKey(holder.publicJwk)]])], ['docType', MDL],
    ['validityInfo', new Map([['signed', tdate(new Date(Date.now() - 120_000))], ['validFrom', tdate(new Date(Date.now() - 60_000))], ['validUntil', tdate(new Date(Date.now() + 86_400_000))]])],
    ...(parts.status === undefined ? [] : [['status', new Map([['status_list', new Map<string, unknown>([['idx', parts.status], ['uri', STATUS_URI]])]])] as [string, unknown]])]);
  parts.mso?.(mso);
  const payload = (parts.payload ?? ((m) => cbor.encode(new Tagged(24, cbor.encode(m)))))(mso);
  const issuerSigned = new Map<string, unknown>([['nameSpaces', new Map([[NS, parts.rawItems ? items : encoded]])],
    ['issuerAuth', coseSign1(parts.signer ?? 'ds', payload, new Map([[1, -7]]))]]);
  return bytes.base64UrlEncode(cbor.encode(parts.wrap ? parts.wrap(issuerSigned) : issuerSigned));
}
