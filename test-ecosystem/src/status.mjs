/**
 * The issuer's status lists: a W3C Bitstring Status List v1.0 (purpose `revocation`, section 2.2: at least 131,072
 * entries) for ldp_vc credentials and an IETF Token Status List (draft-ietf-oauth-status-list, one bit per status) for
 * SD-JWT VCs. The lists themselves are built by the reference libraries; this keeps which entries are taken and revoked.
 */
import { randomInt } from 'node:crypto';
import { createCredential, createList } from '@digitalbazaar/vc-bitstring-status-list';
import { StatusList } from '@sd-jwt/jwt-status-list';

const STATUS_LIST_SIZE = 131_072;
/** Token Status List section 7.1: status type INVALID. */
const INVALID = 1;

/**
 * @param {{ bitstring?: { used: number[], revoked: number[] }, token?: { used: number[], revoked: number[] } }} [saved]
 *   what `toJSON()` returned earlier
 */
export function createStatusLists(saved = {}) {
  const lists = Object.fromEntries(['bitstring', 'token'].map((kind) => [kind, { used: new Set(saved[kind]?.used), revoked: new Set(saved[kind]?.revoked) }]));
  return {
    /** A random free entry of the list, so that an index says nothing about when a credential was issued. */
    allocate(kind) {
      const { used } = lists[kind];
      if (used.size >= STATUS_LIST_SIZE) throw new Error(`The ${kind} status list is full`);
      let index;
      do index = randomInt(STATUS_LIST_SIZE); while (used.has(index));
      used.add(index);
      return index;
    },
    revoke(kind, index) {
      if (!lists[kind].used.has(index)) throw new Error(`Entry ${index} of the ${kind} status list belongs to no credential`);
      lists[kind].revoked.add(index);
    },
    isRevoked: (kind, index) => lists[kind].revoked.has(index),
    /** The unsigned BitstringStatusListCredential (`id`, type, credentialSubject with the encoded list). */
    async bitstringCredential(id) {
      const list = await createList({ length: STATUS_LIST_SIZE });
      for (const index of lists.bitstring.revoked) list.setStatus(index, true);
      return createCredential({ id, list, statusPurpose: 'revocation' });
    },
    tokenStatusList() {
      const list = new StatusList(new Array(STATUS_LIST_SIZE).fill(0), 1);
      for (const index of lists.token.revoked) list.setStatus(index, INVALID);
      return list;
    },
    toJSON: () => Object.fromEntries(Object.entries(lists).map(([kind, { used, revoked }]) => [kind, { used: [...used], revoked: [...revoked] }])),
  };
}
