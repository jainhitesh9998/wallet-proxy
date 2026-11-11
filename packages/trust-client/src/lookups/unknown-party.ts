/**
 * Opt-in ({@code lookups.unknownParties}): asks the service's registries about identifiers absent from the
 * snapshot. Only identifiers are sent — never certificates or credential contents — and the answer is a signed
 * registry entry the device evaluates itself.
 */
import { identifierKey } from '../evaluation/local.js';
import type { EntityView } from '../types.js';
import type { LookupContext } from './context.js';

const ON_DEMAND_TTL_MS = 10 * 60_000;

export class UnknownPartyLookup {
  private readonly answers = new Map<string, { entities: EntityView[]; until: number }>();

  constructor(private readonly ctx: LookupContext) {}

  async find(identifiers: Array<{ type?: string; value: string }>):
      Promise<{ identifier: { type?: string; value: string }; entities: EntityView[] } | undefined> {
    const { ctx } = this;
    if (!ctx.lookups.unknownParties || !ctx.transport) return undefined;
    const seen = new Set<string>();
    for (const id of identifiers) {
      const key = `${id.type ?? ''}|${id.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hit = this.answers.get(key);
      if (hit && hit.until > ctx.now()) {
        if (hit.entities.length > 0) return { identifier: id, entities: hit.entities };
        continue;
      }
      try {
        const r = await ctx.transport.request<string>('GET', `/api/v1/entities/lookup?identifier=${encodeURIComponent(id.value)}`
          + `${id.type ? `&type=${id.type}` : ''}&onDemand=true`, { accept: 'application/jwt' });
        // The signed answer does not name the identifier it answers: keep only entries that carry it, so a replayed
        // answer about another party cannot stand in for this one.
        const entities = (await ctx.snapshots.verifySigned<EntityView[]>(String(r.body).trim(), 'trust-registry+jwt'))
          .filter((e) => namesIdentifier(e, id));
        this.answers.set(key, { entities, until: ctx.now() + ON_DEMAND_TTL_MS });
        if (entities.length > 0) return { identifier: id, entities };
      } catch (e) {
        ctx.logger?.warn?.(`on-demand lookup of ${id.value} failed: ${(e as Error).message}`);
      }
    }
    return undefined;
  }
}

/** Whether a registry entry carries the identifier: the given type, or the types the service reads an untyped one as. */
function namesIdentifier(e: EntityView, id: { type?: string; value: string }): boolean {
  const types = id.type ? [id.type] : id.value.startsWith('did:') ? ['DID']
    : id.value.startsWith('https://') || id.value.startsWith('http://') ? ['URL', 'FEDERATION_ENTITY'] : ['CLIENT_ID', 'OTHER'];
  return e.identifiers.some((i) => types.includes(i.type) && identifierKey(i.type, i.value) === identifierKey(i.type, id.value));
}
