/**
 * OpenID Federation 1.0 metadata policy (§6.1) operators, mirroring the service's MetadataPolicy: the registry
 * curates a registered issuer's live metadata (e.g. pins its authorization servers). Clients that fetch issuer
 * metadata directly apply the policy carried in the trust snapshot, so they see what the service's proxy would serve.
 */
const ORDER = ['value', 'add', 'default', 'one_of', 'subset_of', 'superset_of', 'essential'] as const;

export class MetadataPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MetadataPolicyError';
  }
}

const asList = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? [...v] : [v]);
const key = (v: unknown) => JSON.stringify(v);
const includes = (list: unknown[], v: unknown) => list.some((x) => key(x) === key(v));

/** Applies {@code policy} (parameter → operators) to {@code metadata}; throws MetadataPolicyError on a violation. */
export function applyMetadataPolicy(metadata: Record<string, unknown>, policy: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = { ...metadata };
  if (!policy) return out;
  for (const [param, ops] of Object.entries(policy)) {
    if (!ops || typeof ops !== 'object' || Array.isArray(ops)) throw new MetadataPolicyError(`Policy for '${param}' must be an object`);
    const o = ops as Record<string, unknown>;
    for (const op of ORDER) {
      if (!(op in o)) continue;
      const arg = o[op];
      const current = out[param];
      switch (op) {
        case 'value':
          if (arg === null) delete out[param];
          else out[param] = arg;
          break;
        case 'add': {
          const merged = asList(current);
          for (const a of asList(arg)) if (!includes(merged, a)) merged.push(a);
          out[param] = merged;
          break;
        }
        case 'default':
          if (current === undefined || current === null) out[param] = arg;
          break;
        case 'one_of':
          if (current !== undefined && current !== null && !includes(asList(arg), current)) {
            throw new MetadataPolicyError(`'${param}' value ${key(current)} is not one of ${key(arg)}`);
          }
          break;
        case 'subset_of':
          if (current !== undefined && current !== null) {
            const kept = asList(current).filter((c) => includes(asList(arg), c));
            if (kept.length === 0) delete out[param];
            else out[param] = kept;
          }
          break;
        case 'superset_of':
          if (current !== undefined && current !== null && !asList(arg).every((a) => includes(asList(current), a))) {
            throw new MetadataPolicyError(`'${param}' must contain all of ${key(arg)}`);
          }
          break;
        case 'essential':
          if (arg === true && (out[param] === undefined || out[param] === null)) throw new MetadataPolicyError(`Essential parameter '${param}' is missing`);
          break;
      }
    }
  }
  return out;
}
