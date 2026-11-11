/** Presentation helpers: OpenID4VCI display metadata, claim display names, and value formatting. */
import type { StoredCredential } from '@vctrust/wallet-core';

type Display = { name?: string; locale?: string; description?: string; background_color?: string; text_color?: string;
  logo?: { uri?: string; url?: string; alt_text?: string }; background_image?: { uri?: string } };

export function pickLocale<T extends { locale?: string }>(list: T[] | undefined): T | undefined {
  if (!Array.isArray(list) || list.length === 0) return undefined;
  return list.find((d) => d.locale?.toLowerCase().startsWith('en')) ?? list.find((d) => !d.locale) ?? list[0];
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export function credentialView(c: StoredCredential) {
  const d = (c.display ?? {}) as Display;
  const entityName = c.report?.trust?.entity?.display?.[0]?.name;
  // The display metadata is the issuer's own: its logo is shown (and fetched) only when the issuer is trusted.
  const trusted = c.report?.trust?.decision === 'TRUSTED';
  return {
    title: d.name ?? c.report?.credentialType ?? c.configurationId,
    issuer: entityName ?? hostOf(c.credentialIssuer),
    description: d.description,
    background: d.background_color,
    textColor: d.text_color,
    logo: trusted ? d.logo?.uri ?? d.logo?.url : undefined,
    format: c.format,
    type: c.report?.credentialType,
  };
}

export function issuerView(display: Record<string, unknown> | undefined, fallback: string) {
  const d = (display ?? {}) as Display;
  return { name: d.name ?? hostOf(fallback), logo: d.logo?.uri ?? d.logo?.url };
}

const key = (path: (string | number | null)[]) => path.map((p) => (p === null ? '*' : String(p))).join('\u0001');

/** Maps claim paths to display names from OpenID4VCI 1.0 claims metadata (array) or the older nested-object form. */
export function claimNames(meta: unknown): Map<string, string> {
  const out = new Map<string, string>();
  if (Array.isArray(meta)) {
    for (const m of meta as { path?: (string | number | null)[]; display?: { name?: string; locale?: string }[] }[]) {
      const name = pickLocale(m.display)?.name;
      if (Array.isArray(m.path) && name) out.set(key(m.path), name);
    }
  } else if (meta && typeof meta === 'object') {
    const walk = (node: Record<string, unknown>, path: string[]) => {
      for (const [k, v] of Object.entries(node)) {
        if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
        const name = pickLocale((v as { display?: { name?: string; locale?: string }[] }).display)?.name;
        if (name) out.set(key([...path, k]), name);
        walk(v as Record<string, unknown>, [...path, k]);
      }
    };
    walk(meta as Record<string, unknown>, []);
  }
  return out;
}

export function humanize(id: string): string {
  return id.replace(/[_-]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase());
}

/** A `{ $bytes }` value (mdoc bstr) or a data: URI that holds a JPEG / PNG, as a data URI; otherwise undefined. */
export function imageUri(v: unknown): string | undefined {
  if (typeof v === 'string' && /^data:image\/(jpeg|jpg|png);base64,/i.test(v)) return v;
  const b64 = v && typeof v === 'object' && typeof (v as { $bytes?: unknown }).$bytes === 'string' ? (v as { $bytes: string }).$bytes : undefined;
  if (!b64) return undefined;
  if (b64.startsWith('/9j/')) return `data:image/jpeg;base64,${b64}`;
  if (b64.startsWith('iVBORw0KGgo')) return `data:image/png;base64,${b64}`;
  return undefined;
}

export function isBytes(v: unknown): v is { $bytes: string; length?: number } {
  return !!v && typeof v === 'object' && typeof (v as { $bytes?: unknown }).$bytes === 'string';
}

/** Claim groups to render: mdoc by namespace, others as one group with the path prefix their metadata uses. */
export function claimGroups(c: StoredCredential): { title?: string; prefix: string[]; altPrefix?: string[]; values: Record<string, unknown> }[] {
  const claims = (c.report?.claims ?? {}) as Record<string, unknown>;
  if (c.format === 'mso_mdoc') {
    return Object.entries(claims).map(([ns, v]) => ({ title: ns, prefix: [ns], values: (v ?? {}) as Record<string, unknown> }));
  }
  if (c.format === 'ldp_vc') return [{ prefix: ['credentialSubject'], altPrefix: [], values: claims }];
  const hidden = new Set(['iss', 'iat', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status', '_sd_alg', 'sub']);
  return [{ prefix: [], values: Object.fromEntries(Object.entries(claims).filter(([k]) => !hidden.has(k))) }];
}

export function nameFor(names: Map<string, string>, path: (string | number)[], alt?: (string | number)[]): string | undefined {
  return names.get(key(path)) ?? (alt ? names.get(key(alt)) : undefined)
    ?? names.get(key(path.map((p) => (typeof p === 'number' ? null : p)))) ?? undefined;
}

export function shortDate(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}
