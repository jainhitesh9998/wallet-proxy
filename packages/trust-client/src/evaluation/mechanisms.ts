/**
 * Trust mechanisms: rules an operator writes for a class of questions, saying which proof of key is accepted for them,
 * which trust anchors count, what the certificate must look like and whether its revocation status must be known. They
 * travel in the snapshot (the {@code mechanisms} claim of a format 5 snapshot) and are applied here exactly as the
 * service applies them (TrustMechanisms.java, TrustEvaluator.java); the second pair of evaluation vectors holds the two
 * to that.
 *
 * Mechanisms are tried in the order they are listed, and the first whose {@code for} matches a question governs it. A
 * mechanism only tightens: everything built in keeps applying, and it adds requirements and chooses which anchors count.
 *
 * They are read strictly. A member or a value this client does not know means it cannot apply the operator's rules as
 * the service does, so the snapshot that carries it is refused ("update the client"), and an app's own mechanisms
 * (the client option {@code mechanisms}, in the same shape) are refused at construction.
 */
import { KEY_USAGE_BITS, type CertificateRequirements, type KeyUsageBit } from '../x509/requirements.js';

/** The roles a mechanism can govern, as a query names them. */
export type MechanismRole = 'issuer' | 'verifier' | 'wallet_provider' | 'status_list_provider';
/** An {@code x5c} certificate chain, a DID key ({@code kid} a DID URL), a bare JWK. */
export type KeyKind = 'x5c' | 'did' | 'jwk';

/** One trust mechanism, in the camelCase form of the snapshot claim. Members that are absent require nothing. */
export interface TrustMechanism {
  /** reported in the evidence of every decision it governs ({@code evidence.mechanism}) */
  id: string;
  /** the questions it governs; every member given must match */
  for: {
    role: MechanismRole;
    /** credential formats in their canonical spelling; absent: any */
    formats?: string[];
    /** doctypes, vcts or VC types: exact, or a prefix followed by {@code *}; absent: any */
    types?: string[];
  };
  /** the proofs of key accepted; absent: all */
  keys?: KeyKind[];
  x509?: {
    /** the trust domain whose anchors count, instead of the default one */
    domain?: string;
    /** requirements on the chain, on top of the built-in profile */
    profile?: CertificateRequirements;
    /** an unknown revocation status is an error, whatever the client profile says */
    revocation?: 'required';
  };
  did?: {
    /** the DID methods accepted for a DID key */
    methods: string[];
  };
}

const ROLES: readonly string[] = ['issuer', 'verifier', 'wallet_provider', 'status_list_provider'];
const KEY_KINDS: readonly string[] = ['x5c', 'did', 'jwk'];
/** Canonical spellings only: the service writes vc+sd-jwt as dc+sd-jwt. */
const FORMATS: readonly string[] = ['mso_mdoc', 'dc+sd-jwt', 'ldp_vc', 'jwt_vc_json', 'jwt_vc_json-ld'];
/** The same patterns as the service's (TrustMechanisms.java), all in ASCII so that both read them alike. */
const ID = /^[A-Za-z0-9._:@~-]{1,128}$/;
const DOMAIN = /^[\x21-\x40\x5b-\x7e]{1,200}$/;
const TYPE = /^[\x21-\x29\x2b-\x7e]{1,512}\*?$/;
const OID = /^[0-2](\.(0|[1-9][0-9]{0,14}))+$/;
const DID_METHOD = /^[a-z0-9]{1,64}$/;
const MAX_DAYS = 36_500;
const MAX_INTERMEDIATES = 9;

/** A mechanism (or a list of them) this client does not understand exactly. */
export class MechanismError extends Error {}

type Tree = Record<string, unknown>;

/**
 * Reads mechanisms in the form of the snapshot claim. Anything else, or anything more, is a {@link MechanismError} that
 * names the mechanism and the member: a rule that is half applied is not the operator's rule.
 */
export function parseMechanisms(value: unknown): TrustMechanism[] {
  if (!Array.isArray(value)) throw new MechanismError('mechanisms must be a list');
  const seen = new Map<string, number>();
  return deepFreeze(value.map((v, i) => {
    const m = new Reader(`mechanisms[${i}]`).mechanism(v);
    const first = seen.get(m.id);
    if (first !== undefined) throw new MechanismError(`Trust mechanism mechanisms[${i}] ('${m.id}'): the id is already used by mechanisms[${first}]`);
    seen.set(m.id, i);
    return m;
  }));
}

/** A type pattern: exact, or a prefix followed by '*'. Compared as strings, as the service compares them. */
function typeMatches(pattern: string, type: string): boolean {
  return pattern.endsWith('*') ? type.startsWith(pattern.slice(0, -1)) : type === pattern;
}

/**
 * The mechanism that governs a question: the first whose {@code for} matches its role, its format (canonical) and any of
 * the types it asserts, so that a restrictive mechanism cannot be dodged by listing the types in another order. A
 * question that asserts no type matches only a mechanism without {@code types}, one without a format only a mechanism
 * without {@code formats}. Undefined: none governs, and the question is decided as without mechanisms.
 */
export function selectMechanism(mechanisms: readonly TrustMechanism[], role: string | undefined, format: string | undefined,
                                types: readonly string[]): TrustMechanism | undefined {
  if (!role) return undefined;
  return mechanisms.find((m) => m.for.role === role
    && (!m.for.formats || (format !== undefined && m.for.formats.includes(format)))
    && (!m.for.types || types.some((t) => m.for.types!.some((p) => typeMatches(p, t)))));
}

function deepFreeze<T>(o: T): T {
  if (o && typeof o === 'object') {
    for (const v of Object.values(o)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

class Reader {
  constructor(private where: string) {}

  mechanism(value: unknown): TrustMechanism {
    if (isTree(value) && typeof value.id === 'string' && ID.test(value.id)) this.where = `${this.where} ('${value.id}')`;
    const m = this.tree(value, '', ['id', 'for', 'keys', 'x509', 'did']);
    const id = this.string(this.required(m, 'id', ''), 'id');
    if (!ID.test(id)) throw this.error('id', 'must be 1 to 128 letters, digits or . _ : @ ~ -');
    const q = this.tree(this.required(m, 'for', ''), 'for', ['role', 'formats', 'types']);
    const role = this.string(this.required(q, 'role', 'for.'), 'for.role');
    if (!ROLES.includes(role)) throw this.error('for.role', `'${role}' is not one of ${ROLES.join(', ')}`);
    const out: TrustMechanism = { id, for: { role: role as MechanismRole } };
    if (has(q, 'formats')) out.for.formats = this.strings(q.formats, 'for.formats', (f) => FORMATS.includes(f), `a credential format in its canonical spelling: ${FORMATS.join(', ')}`);
    if (has(q, 'types')) out.for.types = this.strings(q.types, 'for.types', (t) => TYPE.test(t), "a type, or a prefix followed by '*' (printable ASCII without spaces)");
    if (has(m, 'keys')) out.keys = this.strings(m.keys, 'keys', (k) => KEY_KINDS.includes(k), `one of ${KEY_KINDS.join(', ')}`) as KeyKind[];
    if (has(m, 'x509')) {
      if (out.keys && !out.keys.includes('x5c')) throw this.error('x509', 'is given, but keys does not accept x5c: it would never apply');
      out.x509 = this.x509(m.x509);
    }
    if (has(m, 'did')) {
      if (out.keys && !out.keys.includes('did')) throw this.error('did', 'is given, but keys does not accept did: it would never apply');
      const d = this.tree(m.did, 'did', ['methods']);
      out.did = { methods: this.strings(this.required(d, 'methods', 'did.'), 'did.methods', (x) => DID_METHOD.test(x), 'a DID method name (lower-case letters and digits)') };
    }
    return out;
  }

  private x509(value: unknown): NonNullable<TrustMechanism['x509']> {
    const x = this.nonEmpty(this.tree(value, 'x509', ['domain', 'profile', 'revocation']), 'x509');
    const out: NonNullable<TrustMechanism['x509']> = {};
    if (has(x, 'domain')) {
      const domain = this.string(x.domain, 'x509.domain');
      if (!DOMAIN.test(domain)) throw this.error('x509.domain', 'must be a trust domain as anchors name it: lower-case printable ASCII without spaces');
      out.domain = domain;
    }
    if (has(x, 'profile')) out.profile = this.profile(x.profile);
    if (has(x, 'revocation')) {
      if (x.revocation !== 'required') throw this.error('x509.revocation', "must be 'required', or absent to let the client profile decide");
      out.revocation = 'required';
    }
    return out;
  }

  private profile(value: unknown): CertificateRequirements {
    const p = this.nonEmpty(this.tree(value, 'x509.profile', ['leaf', 'maxIntermediates']), 'x509.profile');
    const out: CertificateRequirements = {};
    if (has(p, 'leaf')) {
      const at = 'x509.profile.leaf';
      const l = this.nonEmpty(this.tree(p.leaf, at, ['ca', 'keyUsage', 'extendedKeyUsage', 'sameCountryAsAnchor', 'maxValidityDays', 'crlDistributionPoint']), at);
      const leaf: NonNullable<CertificateRequirements['leaf']> = {};
      if (has(l, 'ca')) {
        if (l.ca !== false) throw this.error(`${at}.ca`, 'must be false: a mechanism can require that the signing certificate is not a CA');
        leaf.ca = false;
      }
      if (has(l, 'keyUsage')) {
        leaf.keyUsage = this.strings(l.keyUsage, `${at}.keyUsage`, (k) => (KEY_USAGE_BITS as readonly string[]).includes(k),
          `one of ${KEY_USAGE_BITS.join(', ')}`) as KeyUsageBit[];
      }
      if (has(l, 'extendedKeyUsage')) leaf.extendedKeyUsage = this.strings(l.extendedKeyUsage, `${at}.extendedKeyUsage`, (o) => OID.test(o), 'a dotted OID');
      if (has(l, 'sameCountryAsAnchor')) {
        if (l.sameCountryAsAnchor !== true) throw this.error(`${at}.sameCountryAsAnchor`, 'must be true, or absent');
        leaf.sameCountryAsAnchor = true;
      }
      if (has(l, 'maxValidityDays')) leaf.maxValidityDays = this.integer(l.maxValidityDays, `${at}.maxValidityDays`, 1, MAX_DAYS);
      if (has(l, 'crlDistributionPoint')) {
        if (l.crlDistributionPoint !== true) throw this.error(`${at}.crlDistributionPoint`, 'must be true, or absent');
        leaf.crlDistributionPoint = true;
      }
      out.leaf = leaf;
    }
    if (has(p, 'maxIntermediates')) out.maxIntermediates = this.integer(p.maxIntermediates, 'x509.profile.maxIntermediates', 0, MAX_INTERMEDIATES);
    return out;
  }

  private required(t: Tree, key: string, prefix: string): unknown {
    if (!has(t, key) || t[key] === null || t[key] === undefined) throw this.error(prefix + key, 'is required');
    return t[key];
  }

  private tree(value: unknown, path: string, members: string[]): Tree {
    if (!isTree(value)) throw this.error(path || 'the entry', 'must be an object');
    for (const k of Object.keys(value)) {
      if (!members.includes(k)) {
        throw this.error(path ? `${path}.${k}` : k, `is not a member this client knows (${path ? `${path}: ` : ''}${[...members].sort().join(', ')})`);
      }
    }
    return value;
  }

  private nonEmpty(t: Tree, path: string): Tree {
    if (Object.keys(t).length === 0) throw this.error(path, 'is empty');
    return t;
  }

  private string(value: unknown, path: string): string {
    if (typeof value !== 'string') throw this.error(path, 'must be a string');
    return value;
  }

  /** A non-empty list of distinct strings, each one {@code valid}. */
  private strings(value: unknown, path: string, valid: (s: string) => boolean, what: string): string[] {
    if (!Array.isArray(value)) throw this.error(path, 'must be a list');
    if (value.length === 0) throw this.error(path, 'is empty');
    const out: string[] = [];
    for (const v of value) {
      const s = this.string(v, path);
      if (!valid(s)) throw this.error(path, `'${s.length <= 80 ? s : `${s.slice(0, 80)}…`}' is not ${what}`);
      if (out.includes(s)) throw this.error(path, `lists '${s}' twice`);
      out.push(s);
    }
    return out;
  }

  private integer(value: unknown, path: string, min: number, max: number): number {
    if (typeof value !== 'number' || !Number.isInteger(value)) throw this.error(path, 'must be a whole number');
    if (value < min || value > max) throw this.error(path, `must be from ${min} to ${max}`);
    return value;
  }

  private error(path: string, problem: string): MechanismError {
    return new MechanismError(`Trust mechanism ${this.where}: ${path} ${problem}`);
  }
}

/** An own member: never one an object inherits. */
function has(t: Tree, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(t, key);
}

function isTree(v: unknown): v is Tree {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
