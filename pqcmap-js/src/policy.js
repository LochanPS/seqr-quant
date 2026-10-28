/**
 * Crypto-policy enforcement for application code — port of Python `pqcmap.policy`.
 *
 * The SDK's job in the SeQr lifecycle: the scanner *measures* against a policy, the
 * migration engine *converges* to it, and pqcmap **enforces** it in code so an app can't
 * silently fall back to quantum-vulnerable crypto. The policy shape is the SeQr platform
 * spine's `{ rules: [...] }` body — a spine policy body loads here as-is. Rule vocabulary:
 *
 *   family_in      — the algorithm's family must be in `allowed`
 *   family_not_in  — the algorithm's family must not be in `forbidden`
 *   min_key_size   — for a classical `family`, key size must be >= `min`
 *   min_nist_level — the algorithm's NIST security level must be >= `min`  (code-layer add)
 *
 * Infra `slot` (tls:kex / tls:cert) maps to a code `kind` (kem / sign); rule types that
 * don't describe a single algorithm are ignored.
 */
import fs from 'node:fs';

import { ALGORITHM_META } from './algorithms.js';
import { PolicyViolationError } from './errors.js';

// --- algorithm resolution ---------------------------------------------------

/** @type {[string, string][]} classical families recognised for guarding arbitrary names. */
const CLASSICAL_FAMILIES = [
  ['ML-KEM', 'ML-KEM'],
  ['ML-DSA', 'ML-DSA'],
  ['SLH-DSA', 'SLH-DSA'],
  ['RSA', 'RSA'],
  ['ECDSA', 'ECDSA'],
  ['ED25519', 'EdDSA'],
  ['ED448', 'EdDSA'],
  ['ECDH', 'ECDH'],
  ['X25519', 'ECDH'],
  ['X448', 'ECDH'],
  ['DSA', 'DSA'],
  ['DH', 'DH'],
];

function parseKeySize(algorithm) {
  const m = /(\d{3,5})/.exec(algorithm || '');
  return m ? parseInt(m[1], 10) : null;
}

/** Best-effort crypto family for `algorithm` (`"RSA"`, `"ML-KEM"`, …), or `"unknown"`. */
export function familyOf(algorithm) {
  const name = (algorithm || '').toUpperCase();
  for (const [needle, fam] of CLASSICAL_FAMILIES) {
    if (name.startsWith(needle) || name.includes(needle)) return fam;
  }
  return 'unknown';
}

/** Resolve an algorithm name to `{ name, family, nistLevel, keySize }`. */
export function resolve(algorithm) {
  const m = ALGORITHM_META[algorithm];
  if (m) return { name: m.name, family: familyOf(m.name), nistLevel: m.nistLevel, keySize: null };
  return { name: algorithm, family: familyOf(algorithm), nistLevel: null, keySize: parseKeySize(algorithm) };
}

// --- policy model -----------------------------------------------------------

/** Code-layer baseline: no quantum-vulnerable families; PQC at NIST Level 3+. */
export const DEFAULT_POLICY_BODY = Object.freeze({
  name: 'pqcmap baseline (PCI DSS + SEBI CSCRF intent)',
  version: '1',
  rules: [
    {
      key: 'no_quantum_vulnerable_family',
      type: 'family_not_in',
      forbidden: ['RSA', 'ECDSA', 'EdDSA', 'ECDH', 'DSA', 'DH'],
      severity: 'immediate',
      target: 'ML-KEM (KEM) / ML-DSA (signatures)',
    },
    {
      key: 'min_nist_level_3',
      type: 'min_nist_level',
      min: 3,
      severity: 'urgent',
      target: 'NIST Level 3+ (ML-KEM-768 / ML-DSA-65)',
    },
  ],
});

const SLOT_TO_KIND = { 'tls:kex': 'kem', 'tls:cert': 'sign' };
const ALGORITHM_RULE_TYPES = new Set(['family_in', 'family_not_in', 'min_key_size', 'min_nist_level']);
const SEVERITY_ORDER = { immediate: 0, urgent: 1, planned: 2 };

function ruleKind(rule) {
  if (rule.kind) return rule.kind;
  return SLOT_TO_KIND[rule.slot] ?? null;
}

export class CryptoPolicy {
  /** @param {object} body a spine `{ rules: [...] }` policy body. */
  constructor(body) {
    if (!body || typeof body !== 'object' || !Array.isArray(body.rules)) {
      throw new Error("policy body must be an object with a 'rules' array");
    }
    this.body = body;
    this.name = body.name ?? 'custom policy';
    this.rules = [...body.rules];
  }

  static default() {
    return new CryptoPolicy(DEFAULT_POLICY_BODY);
  }
  static fromBody(body) {
    return new CryptoPolicy(body);
  }
  static fromFile(path) {
    return new CryptoPolicy(JSON.parse(fs.readFileSync(path, 'utf-8')));
  }

  /**
   * Every violation `algorithm` triggers (empty == compliant), most-severe first.
   * @param {string} algorithm
   * @param {{ kind?: 'kem'|'sign' }} [opts]
   * @returns {Array<{ ruleKey: string, severity: string, actual: string, target: string, message: string }>}
   */
  evaluate(algorithm, { kind } = {}) {
    const r = resolve(algorithm);
    const found = [];
    for (const rule of this.rules) {
      if (!ALGORITHM_RULE_TYPES.has(rule.type)) continue;
      const rkind = ruleKind(rule);
      if (rkind != null && kind != null && rkind !== kind) continue;
      const v = this._checkRule(rule, r);
      if (v) found.push(v);
    }
    found.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));
    return found;
  }

  _checkRule(rule, r) {
    const target = rule.target ?? '';
    const key = rule.key ?? rule.type;
    const sev = rule.severity ?? 'planned';

    if (rule.type === 'family_not_in' && (rule.forbidden ?? []).includes(r.family)) {
      return { ruleKey: key, severity: sev, actual: `${r.name} (${r.family})`, target,
        message: `${r.name} is a ${r.family} algorithm, which policy '${this.name}' forbids (${key}). Use ${target}.` };
    }
    if (rule.type === 'family_in' && !(rule.allowed ?? []).includes(r.family)) {
      return { ruleKey: key, severity: sev, actual: `${r.name} (${r.family})`, target,
        message: `${r.name} is a ${r.family} algorithm; policy '${this.name}' allows only [${(rule.allowed ?? []).join(', ')}] here (${key}). Use ${target}.` };
    }
    if (rule.type === 'min_nist_level' && r.nistLevel != null && r.nistLevel < Number(rule.min)) {
      return { ruleKey: key, severity: sev, actual: `${r.name} (NIST Level ${r.nistLevel})`, target,
        message: `${r.name} is NIST Level ${r.nistLevel}; policy '${this.name}' requires Level ${rule.min}+ (${key}). Use ${target}.` };
    }
    if (rule.type === 'min_key_size' && r.family === rule.family && r.keySize != null && r.keySize < Number(rule.min)) {
      return { ruleKey: key, severity: sev, actual: `${r.name} (${r.keySize}-bit)`, target,
        message: `${r.name} is ${r.keySize}-bit; policy '${this.name}' requires ${rule.family}-${rule.min}+ (${key}). Use ${target}.` };
    }
    return null;
  }
}

// --- active policy (module-global) ------------------------------------------

let activePolicy = null;

/**
 * Resolve a policy from an explicit source, the `PQCMAP_POLICY` env var, or the default.
 * Precedence: explicit `source` (a CryptoPolicy, a body object, or a file path) > env > default.
 * @param {CryptoPolicy|object|string} [source]
 * @returns {CryptoPolicy}
 */
export function loadPolicy(source) {
  if (source instanceof CryptoPolicy) return source;
  if (source && typeof source === 'object') return CryptoPolicy.fromBody(source);
  if (typeof source === 'string') return CryptoPolicy.fromFile(source);
  const env = process.env.PQCMAP_POLICY;
  if (env) return CryptoPolicy.fromFile(env);
  return CryptoPolicy.default();
}

/** The process-wide active policy (lazy-loaded). */
export function getActivePolicy() {
  if (activePolicy === null) activePolicy = loadPolicy();
  return activePolicy;
}

/** Install the process-wide active policy; returns it. `null` resets to default. */
export function setActivePolicy(policy) {
  activePolicy = loadPolicy(policy ?? undefined);
  return activePolicy;
}

function coerce(policy) {
  return policy == null ? getActivePolicy() : loadPolicy(policy);
}

// --- public enforcement API -------------------------------------------------

/** True iff `algorithm` satisfies the policy (non-throwing). */
export function isCompliant(algorithm, { kind, policy } = {}) {
  return coerce(policy).evaluate(algorithm, { kind }).length === 0;
}

/** Every violation `algorithm` triggers under the policy (empty == ok). */
export function violations(algorithm, { kind, policy } = {}) {
  return coerce(policy).evaluate(algorithm, { kind });
}

/**
 * Throw {@link PolicyViolationError} if `algorithm` is below policy; else return.
 * @param {string} algorithm
 * @param {{ kind?: 'kem'|'sign', policy?: CryptoPolicy|object|string }} [opts]
 */
export function assertCompliant(algorithm, { kind, policy } = {}) {
  const vs = coerce(policy).evaluate(algorithm, { kind });
  if (vs.length) throw new PolicyViolationError(vs[0].message, { algorithm, violations: vs });
}

/**
 * Guard a key-minting / signing function so a below-policy algorithm can't be used.
 * JavaScript has no parameter-name introspection, so the algorithm is read from the
 * call's first argument by default; pass `getAlgorithm` to read it from elsewhere.
 *
 *   const newSessionKey = requiresPqc((alg = 'ML-KEM-768') => …, { kind: 'kem' });
 *   const mint = requiresPqc((opts) => …, { kind: 'sign', getAlgorithm: (a) => a[0].alg });
 *
 * @template {(...args: any[]) => any} F
 * @param {F} fn
 * @param {{ kind?: 'kem'|'sign', policy?: any, getAlgorithm?: (args: any[]) => string }} [opts]
 * @returns {F}
 */
export function requiresPqc(fn, { kind, policy, getAlgorithm } = {}) {
  const read = getAlgorithm ?? ((args) => args[0]);
  const guarded = function (...args) {
    assertCompliant(read(args), { kind, policy });
    return fn.apply(this, args);
  };
  return /** @type {F} */ (guarded);
}
