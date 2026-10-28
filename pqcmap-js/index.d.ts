/**
 * Type declarations for @seqr/pqc — the npm port of pqcmap.
 * Hand-authored to mirror the Python public API (typed distribution, like pqcmap's py.typed).
 */

export type Bytes = Uint8Array;

export interface AlgorithmMeta {
  name: string;
  kind: 'kem' | 'sign';
  fips: string;
  nistLevel: number;
  publicKeyBytes: number;
  secretKeyBytes: number;
  outputBytes: number;
}

export class KeyPair {
  readonly publicKey: Bytes;
  readonly secretKey: Bytes;
  constructor(publicKey: Bytes, secretKey: Bytes);
}

export class KeyEncapsulation {
  readonly algorithm: string;
  constructor(algorithm?: string);
  generateKeypair(): KeyPair;
  encapsulate(publicKey: Bytes): { ciphertext: Bytes; sharedSecret: Bytes };
  decapsulate(secretKey: Bytes, ciphertext: Bytes): Bytes;
}

export class Signature {
  readonly algorithm: string;
  constructor(algorithm?: string);
  generateKeypair(): KeyPair;
  sign(message: Bytes, secretKey: Bytes): Bytes;
  verify(message: Bytes, signature: Bytes, publicKey: Bytes): boolean;
}

export class HybridKEM {
  constructor(pqcAlgorithm?: string);
  generateKeypair(): KeyPair;
  encapsulate(publicKey: Bytes): { ciphertext: Bytes; sharedSecret: Bytes };
  decapsulate(secretKey: Bytes, ciphertext: Bytes): Bytes;
}
export function combineSecrets(classicalSecret: Bytes, pqcSecret: Bytes): Bytes;

export class PQCToken {
  static encode(payload: object, secretKey: Bytes, algorithm?: string, headers?: object | null): string;
  static decode(token: string, publicKey: Bytes, opts?: { verifyExp?: boolean; leeway?: number }): Record<string, unknown>;
  static getUnverifiedHeader(token: string): Record<string, unknown>;
}

export const KEMAlgorithm: Readonly<{ ML_KEM_512: string; ML_KEM_768: string; ML_KEM_1024: string }>;
export const SignAlgorithm: Readonly<{ ML_DSA_44: string; ML_DSA_65: string; ML_DSA_87: string; SLH_DSA_SHA2_128F: string }>;
export const Algorithm: Readonly<{ KEM: typeof KEMAlgorithm; Sign: typeof SignAlgorithm; DEFAULT_KEM: string; DEFAULT_SIGN: string }>;
export const DEFAULT_KEM: string;
export const DEFAULT_SIGN: string;
export const ALGORITHM_META: Readonly<Record<string, AlgorithmMeta>>;
export const KEM_ALGORITHMS: readonly string[];
export const SIGN_ALGORITHMS: readonly string[];
export function meta(algorithm: string): AlgorithmMeta;

export interface Violation {
  ruleKey: string;
  severity: string;
  actual: string;
  target: string;
  message: string;
}
export interface ResolvedAlgorithm {
  name: string;
  family: string;
  nistLevel: number | null;
  keySize: number | null;
}
export type PolicySource = CryptoPolicy | object | string;
export class CryptoPolicy {
  readonly name: string;
  readonly rules: object[];
  constructor(body: object);
  static default(): CryptoPolicy;
  static fromBody(body: object): CryptoPolicy;
  static fromFile(path: string): CryptoPolicy;
  evaluate(algorithm: string, opts?: { kind?: 'kem' | 'sign' }): Violation[];
}
export function assertCompliant(algorithm: string, opts?: { kind?: 'kem' | 'sign'; policy?: PolicySource }): void;
export function isCompliant(algorithm: string, opts?: { kind?: 'kem' | 'sign'; policy?: PolicySource }): boolean;
export function violations(algorithm: string, opts?: { kind?: 'kem' | 'sign'; policy?: PolicySource }): Violation[];
export function requiresPqc<F extends (...args: any[]) => any>(
  fn: F,
  opts?: { kind?: 'kem' | 'sign'; policy?: PolicySource; getAlgorithm?: (args: any[]) => string },
): F;
export function loadPolicy(source?: PolicySource): CryptoPolicy;
export function getActivePolicy(): CryptoPolicy;
export function setActivePolicy(policy?: PolicySource | null): CryptoPolicy;
export function familyOf(algorithm: string): string;
export function resolve(algorithm: string): ResolvedAlgorithm;
export const DEFAULT_POLICY_BODY: Readonly<object>;

export namespace compliant {
  class KeyEncapsulation {
    readonly algorithm: string;
    constructor(algorithm?: string, opts?: { policy?: PolicySource });
    generateKeypair(): KeyPair;
    encapsulate(publicKey: Bytes): { ciphertext: Bytes; sharedSecret: Bytes };
    decapsulate(secretKey: Bytes, ciphertext: Bytes): Bytes;
  }
  class Signature {
    readonly algorithm: string;
    constructor(algorithm?: string, opts?: { policy?: PolicySource });
    generateKeypair(): KeyPair;
    sign(message: Bytes, secretKey: Bytes): Bytes;
    verify(message: Bytes, signature: Bytes, publicKey: Bytes): boolean;
  }
}

export class RotationPolicy {
  maxAgeDays: number | null;
  maxUses: number | null;
  constructor(opts?: { maxAgeDays?: number | null; maxUses?: number | null });
  toDict(): { max_age_days: number | null; max_uses: number | null };
  static fromDict(d: object | null): RotationPolicy;
}
export interface KeyMetadata {
  algorithm: string;
  metadata: Record<string, unknown>;
  created_at: string;
  status: string;
  rotated_to: string | null;
  uses: number;
  last_used_at: string | null;
}
export class LocalKeyStore {
  readonly path: string;
  readonly auditPath: string;
  get rotationPolicy(): RotationPolicy;
  constructor(passphrase: string, storePath?: string | null, opts?: { rotationPolicy?: RotationPolicy; audit?: boolean });
  setRotationPolicy(policy: RotationPolicy): void;
  store(algorithm: string, publicKey: Bytes, secretKey: Bytes, metadata?: object | null): string;
  generateAndStore(algorithm: string, metadata?: object | null): string;
  getPublicKey(keyId: string): Bytes;
  getPrivateKey(keyId: string, opts?: { recordUse?: boolean }): Bytes;
  getMetadata(keyId: string): KeyMetadata;
  rotate(keyId: string): string;
  needsRotation(keyId: string, policy?: RotationPolicy | null): boolean;
  rotateIfNeeded(keyId: string, policy?: RotationPolicy | null): string | null;
  listKeys(): Array<{ key_id: string } & KeyMetadata>;
  exportKey(keyId: string, passphrase: string): Bytes;
  importKey(blob: Bytes, passphrase: string): string;
  readAuditLog(): Array<Record<string, unknown>>;
  verifyAuditLog(): boolean;
}

export interface KMSTransportResponse {
  status: number;
  body: Buffer;
}
export type KMSTransport = (method: string, url: string, headers: object, body: Buffer | null) => Promise<KMSTransportResponse>;
export class HostedKMS {
  readonly endpoint: string;
  constructor(opts: { endpoint: string; apiKey: string; timeout?: number; transport?: KMSTransport });
  generateDataKey(masterKeyId: string, opts?: { keyBytes?: number }): Promise<{ plaintext: Bytes; wrapped: Bytes; masterKeyId: string }>;
  decryptDataKey(wrapped: Bytes, opts?: { masterKeyId?: string | null }): Promise<Bytes>;
  encrypt(plaintext: Bytes, opts: { masterKeyId: string }): Promise<Buffer>;
  decrypt(envelope: Bytes): Promise<Buffer>;
  health(): Promise<Record<string, unknown>>;
}

export namespace tls {
  const PQC_HYBRID_GROUP: string;
  class TLSCapabilities {
    opensslVersion: string;
    opensslVersionInfo: number[];
    node: string;
    pqcGroupConfigured: boolean;
    pqcMaybeDefault: boolean;
    configuredGroup: string | null;
    candidateGroups: string[];
    notes: string[];
    get pqcHybridAvailable(): boolean;
    summary(): string;
    asDict(): Record<string, unknown>;
  }
  function capabilities(configuredGroup?: string | null): TLSCapabilities;
  function buildClientOptions(opts?: { verify?: boolean; preferPqc?: boolean }): { options: object; capabilities: TLSCapabilities };
  function pqcHttpsAgent(opts?: { verify?: boolean; preferPqc?: boolean }): import('node:https').Agent & { pqcCapabilities: TLSCapabilities };
  function report(): string;
}

export class PQCError extends Error {}
export class PQCUnavailableError extends PQCError {}
export class UnsupportedAlgorithmError extends PQCError {}
export class KeySizeError extends PQCError {}
export class SignatureVerificationError extends PQCError {}
export class PolicyViolationError extends PQCError {
  algorithm: string;
  violations: Violation[];
}
export class PQCTokenExpiredError extends PQCError {}
export class PQCTokenInvalidError extends PQCError {}
export class PQCTokenSignatureError extends PQCTokenInvalidError {}
export class KMSError extends PQCError {}
export class KMSKeyNotFoundError extends KMSError {}
export class KMSAuthError extends KMSError {}

export function available(): boolean;
export function backend(): string | undefined;
export const version: string;
