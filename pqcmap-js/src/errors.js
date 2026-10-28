/**
 * Error hierarchy — mirrors pqcmap's Python `pqcmap.core.exceptions`.
 *
 * Every error derives from {@link PQCError}, so one `catch (e) { if (e instanceof PQCError) … }`
 * catches the whole family. The names match the Python SDK one-for-one.
 */

/** Base class for every pqcmap error. */
export class PQCError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

/** No usable PQC backend (should never happen — the noble backend is a hard dependency). */
export class PQCUnavailableError extends PQCError {}

/** An algorithm name is unknown or not valid for the requested operation. */
export class UnsupportedAlgorithmError extends PQCError {}

/** A key / ciphertext / signature has the wrong length for its algorithm. */
export class KeySizeError extends PQCError {}

/** A signature failed to verify (used where a throw is more useful than a boolean). */
export class SignatureVerificationError extends PQCError {}

/**
 * An algorithm is below the active crypto policy. Carries the offending `algorithm` and
 * the ranked `violations` list, mirroring the Python SDK.
 */
export class PolicyViolationError extends PQCError {
  constructor(message, { algorithm = '', violations = [] } = {}) {
    super(message);
    this.algorithm = algorithm;
    this.violations = violations;
  }
}

/** A token has a valid signature but a passed `exp`. */
export class PQCTokenExpiredError extends PQCError {}

/** A token is malformed or otherwise unusable. */
export class PQCTokenInvalidError extends PQCError {}

/** A token's signature did not verify (subclass of {@link PQCTokenInvalidError}). */
export class PQCTokenSignatureError extends PQCTokenInvalidError {}

/** Base class for hosted-KMS errors. */
export class KMSError extends PQCError {}

/** The KMS could not find the referenced key. */
export class KMSKeyNotFoundError extends KMSError {}

/** The KMS rejected the credentials. */
export class KMSAuthError extends KMSError {}
