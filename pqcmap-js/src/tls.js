/**
 * Best-effort PQC-hybrid TLS for Node — negotiate X25519MLKEM768 when the runtime can,
 * else degrade cleanly to secure classical TLS, and always report honestly. Port of the
 * Python `pqcmap.tls` module's intent, adapted to Node's `tls`/`https` API.
 *
 * PQC TLS key exchange (hybrid group X25519MLKEM768, IANA 0x11EC) needs **OpenSSL 3.5+**,
 * which ships the ML-KEM groups natively. Node exposes group selection via the `ecdhCurve`
 * option (SSL_CTX_set1_groups_list). Because OpenSSL rejects an *unknown* group name at
 * context creation — which would break the handshake — this module only adds the PQC group
 * when the linked OpenSSL is new enough to know it; otherwise it configures a hardened
 * classical group list. It never breaks a connection to try for PQC.
 *
 * MTU / fragmentation caveat (docs/02): an ML-KEM ClientHello (~1.2 KB) spans multiple
 * packets; test a real handshake against your endpoints before production.
 */
import https from 'node:https';

export const PQC_HYBRID_GROUP = 'X25519MLKEM768';
const CANDIDATE_GROUPS = ['X25519MLKEM768']; // OpenSSL 3.5+ IANA codepoint 0x11EC
const CLASSICAL_GROUPS = ['X25519', 'prime256v1'];

/** Parse process.versions.openssl (e.g. "3.5.0", "3.0.13+quic") to [major, minor, patch]. */
function opensslVersionInfo() {
  const raw = process.versions.openssl || '0.0.0';
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(raw);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : [0, 0, 0];
}

function gteq(info, major, minor) {
  return info[0] > major || (info[0] === major && info[1] >= minor);
}

/** Honest report of what PQC TLS this runtime can do. */
export class TLSCapabilities {
  constructor({ opensslVersion, opensslVersionInfo, node, pqcGroupConfigured, pqcMaybeDefault, configuredGroup, notes }) {
    this.opensslVersion = opensslVersion;
    this.opensslVersionInfo = opensslVersionInfo;
    this.node = node;
    this.pqcGroupConfigured = pqcGroupConfigured;
    this.pqcMaybeDefault = pqcMaybeDefault;
    this.configuredGroup = configuredGroup;
    this.candidateGroups = CANDIDATE_GROUPS;
    this.notes = notes;
  }

  /** True if a PQC hybrid key exchange is achievable on this runtime. */
  get pqcHybridAvailable() {
    return this.pqcGroupConfigured || this.pqcMaybeDefault;
  }

  summary() {
    const state = this.pqcGroupConfigured ? 'configured' : this.pqcMaybeDefault ? 'available-by-default' : 'unavailable';
    const grp = this.configuredGroup || (this.pqcMaybeDefault ? PQC_HYBRID_GROUP : '-');
    return `PQC-hybrid TLS: ${state} (group ${grp}); OpenSSL ${this.opensslVersion}; Node ${this.node}`;
  }

  asDict() {
    return {
      opensslVersion: this.opensslVersion,
      opensslVersionInfo: this.opensslVersionInfo,
      node: this.node,
      pqcGroupConfigured: this.pqcGroupConfigured,
      pqcMaybeDefault: this.pqcMaybeDefault,
      pqcHybridAvailable: this.pqcHybridAvailable,
      configuredGroup: this.configuredGroup,
      candidateGroups: this.candidateGroups,
      notes: this.notes,
    };
  }
}

/** Probe the runtime for PQC TLS support. `configuredGroup` reflects a built context. */
export function capabilities(configuredGroup = null) {
  const info = opensslVersionInfo();
  const pqcMaybeDefault = gteq(info, 3, 5);
  const notes = [];
  if (pqcMaybeDefault) {
    notes.push('OpenSSL >= 3.5 knows X25519MLKEM768 and may negotiate a hybrid key exchange.');
  } else {
    notes.push('OpenSSL < 3.5: native ML-KEM groups absent; the PQC group is not configured to avoid breaking the handshake. Rebuild Node against OpenSSL 3.5+ for PQC TLS.');
  }
  notes.push('MTU: an ML-KEM ClientHello (~1.2 KB) fragments; test real handshakes before production (docs/02).');
  return new TLSCapabilities({
    opensslVersion: process.versions.openssl || 'unknown',
    opensslVersionInfo: info,
    node: process.versions.node,
    pqcGroupConfigured: configuredGroup !== null,
    pqcMaybeDefault,
    configuredGroup,
    notes,
  });
}

/**
 * Build hardened client TLS options that prefer the PQC hybrid group when the runtime
 * supports it, else a secure classical group list. Returns `{ options, capabilities }`.
 * `options` plugs straight into `https.request` / `tls.connect` / `new https.Agent`.
 * Set `verify: false` only for local testing (disables cert/hostname checks).
 */
export function buildClientOptions({ verify = true, preferPqc = true } = {}) {
  const info = opensslVersionInfo();
  const canPqc = preferPqc && gteq(info, 3, 5);
  const groups = canPqc ? [...CANDIDATE_GROUPS, ...CLASSICAL_GROUPS] : [...CLASSICAL_GROUPS];
  const options = {
    minVersion: 'TLSv1.2',
    ecdhCurve: groups.join(':'),
  };
  if (!verify) options.rejectUnauthorized = false;
  return { options, capabilities: capabilities(canPqc ? PQC_HYBRID_GROUP : null) };
}

/** An https.Agent configured with {@link buildClientOptions}; carries `pqcCapabilities`. */
export function pqcHttpsAgent(opts = {}) {
  const { options, capabilities: caps } = buildClientOptions(opts);
  const agent = new https.Agent(options);
  agent.pqcCapabilities = caps;
  return agent;
}

/** One-line human-readable capability summary for logs / CLIs. */
export function report() {
  return capabilities().summary();
}
