# 15 · Discovery Agent — Design (implementation-ready)

**Status:** PARTIALLY BUILT. Slice 1 (agent-ingest backend, 2026-09-15), Slice 2 (signed
air-gap import), and Slice 3 (agent runtime: plugin host + `tls` / `cert_store` / `proxy_conf` /
`pkcs11` collectors + config file + connected/air-gap CLI + Docker/PyInstaller packaging) shipped
2026-09-21 — see `deploy/agent/README.md`. Remaining collectors (k8s, cloud control plane, ssh),
the real-HSM PyKCS11 path, and the `/connections` dashboard UI (Slice 4) stay **deferred, build
per pilot** — the original deferral rationale (§1) still governs *which* collectors come next.

---

## 1. Build now or defer? — DEFER (technically justified)

**Defer.** Reasons:

1. **The pipeline is already proven without it.** The spine → policy → migration → attestation
   loop is validated end-to-end on five realistic sector templates whose data is exactly the
   *shape* a discovery agent would emit (internal hosts, origins, HSM refs, agent-sourced
   observations). Correctness of the platform does not depend on the agent existing.
2. **Highest cost + highest variance component.** It needs an air-gapped deployable, per-source
   plugins, credential custody, and in-perimeter update/ops. Building the wrong plugin set is the
   most expensive mistake available.
3. **Plugin priority is customer-specific.** Which sources matter first (Kubernetes vs cloud
   control-plane vs PKCS#11 HSM vs cert stores vs config files) is precisely what discovery calls
   answer. Building now = guessing.
4. **Value exists without it.** External active scanning + manual/CSV import already populate the
   graph for pilots and the SaaS funnel. The agent is the on-prem flagship's depth, not its gate.

**Reconsider when:** a design partner commits to a pilot that requires internal inventory, or two+
discovery calls converge on the same first source. Then build the plugins they actually need.

---

## 2. Responsibilities

Inventory internal cryptography the external scanner cannot see, and write it into the spine graph
via authenticated APIs — **infrastructure only** (hosts, cert stores, TLS listeners, HSMs, internal
PKI, load balancers, reverse proxies). Application-code crypto is out of scope (that is the SDK/CI).

Read-only discovery. The agent never changes customer config (migration is bundle + runbook).

---

## 3. Modules

- **Core runtime** — scheduler, config loader, plugin host, result buffer, secure uploader.
- **Plugin host** — loads/enables source plugins; each returns normalized `AssetObservation`s.
- **Normalizer** — maps raw plugin output to the spine's asset/observation/edge model + source tags.
- **Uploader** — batches, signs, and POSTs observations to the platform ingest API; offline spool
  + resume for air-gapped/interrupted runs.
- **Local store** — encrypted spool of pending observations (crown-jewel data; see §8).
- **Self-updater (optional, enterprise)** — signed update channel; disabled in air-gapped mode.

## 4. Plugin architecture

A plugin is a small module implementing:

```
class SourcePlugin:
    key: str                 # "pkcs11" | "cert_store" | "nginx_conf" | "k8s" | "cloud_cf" ...
    def available(self) -> bool: ...          # dependencies/permissions present?
    def collect(self) -> list[AssetObservation]: ...   # read-only
```

`AssetObservation` = normalized {asset_natural_key, asset_type, crypto slots (algo/family/keysize),
edges, source=discovery_agent, confidence, observed_at}. First-wave plugins (build per demand):

- `cert_store` — filesystem/OS trust + service cert stores (leaf/chain, key sizes, expiry).
- `nginx_conf` / `haproxy_conf` — parse TLS listener config (groups, ciphers, cert paths) — read-only.
- `pkcs11` — HSM slot inventory via PKCS#11 (key types/sizes; never extracts key material).
- `k8s` — TLS secrets, ingress TLS, service mesh certs.
- `cloud_control_plane` — Cloudflare/AWS/Azure APIs for edge/LB/cert config (read scopes only).
- `ssh_host` — host key + KEX inventory of internal hosts.

## 5. Communication model

- Agent → platform only (outbound). No inbound ports on the agent.
- Batched HTTPS POST to `POST /api/v1/agent/observations` (org-scoped). Idempotent by
  (natural_key, slot, observed_at) so retries/resumes don't duplicate.
- Air-gapped mode: agent writes a signed export file; an operator transfers it; platform imports
  via `POST /api/v1/agent/import`. No network egress.

## 6. Authentication

- Agent authenticates with an org-scoped **API key** (`sq_live_…`, existing hashed-key scheme) OR
  a dedicated agent credential with an `agent` scope. Per-agent identity + revocation.
- Every upload is also **signed** by the agent's own key so the platform can attribute + verify
  origin; the platform records the agent key id on ingested observations.
- Air-gap export files are signed; the platform verifies before import.

## 7. Deployment model

- Single static binary / minimal container, runs inside the customer perimeter (matches the on-prem
  flagship). Offline Ed25519 licensing already exists and gates it.
- Config: which plugins, schedule, target scopes, upload endpoint or export path.
- Modes: **connected** (POST) and **air-gapped** (export/import). Zero data egress guarantee in
  air-gapped mode.

## 8. Security model (the agent handles crown-jewel data)

- **Least privilege:** read-only everywhere; PKCS#11 inventory only (no key extraction); cloud API
  read scopes only.
- **No secrets at rest in clear:** local spool encrypted; credentials from the platform key-request
  flow / OS keystore, never embedded.
- **Attributable + tamper-evident:** signed uploads, per-agent key id, append-only ingest events
  (reuses the spine event log / access audit).
- **Data minimization:** collect crypto posture metadata, never private keys or plaintext secrets.
- **Tenant isolation:** every observation carries `org_id`; ingest re-verifies against the agent
  credential's org.

## 9. Platform-side APIs to add (when built)

- `POST /api/v1/agent/observations` — batched ingest → spine graph (resolver + projection).
- `POST /api/v1/agent/import` — signed air-gap export import.
- `GET  /api/v1/agent/status` — last-seen, plugin coverage, counts (observability).
- Agent credential issuance/revocation under the existing org/admin routes.

## 10. Non-goals

No config changes / execution (read-only). No application-code scanning (SDK/CI). No key material
extraction. No inbound control channel.
