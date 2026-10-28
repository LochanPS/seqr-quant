# 13 · Platform Spine PRD — Crypto-Asset State Graph + Policy Engine + Discovery Agent

**Status:** NEXT — build before the migration engine.
**Owner:** Lochan. **Created:** 2026-07.
**Depends on:** existing `shared-scanner` engines (classifier, risk, cbom, compliance).
**Unblocks:** migration engine, SDK, CI gate, attestation.

---

## 1. Why this exists

Today the CBOM is a **per-scan export** and each product (scanner, planned migration engine, SDK,
CI gate) would own its own state. That produces a bag of disconnected tools, not a platform.

The spine is the shared substrate every product reads and writes. Two pieces:

1. **Crypto-asset state graph** — the CBOM as a living database with desired-vs-actual state and history.
2. **Declarative policy engine** — "quantum-safe" defined once; every product becomes one verb against it.

**Build the spine first** so the migration engine reduces to *"converge actual → policy"* instead
of re-implementing state, inventory, and correctness on its own.

---

## 2. Goals / non-goals

**Goals**
- Persist every discovered crypto asset, its properties, ownership, dependencies, and history.
- Track **desired vs actual** posture per asset and compute drift.
- Evaluate assets against a **declarative policy** and emit violations with severity + remediation intent.
- Expose one API/data model that scanner, discovery agent, migration engine, SDK, CI, and
  attestation all use.

**Non-goals (this phase)**
- No change execution (that's the migration engine).
- No code-repository crawling (that's the discovery scope of the SDK/CI, not the infra agent).
- No ML-DSA certificate issuance (future module).
- No auto-apply of any change.

---

## 3. Crypto-asset state graph

### 3.1 Core entities
- **Asset** — a thing with crypto posture: domain, TLS endpoint, certificate, host, HSM,
  internal-PKI CA, load balancer, reverse proxy, SSH host, mail server, service.
- **CryptoComponent** — an algorithm/parameter instance on an asset (e.g. TLS_AKE
  `X25519MLKEM768`, cert `RSA-2048`, cipher suite, KEX group). Maps to the existing classifier output.
- **PostureState** — per asset/component: `actual`, `desired` (from policy), `status`
  (`compliant | violation | unknown | in_migration`), `last_measured`, `source`
  (`external_scan | discovery_agent | agent_probe`).
- **Owner** — team/person responsible (for workflow + approvals later).
- **Edge/Dependency** — asset→asset relationships (edge→origin, LB→upstream, service→cert,
  host→HSM). This is what makes it a graph and powers the edge/origin bypass analysis.
- **Event** — append-only history: measured, policy-changed, migrated, drifted, attested.

### 3.2 Design notes
- Reuse `engines/cbom.py` (CycloneDX 1.6) as the **export projection**, not the storage format.
  Storage = relational graph (SQLAlchemy 2.0 + PostgreSQL, per stack); CBOM is generated *from* it.
- Multi-tenant: every entity carries `org_id` (see the org-boundary audit task — this spine must
  not weaken tenancy). 404-not-403 on cross-tenant reads.
- Deterministic asset identity (stable keys) so re-scans update rather than duplicate.

---

## 4. Policy engine (build now — do not bolt on later)

### 4.1 Concept
Define the desired crypto posture **once**, declaratively. Then:

| Product | Verb against policy |
|---|---|
| Scanner / discovery | **measure** actual vs policy |
| Migration engine | **converge** actual → policy |
| pqcmap SDK | **enforce** policy in application code |
| CI gate | **block** PRs that violate policy |
| Monitoring | **alert** on drift from policy |
| Attestation | **certify** posture against policy at a point in time |

### 4.2 Policy shape (illustrative)
- `external_tls.must_offer_hybrid_kem: [X25519MLKEM768, ...]`
- `key_exchange.forbid_static_rsa: true`
- `origin.no_exposed_classical_origin: true`
- `certificate.min: {rsa: 3072, ecdsa: p256}` (ML-DSA = future module)
- `tls.min_version: TLS_1_2` / prefer `TLS_1_3`
- Per-scope overrides (org / asset-tag / environment), with an inheritance + precedence model.
- Ships with an opinionated **default policy** derived from PCI DSS + SEBI CSCRF so a customer is
  compliant-by-default and can tighten.

### 4.3 Output
A policy evaluation over the graph yields ranked **violations** (asset, component, rule, severity,
recommended target state). Reuses `engines/risk.py` for severity/priority. This ranked violation
set is exactly the migration engine's input.

---

## 5. Discovery agent v1 — infrastructure only

On-prem agent that inventories internal crypto the external scan can't see. **Infra scope only;
application code is out of scope (SDK/CI own that).**

**In scope v1:** hosts, certificate stores, TLS endpoints, HSMs (PKCS#11), internal PKI / CAs,
load balancers, reverse proxies. **Out of scope v1:** code repositories, secrets in source.

- Air-gap friendly: runs inside the customer perimeter, zero egress, offline Ed25519 licensing
  (already built). Writes into the state graph.
- Clean separation: **Discovery Agent → infrastructure assets; SDK + CI → application code.**

---

## 6. How the rest of the platform sits on the spine

```
Discovery Agent ─┐
External Scanner ─┼─► Crypto-Asset State Graph ◄─► Policy Engine
                  │            ▲   │
Migration Engine ─┘            │   ├─► Violations ──► Migration Engine (converge)
   (writes back actual)        │   ├─► SDK (enforce in code)
                               │   ├─► CI gate (block drift)
                               │   └─► Attestation (certify at T)
```

- **Migration engine** (next PRD, `14`): consumes ranked violations → synthesises infra config
  (nginx/Apache/HAProxy, Cloudflare/CloudFront/ALB/App Gateway), origin hardening, mTLS,
  cipher-suite migration → emits a **signed change bundle + runbook** → re-measures → updates graph.
  Auto-apply is a later opt-in enterprise capability.
- **Attestation (last stage):** signed, timestamped posture snapshots + policy-compliance
  certificates + migration history + audit trail — all projections of the graph + events. The
  artifact that satisfies auditors and justifies the enterprise price.

---

## 7. Phasing

1. **Graph schema + write path** — persist scanner output into the state graph (replace ad-hoc CBOM export path).
2. **Policy engine** — schema, default policy (PCI + SEBI), evaluator → violations.
3. **Drift + history** — desired-vs-actual, events, re-scan diffing.
4. **Discovery agent v1** — infra inventory into the graph (on-prem).
5. Hand off ranked violations to the migration engine PRD (`docs/14`).

---

## 8. Open questions to close before coding
- Policy authoring surface v1: YAML/JSON in-repo vs DB-backed UI? (Lean: versioned file + API, UI later.)
- Graph store: pure relational (Postgres, adjacency tables) vs a graph extension? (Lean: relational; the "graph" is logical.)
- Asset identity keys across scan + agent sources (dedupe strategy).
- How policy versions bind to attestation (an attestation must name the policy version it certified against).
