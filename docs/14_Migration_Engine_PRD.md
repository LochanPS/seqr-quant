# 14 · Migration Engine PRD — Phase 2 (converge Actual → Policy)

**Status:** NEXT (Phase 2). Design doc; models on founder greenlight (same flow as PRD 13).
**Depends on:** the platform spine (PRD 13) — consumes ranked `Violation`s, writes back via re-scan.
**Unblocks:** the remediation half of the product; the flagship commercial differentiator.

---

## 1. What it is (and is not)

The engine turns policy **violations** into an **executed migration** — but "executed from our
side" means we **generate and sign a change bundle + runbook that the customer applies**, then we
**verify** the result. It does **not** run inline in the customer's traffic path.

**Apply model (LOCKED, from the 2026-07 decisions):**
- ✅ Signed **change bundle + runbook**; customer's ops applies it inside their perimeter.
- ✅ Air-gap friendly; low liability; the customer keeps approval before any prod change.
- ❌ **No inline auto-apply / execution pipeline in Phase 2.** Auto-apply is a *later, opt-in*
  enterprise capability, out of scope here.

**Non-goals (Phase 2):** inline execution/agent auto-apply; ML-DSA certificate issuance
(future module); application-code crypto (that's the pqcmap SDK); provider coverage beyond the
first adapters.

---

## 2. The pipeline (all customer-facing steps are generate/verify, not execute)

```
Violations (spine)  ->  Plan  ->  Synthesize  ->  Bundle + Sign
                                                      |
                                        (customer applies the bundle)
                                                      v
                          Verify (re-scan -> re-project -> re-evaluate)  ->  Converge
```

1. **Plan** — group the org's open violations by asset, order by dependency (graph edges), and
   pick target states from `violation.target_state`. Output: a `MigrationPlan` of `ChangeItem`s.
2. **Synthesize** — each ChangeItem → a concrete config artifact via a **provider adapter**
   (nginx / HAProxy / Cloudflare / CloudFront / ALB / App Gateway). e.g. "enable
   `X25519MLKEM768` on this listener", "close/allowlist this origin + enforce mTLS".
3. **Bundle + Sign** — assemble artifacts + a human runbook + a rollback plan into a
   **MigrationBundle**, Ed25519-signed (separate migration signing key; verifiable offline like
   attestations, reusing the fork-C machinery). Customer verifies authenticity before applying.
4. **Verify** — after the customer applies, trigger a re-scan → new observations → projection →
   policy re-evaluation. Confirm the targeted violations cleared. **This reuses the spine; no new
   verification engine.**
5. **Converge** — desired (Policy) vs actual (ComponentState). Remaining violations feed the next
   plan. The loop runs until actual == desired for the targeted slots.

---

## 3. Data model (built on the spine; models pending greenlight)

- **MigrationPlan** — `org_id`, `policy_evaluation_id` (the violations it targets), `status`
  (`draft|bundled|applied|verified|superseded`), `created_at`. Reproducible from its evaluation.
- **ChangeItem** — `plan_id`, `asset_id`, `violation_id`, `slot_key`, `provider`, `action`,
  `from_state`, `to_state`, `depends_on` (ordering), `rollback` (inverse). One remediation step.
- **MigrationBundle** — `plan_id`, `manifest` (JSON: artifacts + checksums), `runbook` (rendered
  steps), `migration_engine_version`, `graph_schema_version`, `key_id`, `signature`, `created_at`.
- **RollbackPlan** — captured pre-change state per ChangeItem + the inverse artifact, so the
  customer can revert deterministically.

`MIGRATION_ENGINE_VERSION` is a pinned constant (already referenced by attestations).

---

## 4. Key design decisions

- **Input = violations, not raw scans.** The engine only ever remediates a policy gap. Clean seam:
  `violation.target_state` is the intended end-state; synthesis makes it concrete.
- **Dependency ordering via the graph.** `asset_edge` (edge↔origin, LB↔upstream) orders changes so
  we don't, e.g., harden an origin in a way that breaks the edge path mid-migration.
- **Dry-run is first-class.** Render the full bundle + diff + affected-asset list **without**
  signing or persisting a committed plan. This is how a customer reviews before anything is real.
- **Rollback is mandatory per ChangeItem.** No change ships in a bundle without its inverse and a
  captured pre-state snapshot.
- **Bundle signing = trust, not execution.** Signature lets the customer verify the bundle is
  authentic SeQr output before they apply it — mirrors the attestation verifier, offline.
- **Verification is re-scan, not self-report.** "It's fixed" is only ever asserted by a fresh
  measurement flowing back through the spine. No engine self-attestation of success.

---

## 5. Phasing (leverage order)

1. **Plan + models** — `MigrationPlan` / `ChangeItem` / `MigrationBundle` / rollback; build a plan
   from an evaluation's violations with graph-ordered ChangeItems. (schema slice)
2. **Change synthesis adapters** — start with **nginx + Cloudflare** for the two highest-value
   fixes: enable hybrid `X25519MLKEM768`, and origin hardening (allowlist + mTLS). Add
   HAProxy/CloudFront/ALB/App Gateway next.
3. **Bundle + signing + offline verifier** — reuse the Ed25519/fork-C machinery, separate
   migration key.
4. **Dry-run + rollback** — render/diff without commit; inverse artifacts + pre-state capture.
5. **Verify-by-rescan + convergence** — trigger re-scan, confirm targeted violations cleared,
   loop until converged.

---

## 6. Open questions to close before coding
- Provider adapter set for v1 — confirm **nginx + Cloudflare** first (highest coverage in the
  measured corpus)?
- Bundle format — tar + `manifest.json` with per-artifact SHA-256, signed manifest?
- Signing key — **separate migration signing key** (recommended, per fork C) vs reuse the
  attestation key?
- How much does a ChangeItem assume about the customer's config layout (templated snippet vs full
  managed file)? Lean: **additive snippet + instructions**, not owning their whole config.
