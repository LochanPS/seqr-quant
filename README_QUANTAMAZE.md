# SeQr × QpiAI — PQC-01: Verification-Gated Cryptographic Migration

**QUANT-A-MAZE 3.0 · Track II (Post-Quantum Cryptography) · Problem Statement PQC-01**

> A bank has RSA/ECC-dependent services that cannot all move to post-quantum crypto at once
> without interrupting payments. **Find the exposure, choose a provably-safe migration order,
> apply it, and prove each change worked before declaring the system migrated.**

This project extends **SeQr** (a working PQC assessment platform) with a **QpiAI quantum
optimisation + verification layer**. The original SeQr product is untouched; this is a separate
repository (`seqr-quant`) that builds on top of it.

---

## 1. The idea in one paragraph

Quantum computers will break the RSA/ECC encryption banks run today. A bank can't flip everything
at once — services depend on each other and only a limited number can be taken down per
maintenance window. So the hard question isn't *what's vulnerable* (SeQr already answers that) —
it's **in what order do we migrate, safely?** We turn that ordering into a combinatorial
optimisation, solve it with **QpiAI Opt** (native HUBO), confirm it on a quantum circuit with
**QpiAI QCloud** (QAOA), then **execute** one real migration at a time, **verify** each with a
fresh measurement, and **roll back** any change that fails.

```
DISCOVER → PLAN → OPTIMISE (QpiAI Opt HUBO) → CONFIRM (QpiAI QCloud QAOA)
         → EXECUTE + VERIFY-GATE + ROLLBACK (real X25519 + ML-KEM-768) → EVIDENCE
```

---

## 2. What is reused vs. what is new

| Layer | Source | Role here |
|---|---|---|
| Code/TLS scanner, CBOM (CycloneDX 1.6), risk engine | **SeQr base** (`shared-scanner`) | Discovery + inventory |
| ACME Bank sample repos + CBOM | **SeQr base** (`ecdat-demo`) | Labelled banking input |
| Migration `ChangeItem` model, `planner.py`, `synthesis/nginx.py`, `verify.py` | **SeQr base** (`audit/backend`) | Migration data model + the config artifact + the verify-by-rescan principle |
| **`optimize.py`** — QpiAI Opt HUBO wave scheduler | **NEW** | The migration-order decision |
| **`quantum_experiment.py`** — QpiAI QCloud QAOA | **NEW** | Same decision on a quantum circuit |
| **`execute.py`** — executed migration + verify-gate + rollback | **NEW** | Real X25519+ML-KEM-768, proof + revert |
| **`demo_quant.py`** — end-to-end story | **NEW** | One runnable command |
| **`detection_metrics.py`** — precision/recall harness | **NEW** | PQC-01 detection evaluation |

All new modules live in `audit/backend/app/migration/`.

---

## 3. How to run

### Setup (once)
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -U pip wheel
.venv/Scripts/pip install sqlalchemy==2.0.35 aiosqlite==0.20.0 pydantic==2.9.2 \
    pydantic-settings==2.5.2 python-dotenv==1.0.1 "cryptography>=42.0.0"
.venv/Scripts/pip install "qpiai-opt[quantum]" qpiai-quantum
# detection metrics only (code scanner) — tree-sitter, no sslyze:
.venv/Scripts/pip install tree-sitter==0.23.0 tree-sitter-python==0.23.0 \
    tree-sitter-javascript==0.23.0 tree-sitter-java==0.23.0 tree-sitter-go==0.23.0
```

### Keys
Register free keys, then put them in `.env` at the repo root (gitignored — never committed):
```
QPIAI_OPT_API_KEY=<from https://opt.qpiai.tech>
QCLOUD_API_KEY=<Access Token from https://qcloud.qpiai.tech>
```

### Run (from `audit/backend/`)
On Windows, prefix with `PYTHONIOENCODING=utf-8`.
```bash
python -m app.migration.demo_quant          # ← the whole PQC-01 story, one command
python -m app.migration.optimize            # QpiAI Opt HUBO scheduler vs baseline
python -m app.migration.quantum_experiment  # QpiAI QCloud QAOA vs classical optimum
python -m app.migration.execute             # executed migration + verify-gate + rollback
python -m app.migration.detection_metrics   # scanner precision/recall (needs tree-sitter)
```

---

## 4. QpiAI technology — where and how (rubric Section 8, 20 pts)

### QpiAI Opt — the migration-order decision (`optimize.py`)
Binary `x[i,t] = 1 ⇔ ChangeItem i runs in wave t`. Objective:
```
minimise  Σ_i Σ_t risk_i·t·x[i,t]                     # retire high-risk crypto earliest
        + A·Σ_i (Σ_t x[i,t] − 1)²                     # each change in exactly one wave
        + C·Σ_(i dep d) Σ_a Σ_{b≥a} x[i,a]·x[d,b]     # dependency precedence
        + K·Σ_t Σ_{risky i<j<k} x[i,t]·x[j,t]·x[k,t]  # ≤2 high-risk changes per wave
```
The crew-cap term is **degree-3** — it does not reduce to pairwise terms, so QpiAI Opt classifies
and solves it as a **native HUBO** (`problem_class = HUBO`). Inputs are real migration
`ChangeItem`s (risk from the violation severity, dependencies from the asset graph); the output is
the migration schedule fed to the runbook.

### QpiAI QCloud — the same decision on a quantum circuit (`quantum_experiment.py`)
QAOA is 2-local, so we take the crew bottleneck as a reduced instance (3 high-risk changes, 2
waves, **6 qubits**), build its QUBO, and run **QAOA** on the `QpiAI-QSV-Local` simulator (zero
cloud credits). We compare its result to the classical QpiAI Opt optimum on the identical
objective.

### Rubric mapping
| Criterion | Where | Evidence |
|---|---|---|
| **A1** product choice + domain integration (5) | Opt schedules real migration ChangeItems; QAOA solves the same decision; in = CBOM findings, out = executed migration | `demo_quant.py` chains it end-to-end |
| **A2** QpiAI Opt correctness (5) | native HUBO, constrained combinatorial, dependency + crew constraints | `optimize.py` → `problem_class = HUBO` |
| **A2** QpiAI QCloud correctness (5) | QAOA on the QUBO form, matches classical optimum | `quantum_experiment.py` |
| **A3** working + recorded + reproducible (5) | every module runs and prints evidence; commands above; all committed | this repo |

---

## 5. Measured results (reproducible)

| Stage | Result |
|---|---|
| Discovery | 16 cryptographic assets, **0 quantum-safe** (RSA 12 / ECDSA 3 / DH 1) |
| QpiAI Opt (HUBO) | naive baseline scored **478** → QpiAI Opt **110** (improvement **368**), crew-feasible, deps respected, solver ≈1 s |
| QpiAI QCloud (QAOA) | 6 qubits, matches classical optimum (scored **12**), **zero cloud credits** |
| Execute + gate | 5 services → `X25519MLKEM768` (real ML-KEM-768); **1 botched apply caught and rolled back**; tamper/forge ciphertexts rejected |
| Detection | precision **1.000**, recall **1.000**, F1 **1.000** (TP 10 / FP 0 / FN 0 / TN 4) |

---

## 6. Honest limitations (read before judging)

- **ML-KEM runs at the key-establishment layer, not full nginx TLS.** This machine has no Docker
  and OpenSSL 3.2 (ML-KEM needs OpenSSL 3.5+). We use real FIPS-203 ML-KEM-768 (via
  `cryptography` / OpenSSL 4.0.3) for a genuine hybrid X25519+ML-KEM-768 handshake. It is the
  **same primitive** an nginx `ssl_ecdh_curve X25519MLKEM768` line negotiates at the TLS layer on
  an OpenSSL 3.5+ runtime — SeQr's `synthesis/nginx.py` already emits exactly that config artifact.
- **QAOA runs the 2-local (QUBO) form** of the bottleneck. The higher-order crew constraint is the
  **HUBO** solved classically by QpiAI Opt. A natively higher-order quantum solve (RecursiveQAOA /
  ADAPT-QAOA) is future work, not claimed.
- **The QpiAI Opt result is a strong heuristic improvement**, not asserted to be globally optimal.
- **Detection metrics are on a small curated corpus** (14 files). Perfect P/R shows correct
  vulnerable-vs-PQC discrimination with zero false positives on real `pqcmap` code — not a claim
  of perfection at scale.
- The scheduling/verify logic here mirrors SeQr's existing `ChangeItem` / `verify.py` design over a
  DB-free core so it runs without the full FastAPI/Postgres stack; the quantum layer is the new work.

---

## 7. PQC-01 deliverables checklist

- [x] Inventory with file/service evidence (CycloneDX 1.6 CBOM)
- [x] Migration sequence (QpiAI Opt HUBO, dependency- and crew-constrained)
- [x] Working before-and-after protocol traces (real X25519 → X25519MLKEM768 handshake)
- [x] Compatibility tests (client/server session agreement)
- [x] Rollback plan (live verify-gate + automatic revert on a botched apply)
- [x] Detection precision/recall on labelled code (P = R = F1 = 1.0, with caveat)
- [x] Substantive QpiAI Opt **and** QpiAI QCloud use, with recorded execution evidence

---

*Built on SeQr. Quantum layer by QpiAI Opt + QCloud. Made for QUANT-A-MAZE 3.0.*
