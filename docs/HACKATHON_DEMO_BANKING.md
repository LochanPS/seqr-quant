# PQC-01 demo script — SeQr for a bank (≈10 minutes)

The product is unchanged; only the story is banking. Two kinds of bank appear:

- **Real Indian BFSI sites, outside-in.** We do a public TLS handshake, the same one any
  browser makes, and nothing more. Origin discovery and recon stay off for third parties
  (the product only runs them on an org's *own* assets).
- **"Meridian Financial", inside-out.** This is the seeded bank in the demo org, with assets,
  graph, HSM and SSH. It stands in for the customer who hired us.

Login: `demo@seqrlabs.com` / `demodemo123`. Local run: `scripts\run-local-backend.cmd` +
`scripts\run-local-frontend.cmd`, then open http://localhost:3000.

**Before the judges arrive:** add and scan the three public assets once (Assets → Add asset
→ Domain → Scan, about 30 s each), so the demo never waits on someone else's network.

---

## Act 1 — Why a bank cares (1 min, no screen)
- Harvest-now-decrypt-later: traffic recorded today is decrypted once a quantum computer
  exists. Bank data (KYC, account history, loan files) must stay secret for 10+ years.
- What already applies: **PCI DSS 12.3.3** (crypto inventory, mandatory since 2025-03-31) and
  **SEBI CSCRF** (crypto-asset inventory). Next: **RBI Q-SAFE** (expected ~Nov 2026) and the
  DST 2027 inventory milestone (recommendatory).
- Say it this way: *"Your crypto inventory is already expected. SeQr builds it, ranks it and
  plans the fix."* Avoid "hard deadline" and "mandatory by law" for DST.

## Act 2 — Outside-in: real Indian finance endpoints (2 min) → Assets / Asset detail
Observed live on 2026-10-29 with the wire-level hybrid probe:

| Endpoint | Key exchange | Certificate | Talking point |
|---|---|---|---|
| hdfcbank.com | **X25519MLKEM768 (hybrid PQC)** → risk 0 | RSA-2048 → **URGENT** | Edge already post-quantum; signatures are the next job |
| razorpay.com | **X25519MLKEM768** | classical | Payment rails moving: usually the CDN edge, not the origin |
| sbi.co.in | classical **X25519** (server declined ML-KEM) | classical | Recorded traffic stays decryptable later |

Point to make: *"We don't ask OpenSSL. SeQr sends its own TLS 1.3 ClientHello carrying an
ML-KEM-768 key share and reads what the server picks."* Then the caveat, which is also the
pitch: *"This is the edge. Our measurement study found 51% of 118 fintech domains expose an
origin behind the CDN, and outside-in can't see it. That's why a bank deploys SeQr inside."*

Phrase findings as observations ("classical key exchange observed"), never as "SBI is
vulnerable/hacked".

## Act 3 — Inside the bank: inventory with evidence (2 min) → Overview, Graph, CBOM
- **Graph:** Meridian's domains, origins, load balancer, HSM and SSH hosts, with edges. That's
  the service evidence.
- **CBOM:** CycloneDX 1.6 export: every algorithm, where it lives, and its source.
- **Code evidence:** `seqr scan code ecdat-demo --ranked` gives findings with file:line (CLI).
- **Overview → risk ranking (context-aware):** the exposed origin's key exchange ranks first
  (100, IMMEDIATE) because traffic can route around the CDN. Internal SSH ranks 27 (needs a
  foothold first). Hybrid endpoints score 0. *Same algorithm, different risk, because of
  context.*

## Act 4 — Decide what to fix first with QpiAI (2 min) → Remediation
- Infrastructure mode, budget **24 engineer-hours** → Plan.
- QpiAI Opt (HUBO) picks 5 fixes and removes **60.2%** of the risk. That is **certified
  optimal** by exhaustive search. Greedy "best value first" gets 59.1%.
- Show the risk-vs-budget curve: 8 h → 25.9%, 24 h → 60.2%, 48 h → 81.7%.
- Why HUBO: fixes overlap. Origin lock-down, hybrid KEX and full migration all cover the
  same slot, which makes cubic terms. That isn't decoration; a linear model can't express it.
- Optional QAOA toggle: alternative plans from a gate-based circuit. **Say the honest result:**
  measured amplification ×0.7–1.5, so no reliable advantage at 12–13 qubits.

## Act 5 — Execute safely: sequence, traces, tests, rollback (2 min) → terminal
```powershell
cd audit\backend
$env:PYTHONIOENCODING = "utf-8"
..\..\.venv\Scripts\python -m app.migration.demo_quant    # ~40 s
```
This one command shows:
- **Migration sequence:** QpiAI Opt HUBO wave schedule (crew cap, risky changes never
  stacked) against a max-parallel baseline.
- **Before/after protocol traces:** a real ML-KEM-768 handshake transcript, classical vs
  hybrid.
- **Compatibility tests + verify gate:** tampered and forged handshakes are caught.
- **Rollback:** a broken migration is rolled back automatically.
- **Detection precision/recall:** P = R = F1 = 1.0 on 14 labelled files. Say "small labelled
  set".

## Act 6 — Prove it (1 min) → Overview → Generate attestation
- A signed posture attestation (PDF + JSON). The auditor verifies it offline:
  `seqr verify-attestation <file>`.

---

## PQC-01 deliverables → where they are
| Required | Shown in |
|---|---|
| Inventory with file/service evidence | Graph, CBOM, `seqr scan code --ranked` (file:line) |
| Migration sequence | Remediation planner (what) + `demo_quant` HUBO waves (order) |
| Before/after protocol traces | `demo_quant` / `execute.py` handshake transcripts |
| Compatibility tests | `execute.py` verify gate (tamper / forge cases) + `tests_quant` |
| Rollback plan | `execute.py` rollback + Overview migration lifecycle |
| Detection precision/recall | `detection_metrics.py` |
| QpiAI Opt (A2) | Remediation planner + wave scheduler (HUBO, certified vs exhaustive) |
| QpiAI QCloud (A2) | QAOA alternatives + `quantum_experiment.py` |

## Likely judge questions — straight answers
- **"Is the vulnerability detection quantum?"** No, and it shouldn't be. Finding RSA in code
  or ECDHE in a handshake is deterministic (AST parsing, TLS handshakes, certificate
  parsing). Quantum and quantum-inspired methods sit at the *decision* layer: which fixes,
  in what order, under real constraints.
- **"Does QpiAI Opt run on quantum hardware?"** Its local HUBO solver is quantum-inspired
  annealing on this machine. QAOA runs on QpiAI's QCloud simulator. Cloud execution is the
  next step (one job per plan, not per optimiser step).
- **"Why does HDFC look good?"** The public edge negotiates hybrid PQC, very likely CDN-side.
  Certificates are still RSA, and the origin is unknown from outside.
