# ECDAT — Terminal Demo Kit

A self-contained, **offline** live demo for the SIH internal round. It shows the
core ECDAT loop — **Discover → Assess → Produce a CBOM** — on a realistic
"ACME Bank" codebase, with no server, no internet, and no Oracle required.

---

## What's in here

```
ecdat-demo/
├── sample-repo/            ← a fake bank's codebase (Python, JS, Java, Go)
│   ├── payments/           RSA + Diffie-Hellman signing keys
│   ├── auth/               RSA-signed JWT session tokens
│   ├── infra/              paramiko SSH deploy key
│   ├── web/src/            Node crypto + node-forge RSA
│   ├── core/src/           Java RSA keygen
│   └── gateway/            Go RSA + ECDSA TLS keys
├── generate_cbom.py        ← turns the scan into a CycloneDX 1.6 CBOM
├── demo.ps1                ← the live demo (Windows — primary)
├── demo.sh                 ← the live demo (bash — fallback)
└── acme-bank.cbom.cdx.json ← generated CBOM (created when you run the demo)
```

## Numbers you can quote on stage

- **9 files scanned, 18 vulnerable findings, 0 quantum-safe.**
- **16 cryptographic components** catalogued into the CBOM.
- Algorithms found: **RSA ×12, ECDSA ×3, Diffie-Hellman ×1** — all quantum-vulnerable.
- Estimated manual fix effort: **~174–261 hours** (the tool computes this).
- Output: **CycloneDX 1.6** — the global standard CBOM format.

---

## One-time setup (already done on this laptop)

If running on a fresh machine, from the `seqr-labs` repo root:

```powershell
pip install -e .\cli               # the `seqr` command
pip install -e .\shared-scanner    # the scanner engine (for generate_cbom.py)
```

`ecdat-demo/` must sit next to `seqr-labs/` (same parent folder) so the CBOM
script finds the engine — or set `$env:SEQR_SHARED` to the shared-scanner path.

> Note: the sample code is only ever *read* by the scanner, never executed —
> so the bank's own dependencies (pycryptodome, node-forge, etc.) do NOT need
> to be installed.

---

## Run the demo

```powershell
cd ecdat-demo
powershell -ExecutionPolicy Bypass -File .\demo.ps1
```

Press **Enter** between steps so you control the pace. Steps:

1. **Show the codebase** — "a bank hands us this; they don't know their own crypto."
2. **`seqr scan code`** — discovers + risk-scores every algorithm live.
3. **`generate_cbom.py`** — produces the CycloneDX 1.6 CBOM.
4. **Peek inside the CBOM** — proves it's a real standard document, not a mockup.
5. *(optional, needs internet)* **`seqr scan domain`** — live TLS scan of a real site.

---

## What to say at each step (maps to the pitch)

- **Step 2:** "In seconds it found 18 places using encryption a quantum computer
  will break — across four languages — and told us exactly what to replace each with."
- **Step 3:** "It doesn't stop at a list. It builds a CBOM — the standard inventory
  format India's DST roadmap will require in procurement from 2027."
- **Step 4:** "Real CycloneDX. This plugs straight into existing compliance pipelines."
- **Close:** "Everything ran on this laptop. Nothing left the room — that's the
  on-premise model NTRO and defence need."

---

## Before the event — safety net

- Run `demo.ps1` end to end the night before.
- **Record a 2-minute screen video** of it working. If the venue laptop or Wi-Fi
  misbehaves, play the recording. Never demo live without a backup.
- Skip Step 5 (domain scan) if the venue has no reliable internet — Steps 1–4 are
  fully offline and are the strongest part anyway.

## Known rough edges (internal note — not for the judges)

- The Java file may show one extra low-confidence "ECDSA" line next to the RSA
  finding; the engine shares a detection rule there. Harmless, defensible.
- This is the free CLI tier. The full risk dashboard, PDF report, and compliance
  mapping live in the web app (localhost demo — ask if you want that wired too).
