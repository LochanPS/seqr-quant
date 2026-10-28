# SeQr — Marketing, Sales & Build-in-Public Source of Truth

> One place for positioning, proof, personas, pricing, outreach, and content.
> Consolidates: [`docs/05_Business.md`](docs/05_Business.md) (GTM playbook — parts stale, corrected here),
> [`docs/12_Product_Strategy.md`](docs/12_Product_Strategy.md) (honest strategy),
> [`gtm/README.md`](gtm/README.md) (outreach playbook — current), and the research paper
> (`research/paper/PQC_India_Measurement.md`).
> **Compliance framing here is the corrected version — use this, not doc 05's Jan-2027 language.**
> Last updated: 2026-07.

---

## 1. One-line pitch

**"SeQr finds every quantum-vulnerable system in your infrastructure, builds the cryptographic
inventory PCI DSS and SEBI already require, and migrates you to post-quantum — before your
auditor asks."**

Build-in-public shorthand: *"Quantum-safe, in name only."* We measured Indian fintech TLS and
the industry's "post-quantum" is a CDN mirage.

---

## 2. The proof (lead with research, not the product)

From an active measurement study of 60+ Indian financial-services endpoints:

- Passive scanners (the standard tool) report **0%** PQC; active probing shows **60%**.
- That 60% is a **CDN-edge default**, not a decision — CloudFront/Cloudflare flip it on.
- **100% of certificates remain classical** (RSA/ECDSA).
- **51% of firms expose a non-CDN origin** that routes around the edge (95% CI 42–60, n=118).
- **0% are end-to-end quantum-safe.**

Public research repo: `github.com/LochanPS/seqr-labs-research`. Rule: share **aggregate**
findings; never name a specific company's weakness in outreach.

---

## 3. Compliance hooks — ACCURATE (this supersedes doc 05)

- **PCI DSS 12.3.3 — live, mandatory since 2025-03-31.** Card-data environments need a
  documented cryptographic inventory, reviewed annually. Enforced at the next QSA audit.
- **SEBI CSCRF (PQC) — live since Jun 2025, binding on SEBI REs.** Best beachhead: the pain is
  current. Explicitly names a crypto-asset inventory + PQC prioritisation.
- RBI Q-SAFE — framework expected ~Nov 2026 (emerging; get ahead of it).
- DST Task Force — **recommendatory**; a CII crypto-inventory milestone **by 2027**. CII
  includes BFSI. **Never call "Jan 1 2027" a hard filing deadline** (doc 05 does — it's wrong).
- DPDP Act §8 — enforceable **2027-05-13**; up to ₹250 Cr for failing to protect PII in transit.
  Frame in future tense.
- **Never use CNSA 2.0** in Indian compliance copy (US NSS only).

---

## 4. Who to target first (from gtm/README — current)

1. **Brokerages (SEBI CSCRF)** — best beachhead, live mandate. Groww, Zerodha, Angel One,
   Upstox, 5paisa, Dhan.
2. **Payment aggregators (PCI DSS 12.3.3 + RBI)** — Razorpay, Cashfree, PayU, Juspay, Pine Labs.
3. **Large NBFCs / superapps** — Bajaj Finance, Paytm, PhonePe.

Skip big banks for the *first* customers (long empanelment) — come back once you have logos.
Company-level targeting only; never scrape CISO emails (it undercuts the DPDP pitch).

---

## 5. Personas (from doc 05, still valid)

- **CTO / CISO at a Series A–C fintech** — asked by board/auditor for crypto documentation;
  doesn't know PQC deeply; needs something to show. Buys ₹1.5–4L without board sign-off.
  Lead with the auditor hook + a live scan of their domain.
- **Compliance Officer / Head of Risk** — knows regulation, not code; owns the audit
  relationship. Lead with audit-ready evidence + framework citations.
- **Security Engineer / DevSecOps** — not the buyer, but must be satisfied. Show the CLI,
  `seqr explain`, CI integration, and the migration path per finding.

---

## 6. The opener (SEBI-CSCRF version — use this)

> **Subject:** 2 of every 3 fintechs measure their PQC posture wrong
>
> Hi <name> — I research post-quantum readiness in Indian financial services. Measuring 60+
> fintech endpoints, I found passive scanners (the standard tool) report **0%** PQC while
> active probing shows **60%** — and that 60% is a CDN default, not real protection: certs are
> 100% classical and half of orgs expose an unprotected origin.
>
> SEBI CSCRF now asks for a cryptographic-asset inventory (CBOM). Most teams don't have one and
> the manual build is weeks. SeQr produces an accurate CBOM in minutes.
>
> Happy to share the research (no entity named) and run a free scan on <company>'s public
> surface. Worth 15 min?

Sequence: LinkedIn connect (no pitch) → share research → offer free scan → deliver scan + CBOM
PDF → book 15-min call. Under-promise; one free scan is the hook.

---

## 7. Positioning & differentiators

- Only tool combining **code + network** scanning with an **India-native** compliance map
  (PCI/SEBI/RBI/DST/DPDP).
- Priced for Indian mid-market (₹1.5–15L vs $100K+ Western PKI tools).
- **On-prem / air-gapped flagship** with offline Ed25519 licensing — the sovereignty play for
  RBI/SEBI/PSU/defence/CII. SaaS is the SMB funnel that feeds it.
- Research credibility: a founder who can explain quantum crypto in India, with measured data.

Competitive frame: *"AppViewX sells to the CISO at JPMorgan. SeQr sells to the CTO at Razorpay.
Different rooms entirely."* QNu Labs (QKD hardware) validates the market a tier above — not a
competitor. Potential partners: PQShield, ExeQuantum.

---

## 8. Pricing (see doc 05 for the full table)

- **CLI / Free** — entry point, community usage.
- **SaaS Professional** — full engine, cloud-hosted, auto-updates, AWS Mumbai.
- **Enterprise / On-Prem** — everything in SaaS **plus** air-gapped deploy, internal discovery,
  HSM/PKI/AD integration, HA/DR, RBAC, audit logging, compliance reporting, premium SLA.
  Priced higher for deployment/governance/scale — **not** for missing features.

Founding-customer motion: first 5 at a locked lifetime rate in exchange for testimonials.
Annual upfront preferred.

---

## 9. Content / build-in-public angles

Your unfair advantage: few people in India can explain quantum crypto credibly. Every post
positions you as *the* India PQC voice.

- "I scanned N Indian fintech domains — here's what I found" (aggregate).
- "What PCI DSS 12.3.3 and SEBI CSCRF actually require — and why you already need a CBOM."
- "Your 'post-quantum' TLS is a CDN mirage. Here's the measurement."
- "The origin bypass: half of fintechs expose a classical origin behind their CDN."
- Ship-log posts as the platform spine → discovery → migration engine get built.

Paper as marketing: on publication, post the measurement study, email DSCI/RBI/DST lists, pitch
YourStory/Inc42, submit to DSCI/NASSCOM/measurement venues.

---

## 10. What NOT to say (corrected inaccuracies)

- ❌ "7 months to file your CBOM with the DST Task Force" / "DST Phase 1 deadline Jan 1 2027."
  ✅ DST is recommendatory; a by-2027 inventory milestone. Lead with **PCI DSS + SEBI** (live).
- ❌ CNSA 2.0 in Indian compliance copy.
- ❌ "DPDP is in force now." ✅ §8 enforceable 2027-05-13.
- ❌ Naming another company's specific weakness in an email. ✅ Aggregate only.
