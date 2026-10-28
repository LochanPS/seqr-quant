# SeQr Competitive Analysis
### India-first mid-market PQC audit · No Western player serves this market

---

## 1. Market Position

SeQr occupies a specific niche: **India-native, software-only, mid-market PQC audit and
compliance tooling.** This niche is currently unoccupied.

The market has two populated segments:

**High-end (above SeQr):**
QNu Labs (Indian, hardware QKD), AppViewX (US, PKI management), QuSecure (US, large infra).
These serve government, defence, Tier-1 banks, and US enterprises. Deals are ₹1Cr+ or $100K+.
Sales cycles are 12-18 months. Require dedicated PKI teams.

**Entry-level (below SeQr):**
Open-source tools (sslyze, testssl.sh) — no compliance mapping, no CBOM, no Indian context.
Used by security engineers manually. No business output.

**SeQr's gap (₹1.5L–15L):**
No tool exists that:
- Combines code scanning + network scanning in one tool
- Maps to Indian regulations (DST/RBI/CERT-In/DPDP)
- Is priced for Indian mid-market
- Has on-prem Docker deployment (critical for data-sensitive Indian fintechs)
- Has developer-first CLI + API

---

## 2. Direct Scanner Competitors

### AppViewX AVX ONE

**What it is:** PKI lifecycle management and certificate automation platform.
**Market:** US and EU enterprise. CISO/PKI team audience.
**Pricing:** $100K+/year. Enterprise procurement. 12+ month sales cycle.
**What it does:** Certificate inventory, renewal automation, CA integration.
**What it does NOT do:** Code scanning, HNDL risk assessment, Indian compliance mapping,
developer CLI, on-prem Docker for SMBs.

**SeQr vs AppViewX:**
| | SeQr | AppViewX |
|---|---|---|
| Code scanning | ✅ AST, 30 patterns | ❌ |
| Network scanning | ✅ TLS + cert | ✅ |
| India compliance | ✅ DST/RBI/DPDP | ❌ US/EU only |
| Pricing | ₹1.5L–15L/year | $100K+/year |
| Deployment | On-prem Docker | SaaS / enterprise install |
| Sales cycle | 2 weeks | 12–18 months |
| Target customer | Indian Series A-C fintech CTO | JPMorgan PKI team |

**Conclusion:** Not competing. AppViewX sells to the PKI team at JPMorgan.
SeQr sells to the CTO at Razorpay. Different rooms entirely.

---

### QuSecure QuProtect

**What it is:** Post-quantum cryptography orchestration and migration platform.
**Market:** US large enterprise, government contractors.
**Pricing:** Large infra deals. Not publicly disclosed. Estimated $200K+.
**What it does:** Network-layer PQC migration, orchestration, intrusive deployment.
**What it does NOT do:** Code scanning, Indian compliance, self-serve, on-prem Docker SMB tier.

**SeQr vs QuSecure:**
QuSecure requires significant infrastructure deployment and a dedicated security team to
operate. It targets organisations that have already decided to migrate and have budget.
SeQr targets organisations that haven't started and need to understand what to migrate first.

**Conclusion:** QuSecure is a migration execution tool; SeQr is a discovery and planning tool.
Different phase of the migration journey. Could potentially be partners (SeQr discovers,
QuSecure executes) in large enterprise deals — but this is not a near-term concern.

---

### Keyfactor Command

**What it is:** Certificate lifecycle management and PKI administration platform.
**Market:** US and EU enterprises with existing PKI infrastructure.
**Pricing:** Enterprise pricing, not publicly disclosed.
**What it does:** PKI admin, certificate tracking, automated renewal.
**What it does NOT do:** AST code scanning, Indian regulatory mapping, developer CLI,
HNDL risk assessment, on-prem Docker for startups.

**SeQr vs Keyfactor:**
Keyfactor is a PKI administration tool for organisations with complex internal CA
infrastructure. SeQr is a cryptographic inventory tool for organisations that don't
have a PKI team and need to understand their quantum exposure quickly.

**Conclusion:** Not competing. Keyfactor is the tool you use AFTER you've decided to
migrate and have a PKI team. SeQr is the tool you use to understand IF and WHERE you need
to migrate.

---

## 3. Non-Competitors Often Mentioned in Conversations

### QNu Labs (India)

**What it is:** Indian company selling QKD (Quantum Key Distribution) hardware.
**Customers:** Indian Army, DRDO, NTPC, critical government infrastructure.
**DNA:** Hardware. Photonic quantum channels. Fibre deployment.
**Pricing:** ₹1Cr+ per deployment. Government procurement.

**Relationship to SeQr:** QNu Labs validates that the Indian quantum security market
exists and that Indian government entities take quantum security seriously.
QNu serves the tier ABOVE SeQr (government, defence, CII Tier 0).
SeQr fills the gap below QNu for commercial enterprises.

**Important:** QNu labs is NOT a competitor. Their customers are not SeQr's customers.
Their presence in the market is a positive signal.

---

### SandboxAQ

**What it is:** Alphabet spinout providing PQC consulting and enterprise software.
**Market:** Large global enterprises, US government contractors.
**DNA:** Consulting-first, enterprise software, quantum sensing + PQC combined.
**Pricing:** Enterprise deals. Not publicly disclosed.

**Relationship to SeQr:** SandboxAQ could theoretically enter Indian market but
has not. Their enterprise positioning and pricing means they target deals 10x SeQr's size.
Their existence validates the market globally.

**If asked in sales:** "SandboxAQ sells to Fortune 500 companies. We sell to Indian
Series A-C fintechs. Different market, different price point, different geography."

---

## 4. Potential Partners (Not Competitors)

### PQShield

**What it is:** UK-based PQC algorithm licensing and chip/firmware implementation company.
Founded by NIST competition participants. Deep mathematical expertise.
**Products:** PQC IP cores, hardware reference designs, algorithm licensing.
**Relationship:** Could validate SeQr's algorithm recommendations. Could co-market to
chip/firmware companies whose products SeQr's customers use.

### ExeQuantum

**What it is:** PQCaaS (Post-Quantum Cryptography as a Service) provider.
**Products:** ML-KEM/ML-DSA as managed API. Drop-in PQC key management.
**Relationship:** SeQr's pqcmap SDK could integrate with ExeQuantum's hosted KMS.
SeQr discovers the vulnerability; ExeQuantum provides the key management backend.

---

## 5. The Competitive Frame

```
AppViewX sells to the CISO at JPMorgan.
$300K deal. 18-month procurement. PKI team required.

SeQr sells to the CTO at Razorpay or Jupiter Money.
₹4L/year. 2-week sale. Docker deploy in an afternoon.
No PKI team required. No procurement committee.

These are not the same market. Not competing.
SeQr fills the gap no Western player has interest in.
```

The Indian mid-market (₹20Cr–₹500Cr ARR fintechs, NBFCs, healthtechs, insurtechs)
is too small for Western enterprise vendors and too sophisticated for manual open-source tools.
SeQr is the only purpose-built solution for this segment.

---

## 6. Global Market Context

### Why India Is the Right Starting Market

1. **Regulatory urgency is highest** — DST Task Force Phase 1 deadline (Jan 1, 2027) is
   the earliest mandatory CBOM requirement in any major economy.
   US federal: 2030. EU: 2030-2035. India CII: Jan 1, 2027.

2. **No incumbent** — No Western PQC vendor has built India-specific compliance mapping.
   No Indian software vendor has built a commercial PQC scanner.

3. **Market size** — 10,000+ Indian fintechs, NBFCs, healthtechs, insurtechs.
   Even 0.1% market penetration = 10 customers = ₹40L ARR.

4. **Founder advantage** — Deep quantum credentials (IBM Qiskit Advocate #116901),
   India's largest quantum community (Quantum Collective India, 600+ members).
   Trust is the primary sales barrier; this eliminates it.

5. **Research paper as moat** — No competitor has India-specific measurement data.
   When the paper publishes: SeQr becomes the credible category authority.
   "We scanned 400 Indian fintech domains and found 84% running quantum-vulnerable
   cryptography with 6 months to the DST Task Force CII deadline."
   No AppViewX case study competes with that.

### Second Wave: Indian IT Services with US Federal Contracts

After Indian mid-market is established:

**TCS, Infosys, Wipro, HCL, Tech Mahindra** all have US government contracts.
Their US federal clients now require NIST PQC compliance (EO 14144, CISA mandates).
These firms are:
- Indian (understand Indian pricing and vendor relationships)
- Already under pressure from US federal clients about PQC
- Would prefer an Indian vendor with on-prem deployment (data sovereignty)

This is SeQr's second-wave GTM, not the initial focus.
Entry point: SeQr's research paper gets cited in RBI / MeitY publications →
Infosys/TCS security leadership sees it → inbound inquiry.

### Global Expansion Timeline

- **Now:** India mid-market focus
- **Year 2 (post seed round):** EU geo module for Indian companies with EU operations
- **Year 3:** US geo module for Indian IT services with federal contracts
- **Year 4:** Direct EU/US market with regional sales

---

## 7. Why the Research Paper Is the Moat

The competitive paper is not the product. It's the measurement data.

When SeQr publishes "Cryptographic Posture of Indian Financial Services:
A Measurement Study of PQC Readiness":

1. **Category leadership** — We are the first to measure this. No competitor can claim
   they studied the Indian market before us.

2. **Media coverage** — "Indian student finds 84% of Indian fintech quantum-vulnerable"
   is a YourStory / Inc42 headline. This brings inbound customers.

3. **Regulatory relationship** — Citing DST Task Force data in a peer-reviewed paper
   published on arXiv creates a direct line to DSCI, RBI, and DST. They cite us.
   We get invited to panels. We become the reference point for Indian PQC policy.

4. **Sales tool** — Every cold outreach email can reference: "Our published research
   found that 84% of Indian fintech domains use RSA-2048 with no PQC migration plan.
   Is [Company] in the 16% or the 84%?"

5. **Defensibility** — Data has a timestamp. By the time a competitor runs a similar
   study, SeQr already has the canonical baseline dataset and the paper citation count.
   We own the India PQC measurement space.

No AppViewX case study competes with this. No QuSecure blog post competes with this.
The research paper is asymmetric leverage.
