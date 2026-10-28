# SeQr Compliance Framework Reference
### Active in product · Excluded · Global future modules

> **Accuracy is a product requirement.** SeQr is sold as compliance evidence, so
> every date/mandate below is tied to a primary government or standards source.
> **Last source-verified: 2026-06-21.** Re-verify before each release — this space
> moves fast (RBI Q-SAFE report ~Nov 2026; DPDP Phase III 2027-05-13; DST
> procurement mandate FY2027-28). Engine source of truth:
> `shared-scanner/engines/compliance.py` (mirrored to `cli/seqr/_scanner/`).
>
> **Two correctness rules learned the hard way:**
> 1. The DST Task Force roadmap is **recommendatory**, not a statute — never call
>    "Jan 1 2027" a hard CBOM *filing* deadline. It is a *by-2027* inventory milestone.
> 2. DPDP Act §8 + ₹250 Cr penalties are **enforceable 2027-05-13**, NOT "in force
>    now." Never present DPDP as a current live penalty.

---

## 1. India Frameworks (Active in Product)

### PCI DSS 12.3.3

**What it is:** Payment Card Industry Data Security Standard, requirement 12.3.3.
Requires organisations to maintain a documented inventory of all cryptographic
cipher suites and protocols in use, and to have a plan for responding to
cryptographic failures.

**Status in SeQr:** ✅ ACTIVE — SeQr directly provides PCI DSS 12.3.3 compliance evidence.

**Pass/Fail logic:**
- PASS: Org has completed at least one scan and has a CBOM on record
- FAIL: No CBOM exists (first scan not yet completed) OR any RSA/ECC in payment API scope
- PARTIAL: CBOM exists but migration plan not documented

**Mandate:** Mandatory since **March 31, 2025** (was best-practice before that date).
Every QSA assessment from March 31, 2025 forward can ask for the cryptographic inventory.
Source: PCI SSC, PCI DSS v4.0.1, Requirement 12.3.3.

**SeQr's value:** The CBOM export IS the cryptographic inventory required by 12.3.3.
One scan = compliance evidence. No manual work.

**Output language:**
```
PCI DSS 12.3.3: PASS ✓
  Cryptographic inventory documented: 47 components
  Last updated: 2026-06-15
  Assessment evidence: Download CBOM PDF
```

---

### NIST FIPS 203/204/205

**What it is:**
- FIPS 203 (ML-KEM): Module-Lattice Key Encapsulation Mechanism — replaces RSA/ECDH key exchange
- FIPS 204 (ML-DSA): Module-Lattice Digital Signature — replaces RSA-sign / ECDSA
- FIPS 205 (SLH-DSA): Stateless Hash-Based Digital Signature — backup algorithm

**Status in SeQr:** Reference standard only. Not a mandate for Indian private companies.

**How to surface:** Label recommendations as "FIPS 203/204/205" for technical credibility.
Do not frame as compliance requirement. Use language: "Begin migration planning."

**Important:** FIPS 203/204/205 are US federal procurement standards. Indian private
companies are not required to comply. Show as "global best practice" only.

---

### SEBI CSCRF — PQC Migration  ⭐ strongest live hook

**What it is:** SEBI's Cybersecurity & Cyber Resilience Framework (CSCRF), circular
20 Aug 2024, with a **Post-Quantum Cryptography migration expectation added June 2025**.
It requires SEBI Regulated Entities to inventory ALL cryptographic assets (keys,
certificates, algorithms) and prioritise PQC migration by risk, criticality, and data
sensitivity.

**Status in SeQr:** ✅ ACTIVE — and **already binding now** (unlike DST, which is 2027).
This is the single strongest "you must do this today" hook for capital-markets fintech.

**Who it binds:** SEBI REs — stock exchanges, clearing corps, depositories, brokers,
mutual funds / AMCs, RTAs, credit rating agencies, portfolio managers.

**SeQr's value:** The crypto-asset inventory + risk-based PQC prioritisation the CSCRF
asks for *is the SeQr CBOM*. (Note: SEBI mandates SBOM for critical systems and expects
a cryptographic inventory; it has not yet *named* "CBOM" explicitly — don't claim it has.)

**Pass/Fail logic:**
- PASS: inventory current, no quantum-vulnerable components
- PARTIAL: inventory exists (control satisfied) but quantum-vulnerable components remain to prioritise
- FAIL: no inventory on record

**Source:** SEBI CSCRF circular (Aug 2024) + PQC migration update (Jun 2025).

---

### DST Task Force — Quantum-Safe Ecosystem

**What it is:** DST report "Implementation of Quantum Safe Ecosystem in India" (published
**4 Feb 2026**, chair Dr. Rajkumar Upadhyay, C-DOT). India's national PQC migration roadmap.

**Status in SeQr:** ✅ ACTIVE urgency driver — but framed accurately (see below).

**⚠ It is RECOMMENDATORY, not a statute.** It is a Task Force *report*. Statutory
enforcement rests with sectoral regulators (RBI, SEBI, DoT). Do **not** describe
"Jan 1 2027" as a hard CBOM *filing* deadline — there is no such filing portal or date in
the source. The real anchor is a *cryptographic-asset inventory by 2027 for CII*.

**Milestone table (as written in the source — year-level, not calendar-day):**

| Milestone | Who | Requirement |
|---|---|---|
| By 2027 | CII | Build foundations: governance + **cryptographic-asset inventory** |
| By 2028 | CII | High-priority systems migrated to PQC/hybrid |
| By 2029 | CII | Full quantum-safe implementation |
| FY 2027-28 | Govt procurement | CBOM required in procurement |
| By ~2033 | All enterprises | Broad nationwide PQC adoption |

**CII includes BFSI.** Per NCIIPC (IT Act s.70A), Critical Information Infrastructure
explicitly includes Banking, Financial Services and Insurance — so banks/NBFCs/insurers
are in scope. (Individual entities are *notified* as CII; not every small fintech is
auto-designated.) The report's headline examples were defence/power/telecom/space, but
BFSI is a listed critical sector.

**SeQr's value:** SeQr builds the cryptographic-asset inventory the 2027 milestone
requires. Honest message: "India's quantum-readiness milestone targets a cryptographic
inventory for critical infrastructure by 2027 — SeQr builds it in minutes."

**Pass/Fail logic:**
- PASS: CBOM exists and is current (< 180 days old)
- FAIL: no CBOM or stale
- Show 2027 milestone countdown as motivation — label it a "milestone," not a "deadline"

**Source:** DST, "Implementation of Quantum Safe Ecosystem in India — Report of the Task
Force," 4 Feb 2026.

---

### RBI — Q-SAFE Committee

**What it is:** RBI's **Q-SAFE Expert Committee** ("Quantum Secure and Adaptive Financial
Ecosystem"), constituted **25 May 2026**, convener **Dr. Anil Prabhakar (IIT Madras)**.
Tasked with reviewing financial-sector cryptographic infrastructure via **CBOM** and
**crypto-agility** assessment, and producing a framework.

**Status in SeQr:** 🔵 MONITOR (emerging) — directly governs your core customers (banks/
NBFCs) and its mandate is almost verbatim the SeQr product.

**Current state (as of June 2026):**
- Committee formed May 2026; framework expected ~**Nov 2026** (6-month brief)
- Explicitly references CBOM + crypto-agility — strong tailwind for SeQr
- No mandatory PQC migration deadline for banks/NBFCs *yet* — pending the report

**How to surface:** "MONITOR — RBI Q-SAFE framework expected ~Nov 2026." Do not show as
FAIL. Use it as a near-term reason to have a standing CBOM ready before guidance lands.

**Output language:**
```
RBI Q-SAFE: MONITOR
  Committee formed: May 2026 (chair: Dr. Anil Prabhakar, IIT Madras)
  Framework expected: ~Nov 2026
  Recommendation: Maintain a current CBOM to be audit-ready when guidance lands
```

**Source:** RBI press release, 25 May 2026.

---

### CERT-In

**What it is:** Indian Computer Emergency Response Team. National cybersecurity authority
under MeitY. Publishes guidelines, advisories, and incident response mandates.

**Status in SeQr:** 🔵 MONITOR — but **claim with care**.

**⚠ Accuracy note (2026-06):** No CERT-In-specific PQC/quantum-readiness advisory,
circular, or guideline could be located in public sources. **Do not assert "CERT-In
national quantum readiness guidelines" as fact** — that claim has no verified citation.
The HNDL assessment rationale is grounded in *global* guidance (CISA/NIST/NCSC) instead.

**Current state:**
- CERT-In's 6-hour breach-reporting mandate (2022) exists but is unrelated to PQC
- No confirmed CERT-In PQC advisory as of June 2026

**How to surface:** "MONITOR — no CERT-In PQC advisory confirmed; HNDL framing per global
guidance (CISA/NIST)." If you later find a real CERT-In document, cite it here.

**Output language:**
```
CERT-In: MONITOR
  PQC advisory: none confirmed as of 2026-06
  HNDL rationale: global guidance (CISA/NIST/NCSC)
```

---

### DPDP Act 2023

**What it is:** Digital Personal Data Protection Act 2023. India's national data protection
law. Section 8 requires data fiduciaries to implement "reasonable security safeguards"
(Rule 6 of the DPDP Rules 2025 lists encryption among the minimum measures).

**Status in SeQr:** 🔵 FUTURE-DATED — relevant, but **not yet enforceable**.

**⚠ Enforcement date:** The Act is passed, but s.8 obligations and the Schedule-1 penalty
schedule become **enforceable 2027-05-13** (DPDP Rules 2025 notified 13 Nov 2025; Phase III
= 18 months later). **Never present DPDP as "in force now" or as a current live penalty.**

**Penalty (from 2027-05-13):** up to ₹250 Crore per the penalty schedule.

**Connection to PQC:** An RSA-encrypted endpoint handling PII data is quantum-vulnerable.
A quantum computer can decrypt historical traffic. This = potential DPDP violation.
HNDL attack on PII endpoint = data breach under DPDP Act.

**When to apply:** Any finding at a URL path that handles user data:
- `/auth`, `/login`, `/register`, `/profile`, `/account`, `/user`, `/kyc`
- `/payment`, `/checkout`, `/health`, `/medical`, `/records`
- Any path flagged as data_sensitivity=confidential or highly_confidential

**Mandatory output language in all PDFs (note the future tense):**
```
From 13 May 2027, under Section 8 of DPDP Act 2023, failure to protect PII against
interception may risk statutory penalties up to ₹250 Crore (DPDP Rules 2025, Phase III).
```

**Output in compliance matrix:**
```
DPDP Act 2023 § 8: MONITOR (enforceable 2027-05-13)
  PII endpoints with quantum-vulnerable encryption: 3
  Potential liability (from 2027-05-13): up to ₹250 Crore
  Recommendation: Prioritise migration of /auth, /profile, /kyc endpoints before enforcement
```

---

## 2. Excluded Frameworks

### CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)

**Why excluded:** CNSA 2.0 is a US National Security Agency mandate for US National
Security Systems (NSS). It is NOT applicable to Indian private companies.

**Do not show:** In any Indian compliance output, audit report, CLI output, or PDF.
CNSA 2.0 appearing in an Indian NBFC's compliance report = incorrect, confusing,
and potentially embarrassing in an audit context.

**Exception:** Only reference CNSA 2.0 if a customer specifically has US government
contracts and asks about US compliance requirements. Even then, label as
"US NSS-specific — not applicable to Indian private sector operations."

---

## 3. Global Frameworks (Future Geo Modules — Not Active Yet)

These frameworks are available via `GET /risk/compliance?geo=eu` or `?geo=us`
in v2 of the scanner. Not in current product. Reference only.

### European Union

**NIS2 Directive**
- Scope: Critical infrastructure, cloud providers, digital services
- Deadline: National roadmaps finalized Dec 2026
- PQC requirement: Critical assets must be PQC by Dec 2030; full market by Dec 2035

**DORA (Digital Operational Resilience Act)**
- Scope: Financial entities (banks, insurers, payment processors) in EU
- Applies to: Indian banks operating in EU (HDFC, ICICI, SBI Europe branches)
- PQC timeline: Aligned with NIS2 (2030 critical, 2035 full)

**GDPR Article 32**
- "Appropriate technical measures" for personal data security
- Quantum-vulnerable encryption on EU personal data = potential Article 32 violation
- Analogous to DPDP Act 2023 in Indian context

### United States

**NIST Post-Quantum Cryptography**
- FIPS 203/204/205 finalized August 2024
- Federal agencies: mandatory PQC for new systems from 2025-2026

**CISA Post-Quantum Cryptography**
- 2025-2026: Federal inventory ACTIVE NOW
- 2030: High-priority systems must be PQC
- 2035: Hard deadline — all federal systems PQC

**Executive Order 14144 (Jan 2025)**
- Requires federal agencies to complete cryptographic inventories
- Establishes NSM-10 compliance requirements for federal contractors
- Relevant for Indian IT services companies with US federal contracts (TCS, Infosys, Wipro)

### United Kingdom

**NCSC Post-Quantum Migration Timeline**
- 2028: Discovery and planning complete for critical systems
- 2031: High-priority systems migrated
- 2035: Full migration complete

### Canada

**ITSM.40.001 — Post-Quantum Cryptography for Government of Canada**
- April 2026: Migration plans submitted by all government departments
- 2035: Full migration complete

---

## 4. National Testing Lab Assurance Levels (NTC)

**TEC/STQC/BIS Assurance Levels L1–L4**

TEC (Telecommunications Engineering Centre), STQC (Standardisation Testing and
Quality Certification), and BIS (Bureau of Indian Standards) are jointly developing
PQC assurance levels L1–L4 for the Indian market. Expected publication: December 2026.

**Current status: DO NOT IMPLEMENT.**
Official L1-L4 criteria are not yet published. Implementing based on speculation
risks non-compliance with the final spec.

**Future field:** When official criteria publish, add `pqc_assurance_level_target`
field to CBOM output and compliance reports.

**Watch:** tec.gov.in, stqc.gov.in, bis.gov.in

---

## 5. Compliance Output Format

### Dashboard compliance matrix format:
```
Framework          | Status      | Key date            | Action
──────────────────────────────────────────────────────────────────────
PCI DSS 12.3.3    | ✅ PASS     | Mandatory 2025-03-31 | CBOM documented ✓
SEBI CSCRF        | ⚠ PARTIAL  | Live (Jun 2025)      | Prioritise 3 vuln components
RBI Q-SAFE        | 🔵 MONITOR | Framework ~Nov 2026  | Keep CBOM current
DST Task Force    | ⚠ ACTION   | CII inventory by 2027 | CBOM current ✓
DPDP Act 2023     | 🔵 MONITOR | Enforceable 2027-05-13 | Migrate PII endpoints first
CERT-In           | 🔵 MONITOR | None confirmed       | HNDL per global guidance
```

### Rules:
- PCI DSS + SEBI CSCRF are the **live "must do now"** hooks — lead with these
- DST 2027: show countdown as a **milestone**, never label it a hard "filing deadline"
- DPDP Act: show as MONITOR with the **2027-05-13** enforcement date; never "in force now"
- RBI Q-SAFE / CERT-In: always MONITOR, never FAIL
- CNSA 2.0: never show
- Staleness: if CBOM > 180 days old, show "STALE" warning on DST/SEBI status
