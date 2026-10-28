# SeQr — Business, Sales, Marketing & Operations
### Complete Go-to-Market Playbook · SeQr Labs Pvt Ltd

> ⚠ **PARTLY STALE — corrected framing lives in [`MARKETING.md`](../MARKETING.md) and
> [`docs/09_Compliance_Frameworks.md`](09_Compliance_Frameworks.md).** This doc's original
> "DST Task Force / Jan 1 2027 filing deadline" language is **inaccurate** — DST is
> *recommendatory* (a by-2027 inventory milestone, not a statutory filing deadline). Lead with
> **PCI DSS 12.3.3 (live since 2025-03-31)** and **SEBI CSCRF (live since Jun 2025)** instead.
> The personas, pricing, competitors, outreach mechanics, and operations below remain valid.
> Last reconciled: 2026-07.

---

## Value Proposition

**Primary (SEBI CSCRF — live now):**
"SEBI CSCRF requires SEBI-regulated entities to inventory their cryptographic assets and
prioritise post-quantum migration. SeQr builds that CBOM in minutes."

**Primary (PCI DSS 12.3.3 — live now):**
"PCI DSS 12.3.3 has required a documented cryptographic inventory since 31 March 2025.
Your next QSA audit will ask for it. SeQr produces it instantly."

**Secondary (DST — recommendatory, forward-looking):**
"India's DST Task Force targets a cryptographic-asset inventory for critical infrastructure
(which includes BFSI) by 2027. Get ahead of it now — it is a milestone, not a filing deadline."

**Tertiary (DPDP financial framing):**
"Under DPDP Act 2023 Section 8, quantum-vulnerable encryption on PII endpoints
creates potential statutory liability of up to ₹250 Crore."

**Founder credibility anchor:**
"The US government estimated PQC migration will cost $7.1 billion because they started
too late with manual tracking. SeQr gives Indian enterprises an automated cryptographic
inventory in minutes — the one PCI DSS 12.3.3 and SEBI CSCRF already require — so you
don't repeat that mistake."

---

## Three User Personas

### Persona 1: CTO / CISO at Indian Series A-C Fintech

**Profile:** CTO or CISO at Indian fintech, NBFC, healthtech, or insurtech.
Company ARR: ₹20Cr–₹500Cr. Has PCI DSS obligations. Team of 5-30 engineers.
**Pain:** Gets asked by auditors and board for cryptographic security documentation.
Doesn't understand PQC deeply. Needs something to show.
**Trigger:** Auditor asks for cryptographic inventory. Board asks about "quantum risk."
DST Task Force requirement circulates on LinkedIn or in industry newsletter.
**Decision criteria:** Can I show this PDF to my auditor? Does it work on-premise?
How long does it take to deploy?
**Budget:** Has authority for ₹1.5L–4L security tool purchases without board approval.
**Sales approach:** Lead with DST Task Force deadline. Show PDF output immediately.
Demo on their domain. Offer founding customer pricing with urgency.

### Persona 2: Compliance Officer

**Profile:** Compliance officer, VP-Compliance, or Head of Risk at a bank, NBFC, or PA/PG.
Knows regulations deeply. Doesn't write code. Owns audit relationships.
**Pain:** RBI or DST Task Force audit is coming. Needs evidence files.
Doesn't know how to generate a cryptographic inventory. Engineers don't prioritise it.
**Trigger:** CERT-In advisory. RBI IT examination. DST Task Force circular.
Auditor explicitly requests "cryptographic posture documentation."
**Decision criteria:** Is this audit-ready documentation? Does it reference specific
DST Task Force / PCI DSS clause numbers? Can I download a PDF?
**Budget:** Shares budget with IT security. May need head of IT approval.
**Sales approach:** Lead with compliance evidence output. Show PDF with framework citations.
Offer to walk through the output with their auditor contact.

### Persona 3: Security Engineer

**Profile:** Senior security engineer or DevSecOps engineer at the same company.
Implements security tools. Evaluates the CLI. Runs the integrations.
**Pain:** Needs specific file/line findings. Needs to know exactly what to fix.
Wants CI/CD integration. Wants migration code examples.
**Trigger:** Their CISO/CTO just bought SeQr. Or they found the CLI on GitHub/PyPI.
**Decision criteria:** Are the findings accurate? Does it work in CI/CD without breaking
builds? Is there a clear migration path per finding?
**Budget:** Not the buyer. Influences the decision. Must be satisfied for deal to close.
**Sales approach:** Show CLI, `seqr explain`, `seqr migrate`. Show SARIF → GitHub Code Scanning.
Show `--fail-on IMMEDIATE` flag. Show pqcmap migration code.

---

## Company Setup

**Entity:** SeQr Labs Pvt Ltd (Private Limited Company)
- Not LLP — need equity for future hires/investors
- Registered address: Bengaluru (virtual office ₹3,000–6,000/year)
- Director: Lochan (DIN required — apply first)

**Registrations (in order):**
1. DPIIT Startup India — Free. Apply at startupindia.gov.in. Takes 2-4 weeks.
   Benefits: 3-year income tax exemption, GeM procurement, fast-track patent filing.
2. GSTIN — Required when billing starts. Register at gst.gov.in.
3. Trademark — File "SeQr" in Class 42. ₹4,500 for startup filing. Do this early.

**Banking:** HDFC or ICICI startup current account. Add Razorpay for receiving payments.

---

## Pricing (Current)

### On-Prem Docker (Primary Product)

**Trial:** Free — 5 assets. No credit card.

**Founding Customer (next 5, pre-launch):**
₹75,000/year — locked for life. All features. Named on website.
"Only 2 founding customer slots remaining" — urgency is real.

**Standard Pricing (post-launch):**

| Tier | Assets | Price/year |
|---|---|---|
| Small | 25 | ₹1,50,000 |
| Mid | 100 | ₹4,00,000 |
| Large | 500 | ₹8,00,000 |
| Enterprise | Unlimited | ₹15,00,000+ custom |

All tiers include: full CBOM, all scanners, all compliance frameworks (PCI DSS, DST, RBI, DPDP),
all report types, annual updates, email support.

**Payment terms:** Annual upfront preferred. Quarterly at +10%. No monthly.

**On-prem Docker:** Offline Ed25519 license validation. Zero data egress.
License format: `SQ-{TIER}-{base64_payload}.{ed25519_signature}`
Grace period: 30 days read-only after expiry.

### GitHub App (Acquisition + Secondary Revenue)
- Free: 3 repos, summary only
- Pro: ₹3,000/org/month — unlimited repos, full findings, dashboard sync
- DEFERRED — not building until after first paying customer

### SDK (pqcmap)
- Core: Free (MIT open source)
- Hosted KMS: ₹8,000/month
- Enterprise support: ₹30,000/month
- DEFERRED

### Gateway
- Starter (1 instance, ≤5 upstreams): ₹15,000/month
- Professional (3 instances): ₹40,000/month
- Enterprise: custom
- DEFERRED

---

## Financial Model

### Month-by-Month Revenue Targets

| Period | Target | Driver |
|---|---|---|
| Month 1-2 | ₹0 | 3 design partners (free) |
| Month 3 | ₹75,000 | 1 founding customer |
| Month 5 | ₹3,00,000 | 4 founding customers |
| Month 7 | ₹7,50,000 | Standard launch, 1 Small customer |
| Month 9 | ₹15,00,000 | 3 Small + 1 Mid customers |
| Month 12 | ₹30,00,000+ | 5 Small + 3 Mid + 1 Large |

### Unit Economics
- CAC target: < ₹20,000 (warm network, no paid ads)
- ACV average: ₹2,00,000 (blended Small + Mid)
- Payback period: < 2 months (annual upfront)
- Gross margin: ~85%

### Break-Even
Fixed costs ~₹23,000/month. Break-even at 5 founding customers (₹31,250/month).
Target: break-even by Month 5.

---

## Go-to-Market Sequence

### Phase 0 — Now: Customer Discovery (15 conversations needed)

**Before building more.** No product needed for these conversations.

**Target list:**
- Quantum Collective India members who work at fintechs — DM directly
- CTOs/founders met at CodeSapiens, Razorpay HQ, Magic Bond hackathons
- IISc and IIIT-B startup ecosystem connections
- Hatch platform users in fintech/healthtech

**Conversation script:**
"Hey [name], I'm doing research on quantum cryptography readiness in Indian startups
for a paper I'm writing. I know you work at [company]. Could I get 20 minutes to ask
a few questions about how your team handles cryptographic infrastructure?"

**Questions to ask:**
1. "Do you know which encryption algorithms your product uses?"
2. "Do you have a documented list of all your TLS certificates?"
3. "Has anyone in your company heard of PQC or post-quantum cryptography?"
4. "SEBI CSCRF / PCI DSS now expect a documented cryptographic inventory — if your auditor
    asked for one, who in your company would own producing it?"
5. "Would it be useful to have a tool that generates that inventory in 10 minutes?
    What would you pay for it?"

After 15 conversations: know the buyer's language, decision maker, which compliance
driver resonates (PCI DSS > DST > DPDP), real price anchors.

### Phase 1 (Months 1-3): 3 Design Partners

After discovery, identify 3 most engaged contacts.
Pitch: "I'm building a tool that automates exactly what we discussed.
Let me run it on your infrastructure for free for 3 months.
In exchange: weekly 30-minute feedback call, written testimonial."

### Phase 2 (Months 3-4): First Revenue

Convert 3 design partners to ₹75,000/year founding customers.
5 new outreach conversations/week in parallel.

### Phase 3 (Month 6): Public Announcement

Don't announce before this. Announce with proof.
"We actively measured 60+ Indian financial-services endpoints (paper + open data). Passive
scanners report 0% post-quantum; the real number is 60% — and it's a CDN mirage: certificates
stay 100% classical and half the firms expose an unprotected origin. 0% are end-to-end
quantum-safe. SEBI CSCRF and PCI DSS already require the inventory. [Founding customers] use SeQr."

**Launch channels:**
- LinkedIn post (personal + company)
- Quantum Collective India newsletter (600+ members)
- ProductHunt launch
- YourStory / Inc42 startup story pitch

---

## Outreach Templates

> **Note (2026-07):** lead with **research + the mirage**, then the live mandate (SEBI CSCRF /
> PCI DSS 12.3.3). Do **not** use DST "Jan 2027 deadline" language. See `MARKETING.md` §6 for the
> canonical opener; the templates below are corrected.

### Email Template 1 (cold CTO / CISO at a payment startup or brokerage)

```
Subject: 2 of every 3 fintechs measure their PQC posture wrong

Hi [Name],

I research post-quantum readiness in Indian financial services. Measuring 60+ fintech
endpoints, I found the standard (passive) scanners report 0% PQC while active probing
shows 60% — and that 60% is a CDN default, not real protection: certificates are 100%
classical and about half of orgs expose an unprotected origin behind the CDN.

SEBI CSCRF (live since Jun 2025) and PCI DSS 12.3.3 (mandatory since Mar 2025) both ask
for a cryptographic-asset inventory (CBOM). Most teams don't have one; the manual build is
weeks. SeQr produces an accurate CBOM in minutes.

I'm Lochan — IBM Qiskit Advocate #116901, founder of Quantum Collective India. Happy to
share the research (no company named) and run a free scan on [company]'s public surface.

Worth 15 minutes?

Lochan
[LinkedIn] | Quantum Collective India (600+ members)
```

### Email Template 2 (warm connection)

```
Subject: Quick question about your crypto inventory

Hey [Name],

Quick one: does [Company] have a cryptographic inventory (a CBOM)?
SEBI CSCRF now asks SEBI-regulated entities for it, and PCI DSS 12.3.3 has required one
since March 2025 — your next QSA audit will ask.

I built SeQr — it scans your infrastructure, finds every RSA/ECC dependency, and generates
the inventory + migration roadmap in minutes.

Free scan on your top 5 domains if you want to see what it finds.

Lochan
```

### LinkedIn DM

```
Hi [Name],

I research PQC readiness in Indian fintech — measured 60+ endpoints and found the
"post-quantum" most tools report is a CDN mirage (certs 100% classical, ~half expose a
classical origin).

SEBI CSCRF and PCI DSS 12.3.3 both now expect a cryptographic-asset inventory. SeQr builds
it in minutes. Happy to share the research + a free scan of your public domains. Worth it?
```

---

## Sales Call Structure (30 minutes)

**Minutes 0-5: Credibility**
"I'm Lochan. IBM Qiskit Advocate, ran India's largest quantum computing community
(600 members), published a study showing X% of Indian fintech uses quantum-vulnerable RSA.
That's why I built SeQr."

**Minutes 5-15: Discovery**
- "Do you know which encryption algorithms your product uses?"
- "Who owns your TLS certificate renewals?"
- "Has your auditor asked about quantum readiness or cryptographic inventories?"
- "What's your next QSA audit date?"

**Minutes 15-22: Demo**
Share screen. Show dashboard, CBOM, compliance gap report.
Best: scan their actual domain live. "Let me scan [their domain] right now — 60 seconds."
Their reaction does the selling.

**Minutes 22-27: Pricing**
"Based on your size, you'd be on the [tier] plan at ₹X/year. Since we're in early launch,
founding customer pricing is ₹75,000/year, locked for life. We have [2] slots left."

**Minutes 27-30: Next step**
Never leave without a clear next step. "I'll send the invoice by Thursday."

---

## Objection Handling

**"We'll think about it"**
"Who else needs to be involved? Can we get a 15-minute call with [decision maker] this week?"

**"No budget"**
"PCI DSS 12.3.3 is already enforceable. Your next QSA audit will ask for your cryptographic
inventory. When is your next audit? Would a one-time audit report at ₹60,000 work?"

**"Our infra is too sensitive"**
"That's exactly why SeQr is on-premise. The Docker container runs entirely inside your network.
No data ever leaves your perimeter."

**"We'll build this ourselves"**
"What's your timeline? Building a scanner covering code, TLS, and compliance mapping typically
takes 3-6 months for a focused engineer. At ₹1.5L/year, you break even in engineer-hours
within the first month."

**"Quantum computers aren't real yet"**
"Correct — large-scale quantum computers are years away. But the compliance requirement is
now: PCI DSS 12.3.3 (since Mar 2025) and SEBI CSCRF (since Jun 2025) both require a
cryptographic inventory today, and HNDL means encrypted data harvested now can be decrypted
later. The quantum threat is why the regulation exists — you're documenting for the audit,
not for a computer that arrives tomorrow."

---

## Content Marketing Strategy

### Your Unfair Advantage
You are one of very few people in India who can explain quantum cryptography credibly.
Every piece of content positions you as THE India PQC expert.

### LinkedIn (3x/week)
**Monday (educational):**
- "I scanned 10 Indian fintech domains. Here's what I found." [aggregate findings]
- "What PCI DSS 12.3.3 and SEBI CSCRF actually require — and why you already need a CBOM"
- "Your 'post-quantum' TLS is a CDN mirage. Here's the measurement."
- "The DPDP Act and quantum computing: a ₹250 Crore reason to care (from May 2027)"

**Wednesday (case study/progress):**
- "We just delivered the first CBOM for an Indian NBFC. Here's what we found."
- "3 months in: what design partners taught us about PQC migration"

**Friday (opinion):**
- "The inventory is already the deliverable — why PCI DSS + SEBI make PQC a today problem"
- "Competing with AppViewX as a 21-year-old Indian founder"

### The Research Paper as Marketing

When the preprint publishes:
1. LinkedIn post: "We published a measurement study of India's quantum-cryptographic
   readiness. Passive scanners report 0% PQC; active probing shows 60% — a CDN mirage.
   Certs 100% classical, ~half expose a classical origin, 0% end-to-end quantum-safe.
   PCI DSS + SEBI already require the inventory. [preprint link]"
2. Email DSCI, RBI, DST email lists
3. YourStory / Inc42 pitch: "Indian student measures the country's fintech quantum readiness —
   finds 0% are end-to-end quantum-safe, builds the tool to fix it." (they will cover this)
4. DSCI / NASSCOM conference submissions (empirical data = speaker credibility)
5. Cold email to RBI IT department and DST quantum cell

---

## Competitors (Summary)

**Not SeQr's competitors:**
- **QNu Labs:** QKD hardware, Indian Army, ₹1Cr+ deals. Hardware DNA. Government/CII tier.
  Validates the market exists. Not competing — serves the tier above.
- **AppViewX AVX ONE:** PKI management, US enterprise, $100K+, no code scanning,
  no India compliance. Not competing — different country, 10x price, 18-month sales cycle.
- **QuSecure QuProtect:** Large infra orchestration, expensive, intrusive.
  Not competing — US enterprise, requires dedicated security team.
- **Keyfactor Command:** Certificate lifecycle, PKI admin focused, no AST, no India mapping.
  Not competing — different buyer, different phase of migration journey.

**SeQr's real differentiators:**
1. Only tool combining code scanning + network scanning
2. Only India-native tool with DST/RBI/CERT-In/DPDP mapping
3. Priced for Indian mid-market (₹1.5L–15L vs $100K+)
4. Developer-first (CLI, API, SARIF output, future GitHub App)
5. On-prem Docker with offline Ed25519 license
6. DPDP Act ₹250 Crore framing (no Western tool has this)

**The competitive frame:**
"AppViewX sells to the CISO at JPMorgan. SeQr sells to the CTO at Razorpay.
Different rooms entirely."

**Potential partners (not competitors):**
- PQShield: algorithm licensing, could validate SeQr's recommendations
- ExeQuantum: PQCaaS, could integrate with pqcmap SDK for key management

---

## Global Expansion (Not Now — Later)

**First wave: Indian mid-market (now)**
10,000+ Indian fintechs, NBFCs, healthtechs, insurtechs.

**Second wave: Indian IT services with US federal contracts**
TCS, Infosys, Wipro, HCL, Tech Mahindra all have US government contracts.
Their US federal clients now require NIST PQC compliance (EO 14144, CISA mandates).
These firms are:
- Indian (understand Indian pricing and vendor relationships)
- Under pressure from US federal clients about PQC readiness
- Would prefer an Indian vendor with on-prem deployment (data sovereignty)
Entry point: After research paper → RBI/MeitY citation → Infosys/TCS security leadership inquiry.

**Third wave (post seed round):**
- EU geo module for Indian companies with EU operations (NIS2, DORA, GDPR Article 32)
- US geo module for Indian IT services (NIST FIPS, CISA, EO 14144)

---

## Sales Tracking (Notion CRM)

```
Database: SeQr Prospects

Key columns:
  Company, Contact, Role (CTO/CISO/IT Head/Compliance Officer)
  Sector (Fintech/NBFC/Healthtech/Insurtech/IT Services)
  Source (Quantum Collective/Hackathon/LinkedIn/Referral/Conference)
  Stage (Identified → Contacted → Discovery Call → Demo → Proposal → Closed Won/Lost)
  ACV Estimate, Health (Green/Amber/Red)
  DST Task Force awareness (Yes/No/Doesn't know)

Weekly review (Friday, 30 min):
  Update every contact, set next action, move stalled to Nurture.
```

---

## Investor Strategy

**Don't raise yet.** Reach ₹15L/month ARR with 5 customers first.
Raise after: 5 paying customers + ₹5L/month ARR + research paper published.

**When raising:**
- Target: ₹1-2Cr pre-seed (angel/micro-VC)
- Use: 1 full-stack developer hire, 1 sales hire, marketing budget
- Investors: Blume, BoldCap, Kalaari, 100X.VC, MeitY/DST grants (non-dilutive)

**Pitch story:**
"Quantum computers will eventually break RSA/ECC. PCI DSS 12.3.3 and SEBI CSCRF already
require Indian financial firms to inventory their cryptography — and India's DST roadmap
targets a CII crypto inventory by 2027. India has no native compliance tooling for this.
We built it, and our measurement study proves the market is unprepared (0% end-to-end
quantum-safe). [X] paying customers. ₹[Y] ARR. Founded by one of India's most credentialed
quantum-computing students."

---

## Deployment Model Decision Matrix

| Customer Type | Deployment | Reasoning |
|---|---|---|
| Series A-B fintech (30-100 employees) | Cloud SaaS (app.seqrlabs.com) | Low ops overhead, no DevOps team |
| NBFC / regulated fintech (200+ employees) | On-prem Docker | RBI compliance, data sovereignty, has IT team |
| Government / defence | On-prem Docker (air-gapped) | Strict data sovereignty |
| Individual developer / small startup | CLI + GitHub App | No budget, entry point |
| System integrator | White-label On-prem | Deploy to clients' environments |

---

## Operations

### Support Process
Response: 48h standard, 24h for paying customers, 4h for enterprise.
Channels: Email (standard), Slack (enterprise).
Common issues: Docker networking, license key problems, scan errors on internal hosts.

### Onboarding Process
- Day 0: Send license key + welcome email + docker-compose.prod.yml
- Day 1: 30-minute onboarding call (installation walkthrough)
- Day 7: Check-in email ("Did the first scan complete?")
- Day 30: Review call (walk through findings, answer questions)

### Legal Documents Needed
1. Terms of Service (authorized use only — customer owns assets being scanned)
2. Privacy Policy + Data Processing Agreement (all scan data stays on-prem OR in AWS ap-south-1)
3. License Agreement (annual, no redistribution, SeQr Labs Pvt Ltd retains IP)
4. NDA template (enterprise sales)

Cost: ₹15,000–30,000 for startup lawyer review of all four. Use AI templates first.

### Invoicing
Tool: Zoho Invoice (free tier) + Razorpay for payment.
Invoice prefix: SQ-2026-001 (sequential)
SAC Code: 998314 (IT consulting and support services)
GST: 18%
