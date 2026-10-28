# SeQr — Go-to-Market: Prospect Database & Outreach Playbook

**Private. Do not publish.** This is sales intelligence, not research.

## What's here

- `prospects.csv` — target *companies* (not people). 51 Indian financial-services orgs,
  ranked, with the regulator, the framework hook, and which **role** to approach.

## Why no personal contact details

We sell DPDP / privacy compliance. Scraping CISO names + emails is the exact personal-data
harvesting DPDP restricts — doing it undercuts the pitch and creates legal risk. So this DB
is **company-level**. Get the actual person the clean way:

1. LinkedIn search: `<company> CISO` / `Head of Information Security` / `CTO`.
2. Warm intro via mutual connections (strongest channel by far).
3. Company security/responsible-disclosure page (often lists a security contact).
4. Conference / community (Nullcon, c0c0n, OWASP India, BSides) — meet in person.

Never buy or scrape email lists.

## Who to target first (priority = HIGH)

1. **Brokerages (SEBI CSCRF).** Best beachhead — SEBI CSCRF is **live now** and explicitly
   names a cryptographic-asset inventory. The pain is current, not hypothetical. Groww,
   Zerodha, Angel One, Upstox, 5paisa, Dhan.
2. **Payment aggregators (RBI + PCI DSS 12.3.3).** PCI 12.3.3 inventory mandatory since
   Mar 2025. Razorpay, Cashfree, PayU, Juspay, Pine Labs.
3. **Large NBFCs / superapps.** Bajaj Finance, Paytm, PhonePe.

Skip big banks for *first* customers — long procurement, security-vendor empanelment.
Come back once you have logos.

## The opener (SEBI-CSCRF version)

> Subject: 2 of every 3 fintechs measure their PQC posture wrong
>
> Hi <name> — I research post-quantum readiness in Indian financial services. Measuring 60+
> fintech endpoints, I found passive scanners (the standard tool) report **0%** PQC while
> active probing shows **60%** — and that 60% is a CDN default, not real protection: certs
> are 100% classical and half of orgs expose an unprotected origin.
>
> SEBI CSCRF now asks for a cryptographic-asset inventory (CBOM). Most teams don't have one
> and the manual build is weeks. SeQr produces an accurate CBOM in minutes.
>
> Happy to share the research (no entity named) and run a free scan on <company>'s public
> surface. Worth 15 min?

Rules: lead with **research**, not the product. Findings **aggregate** (never name another
company's weakness in an email). Under-promise. One free scan as the hook.

## Sequence

1. Connect on LinkedIn (no pitch) → 2. Share research link (whitepaper / repo) →
3. Offer free scan → 4. Deliver scan + CBOM PDF → 5. Book the 15-min call.

## Columns in prospects.csv

`company, sector, regulator, domain, priority, target_role, framework_hook, notes`
