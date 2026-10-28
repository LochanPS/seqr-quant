TITLE: SEBI CSCRF now expects a cryptographic inventory. Most fintechs don't have one.
SLUG: sebi-cscrf-cryptographic-inventory
EXCERPT: PCI DSS 12.3.3 and SEBI's CSCRF both now ask regulated entities for a cryptographic bill of materials. Here's what that is, why it's suddenly urgent, and how to produce one.
TAGS: SEBI, CSCRF, compliance, CBOM, PCI DSS
STATUS: draft

---

Two mandates that are **live today** in Indian financial services quietly ask for the same
deliverable, and it's the one most teams don't have.

- **PCI DSS v4.0.1, Requirement 12.3.3** — mandatory since 31 March 2025 — requires a
  documented inventory of your cryptography, reviewed annually.
- **SEBI's Cybersecurity and Cyber Resilience Framework (CSCRF)** — live since June 2025 —
  expects regulated entities to inventory cryptographic assets and prioritise post-quantum
  migration by risk.

And the next wave is dated, not hypothetical: the RBI's Q-SAFE committee framework is
expected around late 2026, the DST's quantum-safe roadmap targets a cryptographic-asset
inventory for critical infrastructure (which includes BFSI) by 2027, and the DPDP Act's
security-safeguard penalties become enforceable in May 2027.

## The common denominator: a CBOM

Every one of those frameworks asks, first, for a **Cryptographic Bill of Materials** — a
machine-readable inventory of every algorithm, certificate, and key exchange across your
infrastructure, with its quantum-risk classification. It's the foundational control:
before you can migrate, you have to know what you have.

Almost nobody has one. Building it by hand is weeks of spreadsheet archaeology across
certificates, TLS endpoints, SSH hosts, mail servers, databases, and code — and it's stale
the moment you finish.

## Why "we use TLS 1.3" isn't an answer

Modern transport (TLS 1.3, no legacy protocols) is good hygiene and has **nothing to do
with quantum readiness**. Under TLS 1.3 your key exchange is still X25519 or ECDHE
(quantum-vulnerable), and your certificate is still RSA or ECDSA (quantum-forgeable). An
auditor asking for your cryptographic inventory won't accept "we're on 1.3."

Nor is edge hybrid PQC from your CDN enough: it protects the client-to-edge hop only, not
your certificates, your origin servers, or the compliance inventory itself.

## Producing a CBOM in minutes

SeQr scans your web/TLS, SSH, mail, and database endpoints, actively confirms real
post-quantum support (not the passive guess), and aggregates everything into a **CycloneDX
1.6 CBOM** — the exact artifact PCI DSS 12.3.3 and SEBI CSCRF ask for — mapped to each
Indian framework with accurate dates. One scan, an audit-ready PDF and machine-readable
inventory, minutes instead of weeks.

*Start free: `pip install seqr`. Or run a scan of your public surface at seqrlabs.com.*
