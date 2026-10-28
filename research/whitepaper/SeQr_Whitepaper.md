# The Quantum-Vulnerable Enterprise: Measuring and Closing the Post-Quantum Gap in Indian Financial Services

### A SeQr Labs White Paper · 2026

---

## Executive Summary

Every RSA and elliptic-curve key protecting India's financial infrastructure today is
breakable by a sufficiently capable quantum computer, and an adversary does not need that
computer yet — under *harvest-now, decrypt-later* (HNDL), encrypted traffic captured today
is decryptable the moment such a machine exists. India's regulators have responded: PCI DSS
12.3.3, SEBI's Cybersecurity and Cyber Resilience Framework (CSCRF), the RBI Q-SAFE
committee, the DST quantum-safe roadmap, and the DPDP Act all now require organisations to
*know* and *migrate* their cryptography.

Yet almost no organisation knows where it stands — and, as our measurement study shows,
the standard way of finding out is **wrong**. Scanning 61 Indian fintech endpoints, we
found that **passive TLS measurement reports 0% post-quantum adoption while active probing
confirms 60%** — a 60-point blind spot in the tool every security team reaches for first.
That 60% turns out to be a content-delivery-edge default, not a migration: **100% of
certificates remain classically signed**, every directly-hosted origin is classical, and
**51% of organisations expose a non-CDN origin** that bypasses the protected edge entirely.

The conclusion is stark: Indian financial services look modern, are measured as either
"nothing" or "mostly safe" depending on the tool, and are in reality **end-to-end
quantum-vulnerable with zero cryptographic inventory**. This paper explains why, what the
regulations actually demand, and how SeQr produces an accurate, audit-ready Cryptographic
Bill of Materials (CBOM) in minutes.

---

## 1. The Threat: Why Classical Cryptography Has an Expiry Date

Public-key cryptography secures every TLS handshake, every API token, every signed
certificate. Its security rests on two hard problems — integer factorisation (RSA) and the
discrete logarithm (ECC/Diffie-Hellman). **Shor's algorithm solves both efficiently on a
quantum computer**, collapsing RSA-2048 and ECDSA-P256 from "infeasible" to "minutes."

A cryptographically relevant quantum computer (CRQC) does not exist today. The danger is
not future — it is **retroactive**. An adversary recording ciphertext now (the
**harvest-now, decrypt-later** model) decrypts it later. Any data whose confidentiality
must outlive the CRQC — financial records, KYC, health data, long-lived keys — is exposed
**today**. NIST finalised the replacements in August 2024: **ML-KEM** (FIPS 203) for key
exchange, **ML-DSA** and **SLH-DSA** (FIPS 204/205) for signatures.

---

## 2. The Mandate: India's Regulatory Clock Has Started

| Framework | What it requires | Status |
|---|---|---|
| **PCI DSS 12.3.3** | Documented cryptographic inventory, reviewed annually | **Mandatory since 31 Mar 2025** |
| **SEBI CSCRF** | Regulated entities: inventory all cryptographic assets, prioritise PQC migration by risk | **Live since Jun 2025** |
| **RBI Q-SAFE** | Financial-sector CBOM + crypto-agility review | Committee formed May 2026; framework ~Nov 2026 |
| **DST Task Force** | Cryptographic-asset inventory for critical infrastructure (incl. BFSI) | **By 2027** (recommendatory; sectoral regulators enforce) |
| **DPDP Act 2023 §8** | "Reasonable security safeguards" for personal data; penalties to ₹250 cr | Enforceable **13 May 2027** |

The common denominator across every one of these is a **cryptographic inventory** — a
Cryptographic Bill of Materials (CBOM). It is the first deliverable each framework asks
for, and the one almost no organisation has. Building one by hand is weeks of spreadsheet
archaeology across certificates, code, and infrastructure.

---

## 3. The Measurement Problem: Your Scanner Is Lying to You

Security teams measure cryptographic posture with passive TLS scanners (sslyze, testssl,
SSL Labs). These connect, observe what the server *advertises*, and report. For classical
TLS this is fine. **For post-quantum cryptography it fails silently.**

A hybrid PQC key exchange (e.g. X25519MLKEM768) is only negotiated if the *client* offers
an ML-KEM-capable ClientHello. A passive scanner using a normal client never offers one —
so it never sees the server's PQC support, and reports **0%**. The capability is there; the
measurement misses it.

**SeQr's approach: active probing.** SeQr sends an ML-KEM-capable ClientHello (via OpenSSL
3.5+, which ships the standardised groups) and reads the *negotiated* group. This is the
difference between "we think you have no PQC" and the truth.

We validated this empirically (full study: [seqr-labs-research](https://github.com/LochanPS/seqr-labs-research)):

| Measurement of Indian fintech key exchange | Hybrid PQC | 95% CI |
|---|---|---|
| **Passive (industry standard)** | **0 / 53 (0%)** | 0–7 |
| **Active (SeQr ML-KEM probe)** | **32 / 53 (60%)** | 47–72 |

---

## 4. The Findings: Modern on the Surface, Vulnerable Underneath

Across 61 Indian payment gateways, brokerages, NBFCs, and UPI apps (and a 24-endpoint
international comparison set):

1. **Transport is modern.** TLS 1.3 on ~87%; zero legacy TLS. Good hygiene — and
   misleading, because it has nothing to do with quantum readiness.
2. **Authentication is 100% classical.** Every certificate is RSA or ECDSA. No PQC
   signature anywhere. Certificates are quantum-forgeable.
3. **PQC is an edge mirage.** The 60% hybrid PQC is a CDN default: CloudFront 95%,
   Cloudflare 88%, **direct origins 0%**. No organisation in the corpus deliberately
   migrated; they inherited it.
4. **The edge is bypassable.** **51% of organisations expose a non-CDN origin**
   (`api.`, `dev.`, `sftp.` on direct cloud IPs) outside the protected edge — and those
   origins are classical. Edge PQC you can route around is not protection.
5. **Forward-secrecy gaps.** ~9% use static RSA key exchange — no forward secrecy at all,
   the most exposed configuration, exploitable independent of quantum.

**Net result: no measured endpoint is end-to-end quantum-safe, and none has a CBOM.**

---

## 5. Why This Matters: Edge PQC Is Not Compliance

An organisation told "you have 60% PQC" by a CDN dashboard may believe it is ahead. It is
not. Edge hybrid PQC protects only the client↔edge hop. It does **not**:

- protect the edge↔origin hop, or the exposed origin directly;
- make certificate authentication quantum-safe (signatures remain forgeable);
- constitute the cryptographic inventory PCI DSS / SEBI / DST require;
- address data-sovereignty (TLS terminates at a foreign-operated edge — a DPDP concern).

The gap between *advertised edge PQC* and *actual end-to-end posture* is precisely where
compliance risk and quantum risk both live.

---

## 6. The SeQr Approach

SeQr is built to measure cryptographic posture *accurately* and turn it into the inventory
regulators demand.

- **Active PQC detection.** Real ML-KEM ClientHello probing — measures what passive tools
  miss (§3).
- **Multi-protocol coverage.** Not just web TLS: SSH key exchange and host keys, mail
  STARTTLS (SMTP/IMAP/POP3), and database TLS (PostgreSQL) — the real cryptographic
  surface, not one port.
- **Origin discovery.** For CDN-fronted assets, SeQr discovers and flags exposed origins,
  so edge PQC is never mistaken for end-to-end safety.
- **Cryptographic Bill of Materials.** Every finding aggregates into a **CycloneDX 1.6
  CBOM** — machine-readable, ingestible into GRC/security tooling, and the exact artifact
  PCI DSS 12.3.3 and SEBI CSCRF ask for. One scan, minutes, not weeks.
- **India-first compliance mapping.** Findings map to PCI DSS 12.3.3, SEBI CSCRF, RBI
  Q-SAFE, the DST roadmap, and DPDP §8 — with accurate dates and enforcement framing, not
  US-centric boilerplate. (CNSA 2.0 is deliberately excluded as inapplicable to Indian
  private entities.)
- **Strength-tiered, actionable remediation.** Each vulnerable algorithm maps to the
  correct FIPS replacement (e.g. RSA-4096 → ML-KEM-1024 / ML-DSA-87), with CDN-specific and
  origin-specific guidance.
- **Free CLI to PRO SaaS.** A free, open CLI scans web/SSH/mail passively; the PRO platform
  adds active PQC, the CBOM, compliance evidence, history, and audit-grade PDF reports.

---

## 7. From Measurement to Migration

1. **Inventory (now).** Generate a CBOM. This alone satisfies the core PCI DSS 12.3.3 /
   SEBI CSCRF control and gives you a baseline.
2. **Prioritise.** Rank by risk: HNDL-exposed long-lived-data endpoints, static-RSA
   (no forward secrecy), and exposed classical origins first.
3. **Migrate authentication and origin.** Plan ML-DSA certificates and ML-KEM at the origin
   — the layers edge PQC does not cover.
4. **Maintain agility.** Keep the CBOM current; PQC standards and CDN defaults evolve. A
   standing inventory turns each future audit from weeks into minutes.

---

## 8. Conclusion

Indian financial services are measured as quantum-ready by the very tools meant to assess
them, and are in fact quantum-vulnerable end-to-end with no cryptographic inventory. The
regulatory deadlines are not hypothetical — PCI DSS and SEBI are live today; DST 2027 and
DPDP 2027 are next. The first, mandatory, and most-deferred step in every framework is a
CBOM. SeQr produces an accurate one — measuring what passive tools miss — in minutes.

*SeQr Labs — post-quantum cryptography compliance for Indian financial services.
`seqrlabs.com`*
