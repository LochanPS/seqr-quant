# Research Paper Specification
### "Cryptographic Posture of Indian Financial Services: A Measurement Study of PQC Readiness"
**Targets: arXiv (cs.CR) + INDOCRYPT 2026**

---

## Paper Overview

Type: Empirical measurement study (data-driven, not theoretical)
Novel contribution: First systematic scan of Indian fintech/NBFC cryptographic posture
Audience: Security researchers, Indian policymakers, DSCI, RBI, DST Task Force, CERT-In

**Core finding (hypothesis to validate):**
The majority of India's digital payment and lending infrastructure uses RSA/ECC algorithms
that will be broken by quantum computers, with no demonstrated migration toward NIST PQC
standards, despite mandatory regulatory timelines from DST Task Force (Jan 1, 2027 for CII)
and PCI DSS 12.3.3 (already enforceable).

**Secondary finding (DPDP angle):**
RSA-encrypted endpoints handling PII are quantum-vulnerable to HNDL attacks.
Under DPDP Act 2023 Section 8, this constitutes an inadequate security safeguard
for personal data, with potential statutory penalties up to ₹250 Crore.

---

## Target Venues (in order of preference)

1. **arXiv (cs.CR)** — Submit immediately when done. Establishes priority. Free.
   Cross-list: cs.NI (TLS measurement work fits here too)
2. **IACR ePrint** — Crypto-specific preprint. Submit same day as arXiv.
3. **INDOCRYPT 2026** — Indian cryptography conference. Check submission deadline.
4. **IEEE COMSNETS 2027** — Indian networking/systems conference.
5. Workshop on Quantum-Safe Internet @ IETF or IEEE QCE
6. DSCI Annual Information Security Summit — industry report version

For a 3rd year student: arXiv + INDOCRYPT is a realistic and credible path.
The paper's empirical nature makes it stronger than theoretical work for these venues.

---

## Methodology Constraints (must disclose in paper)

These are inherent limitations of passive TLS scanning. ALL must appear in Section 5
(Discussion → Limitations) and in the methodology disclosure:

**[M1] Hybrid PQC undercounting (sslyze limitation)**
sslyze cannot detect hybrid PQC (X25519Kyber768) without sending a Kyber-capable
ClientHello. Servers supporting hybrid PQC may appear as "not detected."
Therefore, actual PQC adoption is likely higher than our reported figures.
All hybrid PQC capable servers are labeled "not detected — sslyze passive-scan limitation."

**[M2] HNDL exposure is estimated, not measured**
HNDL exposure scores are derived from domain/path category and data-type endurance
heuristics, not from actual measured data retention policies of the scanned organisations.
Always labeled "estimated" or "assumed" in output and in paper.

**[M3] CDN-terminated results are LOW confidence**
TLS configuration of CDN-terminated domains belongs to the CDN provider (Cloudflare,
CloudFront, Akamai), not to the origin server. We cannot assess the origin server's
cryptographic configuration through CDN termination.

**[M4] Confidence labeling**
All findings labeled with scan_confidence:
- high: direct TLS connection (non-CDN IP)
- medium: cloud provider IP (AWS/GCP/Azure — likely CDN or reverse proxy)
- low: confirmed CDN provider IP

---

## Domain List Strategy

**crt.sh approach: failed**
Initial plan was to extract Indian fintech domains from crt.sh (Certificate Transparency
logs). This produced too many false positives (marketing subdomains, staging, etc.) and
required significant manual filtering.

**Final approach: Manual curated CSV**
`research/domains.csv` — 60+ Indian fintech domains manually curated from:
- NPCI UPI member list
- RBI NBFC and Payment Aggregator lists
- Top Indian fintech companies by transaction volume
- Manual curation of primary API/payment endpoints (not marketing sites)

**Column structure:**
```
entity_name, entity_type, primary_domain, secondary_domains, notes
```

**Entity types:** payment_gateway, nbfc, upi_app, bank, insurance, wealth_mgmt

---

## Scanner Version and Methodology Disclosure

**Tool used:** SeQr scanner v0.1.0 (`seqr-scanner` pip package)
**Scanning methodology:**
- sslyze 6.0 for TLS analysis
- cryptography (PyCA) 43.0 for certificate parsing
- Passive TLS handshake only — no active exploitation, no credential bypass
- Rate limited: 0.5 seconds between domain scans (ethical scanning)
- Scanned: port 443 only (public-facing TLS endpoints)
- NOT scanned: application-layer content, internal services, credentials, authentication

**Ethics statement for paper:**
"All scans were conducted on publicly accessible TLS endpoints. No authentication was
bypassed, no data was exfiltrated, and all scanning was performed at a rate equivalent to
a single normal client connection. Critically vulnerable entities were notified prior to
submission. Scan methodology is reproducible using the open-source SeQr scanner available
at [GitHub URL]."

---

## Expected Findings (from 5 Indian fintechs pre-scanned)

Pre-scan of 5 Indian fintech domains (before full dataset scan) reveals:

| Finding | Value |
|---|---|
| Quantum vulnerability level | Level 1 Classical (all 5) |
| CDN termination | All 5 CDN-terminated (CloudFront or Cloudflare) |
| Certificate algorithms | 4 RSA, 1 ECDSA |
| Hybrid PQC detected | 0 of 5 |
| Direct origin access | 0 of 5 (all CDN) |
| Scan confidence | Low (all 5 — CDN-terminated) |

**Implication for full dataset:** Expect majority of Indian fintech domains to be
CDN-terminated with classical TLS. Hybrid PQC adoption expected < 5%.
RSA-2048 remains dominant. ECDSA P-256 as minority. No ML-KEM detected.

**Hypothesis for full paper:** 80%+ of scanned domains will show quantum-vulnerable
TLS configuration. <2% will show any hybrid PQC capability. 0% will show native PQC.

---

## Paper Structure (8-12 pages, IEEE double column format)

### Abstract (150 words)
- India's payment infrastructure processes 13B+ UPI transactions/month
- Quantum computers running Shor's algorithm will break RSA/ECC by ~2030
- We scanned N Indian RBI-regulated entities and NPCI-registered services
- Found: X% use RSA-2048, Y% use ECC, Z% support TLS 1.3, <2% show hybrid PQC readiness
- DST Task Force Phase 1 deadline (Jan 1, 2027 for CII) mandates cryptographic inventory
- DPDP Act 2023 creates additional financial liability (up to ₹250 Crore) for
  organisations with quantum-vulnerable PII endpoints
- Provide recommendations and a migration priority framework

### 1. Introduction (1 page)
- Quantum threat: Shor's algorithm breaks RSA and ECC
- HNDL risk: adversaries collecting ciphertext today for future decryption
- Regulatory landscape: NIST FIPS 203/204/205 (Aug 2024), DST Task Force 2026 (Feb 2026),
  PCI DSS 12.3.3 (enforceable now), DPDP Act 2023 (Section 8)
- India-specific context: UPI processes 13B+ transactions/month, all protected by classical crypto
- Gap: no measurement study exists for Indian financial infrastructure
- Contribution: first empirical assessment, methodology, policy recommendations

### 2. Background (1 page)
- 2.1 Shor's Algorithm and Quantum Threat Timeline
- 2.2 NIST Post-Quantum Standardisation (FIPS 203/204/205 — August 2024)
- 2.3 Harvest-Now-Decrypt-Later (HNDL) Attacks
- 2.4 Regulatory Requirements (DST Task Force, PCI DSS 12.3.3, DPDP Act 2023)
  - Note: CNSA 2.0 not applicable to Indian private companies — not referenced
- 2.5 Related Work (TLS measurement studies for US/EU — none exist for India)

### 3. Methodology (1.5 pages)
- 3.1 Dataset Construction (crt.sh failure → manual CSV approach)
- 3.2 Scanning Methodology (sslyze, passive only, rate-limited)
- 3.3 Methodology Constraints (all 4 constraints from above — M1 through M4)
- 3.4 Classification Framework
  - Quantum-Vulnerable: RSA, ECDSA, ECDH, DH, DHE
  - Quantum-Safe: AES-256, SHA-256+, ML-KEM, ML-DSA
  - Deprecated (classically broken): RSA<1024, TLS 1.0/1.1, SHA-1
  - PQC-Ready: hybrid TLS (X25519Kyber768), ML-KEM
- 3.5 Compliance Mapping (PCI DSS 12.3.3, DST Task Force Phase 1, DPDP Act 2023)

### 4. Results (2-3 pages)
- 4.1 Dataset Overview (entity types, domain counts)
- 4.2 TLS Version Distribution
- 4.3 Certificate Algorithm Distribution (RSA-2048 vs RSA-4096 vs ECDSA vs other)
- 4.4 Key Exchange Algorithm Distribution
- 4.5 PQC Readiness Assessment (% hybrid PQC, % native PQC)
- 4.6 Certificate Expiry Analysis (% expiring before Jan 2027 deadline)
- 4.7 Compliance Gap Analysis (% failing PCI DSS 12.3.3, % failing DST Phase 1)
- 4.8 Sector Comparison (payment gateways vs NBFCs vs UPI apps vs banks)
- 4.9 HNDL Risk Assessment
- 4.10 DPDP Act exposure (% of PII endpoints with quantum-vulnerable encryption)

### 5. Discussion (1 page)
- 5.1 Key Findings Summary
- 5.2 India vs Global Comparison
- 5.3 Implications for DST Task Force Phase 1 deadline (Jan 1, 2027 for CII)
- 5.4 Implications for DPDP Act 2023
- 5.5 Limitations (all 4 methodology constraints — see Section 3.3)

### 6. Recommendations (0.5 page)
- 6.1 For entities: immediate TLS cert rotation, CBOM generation, migration roadmap
- 6.2 For DSCI: mandatory CBOM requirement by Phase 1 deadline
- 6.3 For RBI: include PQC readiness in IT examination criteria (Q-SAFE Committee)
- 6.4 For NPCI: mandate hybrid TLS for UPI app backends by 2027
- 6.5 For MeitY/DST: publish NTC Assurance Level criteria (L1-L4) by Dec 2026

### 7. Conclusion (0.25 page)

### References
Key citations (note: CNSA 2.0 excluded from Indian-context paper):
- NIST FIPS 203, 204, 205 (2024)
- India DST Task Force Report (February 2026)
- DPDP Act 2023 (Government of India)
- Shor's original paper (1994/1997)
- HNDL threat papers (Mosca et al.)
- TLS measurement studies (Holz et al., Felt et al.)
- PCI DSS v4.0 specification

---

## Research Scanner Code

Files at `research/`:
- `scan.py` — Fixed. Reads domains.csv, scans each domain with sslyze, outputs JSON
- `domains.csv` — 60+ Indian fintech domains. Ready to scan.
- `checkpoint.json` — Resume support (created on first run)
- `results_YYYYMMDD_HHMM.json` — Output file (created after scan)

**Rate limiting:** 0.5 seconds between domains (ethical scanning, avoids triggering WAF)
**Resume:** If scan interrupted, `checkpoint.json` tracks progress — re-run to resume

**Run:**
```bash
cd research
python scan.py
# Output: results_YYYYMMDD_HHMM.json
```

**Analysis:**
```bash
python analyse.py --input results_YYYYMMDD_HHMM.json --output figures/
# Produces: statistics dict + charts for paper
```

---

## Statistical Analysis

Tests to include:
1. Chi-square: algorithm distribution by entity type (payment gateway vs NBFC vs UPI)
2. Fisher's exact: PQC readiness vs entity type (small expected cell counts)
3. Wilson confidence intervals: for all percentage findings (95% CI)
4. Comparison with global baseline: Qualys SSL Labs Pulse for global TLS stats

Sample size: n=60+ domains. Report ±CI alongside all percentages.

---

## Timeline

```
Status:    Scanner ready. domains.csv ready. Run scan NOW.

Week 0:    Run research/scan.py on all 60+ domains
Week 1-2:  Run analysis/analyse.py. Compute stats. Generate charts.
Week 3-6:  Write paper. All sections as outlined above.
Week 7:    Internal review. Send to technical reviewer.
Week 8:    Submit to arXiv (cs.CR) + IACR ePrint on same day.
Week 9+:   Submit to INDOCRYPT if deadline permits.
```

**LinkedIn post on day of arXiv publication:**
```
"We just published the first measurement study of Indian financial services'
quantum cryptographic readiness. The headline: X% use RSA-2048 with 7 months
to the DST Task Force CII deadline.

DST Task Force Phase 1 deadline: Jan 1, 2027.
Your CBOM should be ready. Most companies don't have one.

arXiv: [link] | SeQr: [seqrlabs.com]"
```

---

## BibTeX Reference List

```bibtex
@article{shor1994,
  title={Algorithms for quantum computation: discrete logarithms and factoring},
  author={Shor, Peter W},
  booktitle={Proceedings 35th Annual Symposium on Foundations of Computer Science},
  pages={124--134},
  year={1994},
  publisher={IEEE}
}

@techreport{nist_fips203_2024,
  title={{FIPS} 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard},
  author={{National Institute of Standards and Technology}},
  institution={NIST},
  year={2024},
  month={August},
  url={https://doi.org/10.6028/NIST.FIPS.203}
}

@techreport{nist_fips204_2024,
  title={{FIPS} 204: Module-Lattice-Based Digital Signature Standard},
  author={{National Institute of Standards and Technology}},
  institution={NIST},
  year={2024},
  month={August},
  url={https://doi.org/10.6028/NIST.FIPS.204}
}

@techreport{nist_fips205_2024,
  title={{FIPS} 205: Stateless Hash-Based Digital Signature Standard},
  author={{National Institute of Standards and Technology}},
  institution={NIST},
  year={2024},
  month={August},
  url={https://doi.org/10.6028/NIST.FIPS.205}
}

@techreport{dst_taskforce_2026,
  title={Post-Quantum Cryptography Migration Roadmap for India},
  author={{Department of Science and Technology, Government of India}},
  institution={DST},
  year={2026},
  month={February}
}

@legislation{dpdp_2023,
  title={Digital Personal Data Protection Act 2023},
  author={{Government of India}},
  year={2023},
  note={Section 8: Obligations of Data Fiduciary}
}

@article{mosca2018,
  title={Cybersecurity in an era with quantum computers: will we be ready?},
  author={Mosca, Michele},
  journal={IEEE Security \& Privacy},
  volume={16},
  number={5},
  pages={38--41},
  year={2018},
  publisher={IEEE}
}

@techreport{pci_dss_v4_2022,
  title={Payment Card Industry Data Security Standard v4.0},
  author={{PCI Security Standards Council}},
  year={2022}
}

@misc{qualys_ssl_pulse,
  title={{SSL} Pulse: Survey of {SSL} implementation of most popular websites},
  author={{Qualys SSL Labs}},
  year={2024},
  note={Used as global baseline comparison}
}
```

---

## arXiv Submission Checklist

```
□ Category: cs.CR (cross-list: cs.NI)
□ Keywords: post-quantum cryptography, TLS, India, financial services, NIST PQC,
            measurement study, cryptographic agility, CBOM, DST Task Force
□ Author affiliations: ECE department, university name
□ Acknowledgements: Quantum Collective India, IBM Qiskit (if IBM resources used)
□ Abstract: 150-200 words, states methodology, key findings, conclusion
□ Methodology constraints: all 4 listed in Section 3 (M1-M4)
□ DPDP Act section: included in compliance analysis
□ CNSA 2.0: NOT referenced (US NSS only — not applicable)
□ Disclosure statement: included (passive scanning, no exploitation, notification sent)
□ License: CC BY 4.0
```
