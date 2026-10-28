# SeQr Scanner Technical Roadmap
### seqr-scanner pip package · v0.1.0 → v3

---

## 1. Current State (v0.1.0)

### What's Built and Tested

**Code Scanner (scanner/code.py)**
- AST scanning via tree-sitter 0.23
- 30 patterns across Python, JavaScript, Java, Go
- Detects: RSA keygen, ECDSA keygen, ECC, JWT algorithms (RS256/RS384/RS512, ES256/ES384/ES512),
  DH/DHE, node-rsa, node-forge, paramiko, Spring Security JWT
- Outputs: finding_id, file, line, algorithm, algorithm_family, quantum_status, algorithm_risk,
  confidence, recommended_replacement, estimated_effort_hours

**Network Scanner (scanner/network.py)**
- sslyze 6.0 TLS/cert scanning
- CDN detection (CloudFront, Cloudflare, Akamai, Fastly, Google Cloud CDN)
- Hybrid PQC detection via TLS curve group names (X25519Kyber768, etc.)
- Certificate algorithm, key size, expiry, issuer, SANs
- Outputs: deployment_level (0-4), crypto_agility_score (0-10), hybrid_status, cdn_detected,
  scan_confidence (high/medium/low), pqc_migration_priority, threat_timeline

**Risk Engine (engines/risk.py)**
- HNDL risk assessment (path-based inference)
- threat_timeline calculation
- pqc_migration_priority (IMMEDIATE / URGENT / PLANNED / MONITORING)
- crypto_agility_score (0-10)
- deployment_level (0-4)

**CBOM Engine (engines/cbom.py)**
- CycloneDX 1.5 export
- JSON and CSV export
- Org-level CBOM aggregation

**Compliance Engine (engines/compliance.py)**
- PCI DSS 12.3.3
- DST Task Force Phase 1
- RBI IT Framework (MONITOR)
- CERT-In (MONITOR)
- DPDP Act 2023 Section 8

**Test Coverage: 386 tests**
- 289 unit tests
- 6 integration tests (require network, run with `-m integration`)
- 51 v1.1 improvement tests
- 40 fix regression tests

### Known Limitations (sslyze passive scanning)
1. **Hybrid PQC undercounting** — sslyze cannot detect X25519Kyber768 without sending
   a Kyber-capable ClientHello. Servers supporting hybrid PQC may appear as not detected.
   Label in output: "Hybrid PQC not detected — sslyze passive-scan limitation."
2. **HNDL is estimated, not measured** — HNDL exposure derived from domain/path category,
   not from actual data retention policies. Always labeled "estimated."
3. **CDN = LOW confidence** — TLS config belongs to CDN, not origin. Report as confidence=low.
4. **No active probing** — passive TLS handshake only. Cannot test downgrade attacks
   without dual-probe implementation.

---

## 2. v1.x Improvements (next 3 months, before first enterprise customer)

### CRITICAL — Security & Multi-tenant

**[C1] Multi-tenant org boundary enforcement**
Every API route must enforce `org_id` WHERE clause. CBOM data leaks are catastrophic.
`GET /api/v1/assets/{id}` must verify `asset.org_id == current_user.org_id`.

**[C2] HNDL legal disclaimer in all outputs**
Every PDF report, CLI scan output, and API response must include:
"HNDL exposure scores are predictive cryptographic risk metrics based on data-type
endurance, not indicators of active data interception or confirmed network breaches."

**[C3] CI/CD policy flags**
`seqr scan code` default: exit 0 (never break a build by default).
Add flags: `--fail-on IMMEDIATE`, `--fail-on URGENT`, `--policy=strict`, `--policy=lax`

**[C4] Indian sovereign cloud documentation**
SaaS: AWS ap-south-1 only. On-prem Docker: zero data egress.
Document in README and PRD. CERT-In / DPDP compliance.

### Risk Engine Improvements

**[R1] Shannon entropy hardcoded secret detection**
AST scanner: if string has entropy > 4.5 AND matches PEM private key pattern → IMMEDIATE.
Classically exploitable NOW. Not quantum-specific but always in scope.

**[R2] Certificate lifespan vs DST deadlines**
Scale HNDL exposure if cert validity extends past Jan 1, 2027 (CII deadline) or
Jan 1, 2028 (regular deadline). 5-year cert expiring 2029 = full HNDL window open.

**[R3] CBOM staleness index**
If no scan in 14 days: compliance output shows
"STALE — inventory may not reflect current cryptographic state."

**[R4] Ephemeral vs static key via cert key_usage flags**
`keyUsage=keyCertSign` (static CA key, long validity) → higher HNDL.
Ephemeral session keys → lower HNDL.

**[R5] DPDP Act ₹250 Crore in compliance output**
For any endpoint handling user data (PII paths): transform findings into financial liability.
Output: "Under Section 8 of DPDP Act 2023, failure to protect PII against interception
risks statutory penalties up to ₹250 Crore."

### Network Scanner Improvements

**[N1] CDN = LOW remediation effort (reframe)**
Replace warning with opportunity framing:
- Cloudflare: "Remediation Effort: LOW. One dashboard toggle when ML-KEM becomes available."
- CloudFront: "Enable TLS policy in AWS Console. No code changes required."

**[N2] HNDL path inference pivot**
Override domain category with URL path signals:
- HIGH persistence: `/auth`, `/login`, `/kyc`, `/profile`, `/account`, `/user`,
  `/health-records`, `/archive`, `/vault`, `/backup`, `/export`, `/history`
- LOW persistence: `/ticker`, `/heartbeat`, `/static`, `/public`, `/images`, `/metrics`

**[N3] Downgrade attack two-probe detection**
Probe domain twice: with hybrid PQC ClientHello, then classical only.
If server accepts classical without downgrade warning headers → `HYBRID_DOWNGRADE_EXPOSURE`.
Genuine differentiator vs all passive-only competitors.

**[N4] DNSSEC + CAA DNS check**
Run DNS query per domain.
Missing DNSSEC: -1.5 from crypto_agility_score.
Missing CAA: -1.0 from crypto_agility_score.

**[N5] PKI chain algorithm mismatch detection**
Leaf cert PQC but intermediate CA classical → flag as deployment blocker.

**[N6] Dual-signature certificate test cases**
Add mock dual-sig cert to test suite. Scanner must not crash or miss the PQC block.

**[N7] MTU fragmentation warning for hybrid PQC**
When hybrid PQC detected: "ML-KEM key sizes (1,184 bytes) may exceed standard MTU
of 1,500 bytes. Test with large ClientHello before production rollout."

**[N8] Open-source crypto drift in dependency manifests**
Scan `requirements.txt` and `package.json` for unofficial/experimental PQC forks.
Flag unapproved PQC libraries as IMMEDIATE (may have unvetted security properties).

### Code Scanner Improvements

**[C5] JWT algorithm confusion AST detection**
If JWT verification accepts algorithm dynamically from token header (not pinned) → IMMEDIATE.
Classically exploitable NOW via algorithm confusion attacks.

**[C6] Firmware/download path elevation**
Paths: `/firmware/`, `/download/`, `/updates/`, `/deploy/`
Elevate priority, flag signing algorithm used.

**[C7] CycloneDX 1.5 → 1.6 upgrade**
CycloneDX 1.6 has native PQC `cryptoProperties` fields.
Enterprise compliance tools expect 1.6.

### CLI Improvements

**[L1] `seqr explain <finding-id>`**
Offline static lookup dictionary. No API call. Works in air-gapped environments.
Explains the vulnerability, FIPS reference, and migration path.

**[L2] `seqr migrate --finding <id>`**
Generates migration code snippet for a specific finding.
Uses static templates per pattern_id. Offline.

**[L3] `seqr scan domain --file domains.txt`**
Bulk domain scanning from a file. One domain per line.
Shows per-domain progress, summary table at end.

**[L4] HNDL disclaimer in CLI output**
Show disclaimer once per scan run in terminal output.

### Backend / Infrastructure Improvements

**[B1] Cryptographic library version tracking**
Detect: OpenSSL version, PyCA version, BouncyCastle, node-forge.
Flag if version doesn't support FIPS 203/204/205.
Flag if version is 24+ months old (stale-life).

**[B2] Multi-port correlation**
Group findings by IP address.
Drag risk score to weakest port.
If port 443 is TLS 1.3 + ECDSA but port 8443 is TLS 1.2 + RSA-2048 → report overall as RSA.

---

## 3. v2 Features (post first customer)

**SSH PQ readiness**
`seqr scan ssh hostname`
Check supported key exchange algorithms on port 22.
`sntrup761x25519-sha512` supported = good.
`ecdh-sha2-nistp256` only = vulnerable.

**Email PQ readiness**
`seqr scan email domain.com`
SMTP STARTTLS algorithm check. Flag weak cipher suites on port 25/587/465.

**VPN scanning**
IKE probe UDP 500/4500. Check IKEv2 cipher suites.

**Active hybrid ClientHello testing**
Requires `liboqs-python` + custom TLS stack.
Cannot detect with sslyze alone. Uses oqs-provider Python binding to send
X25519Kyber768 ClientHello and detect server response.

**HTTP/3 + QUIC scanning**
Requires `aioquic`. QUIC uses TLS 1.3 internally.
Check QUIC cipher suite negotiation.

**Supply chain third-party API risk**
Extract external API calls from code → scan the target domains for PQC readiness.
"Your code calls stripe.com — Stripe currently supports hybrid PQC: ✅"

**India regulatory sector modes**
```
seqr scan domain company.com --india-rbi      # NBFCs, banks
seqr scan domain company.com --india-sebi     # brokers, wealth mgmt
seqr scan domain company.com --india-irdai    # insurers
```

**Geo compliance flag**
```
GET /risk/compliance?geo=in   # India (DST, RBI, CERT-In, DPDP) — current
GET /risk/compliance?geo=eu   # EU (NIS2, DORA, GDPR Art 32)
GET /risk/compliance?geo=us   # US (NIST, CISA, EO 14144)
```

---

## 4. v3 Features (post Series A)

- **OS layer scanning** — requires on-prem agent
- **AD/Kerberos scanning** — requires domain admin access (Kerberos cipher suite audit)
- **Kubernetes/service mesh scanning** — mTLS policy audit, Istio/Linkerd cipher config
- **mTLS scanning** — client cert algorithm check
- **VPN full implementation** — OpenVPN, WireGuard, IPsec full algorithm audit
- **HSM integration** — scan hardware security module key types via PKCS#11

---

## 5. Out of Scope (and Why)

**ASV certification (PCI Approved Scanning Vendor)**
Wrong market, wrong product. ASV certifies vulnerability scanners for PCI DSS external
scanning. SeQr is a cryptographic inventory tool, not a vulnerability scanner.
Adding ASV scope dilutes PQC focus and adds massive compliance overhead.

**General OWASP / CVSS scanning**
Snyk, SonarQube, Semgrep already own this space and do it better.
SeQr's moat is PQC-specific scanning + Indian compliance mapping.
Don't dilute the focus.

**Windows registry / AD certificate store scanning (v1)**
Requires agent on Windows hosts. High support burden. Defer to v3 after funding.

**NTC Assurance Levels L1–L4**
TEC/STQC/BIS establishing these levels by Dec 2026.
**DO NOT implement until official criteria published.**
Watch: tec.gov.in, stqc.gov.in, bis.gov.in
Future field to add: `pqc_assurance_level_target` when official L1-L4 spec publishes.

---

## 6. Methodology Limitations (document in research paper)

These are inherent limitations of passive TLS scanning that must be disclosed:

1. **Hybrid PQC undercounting** — sslyze cannot detect X25519Kyber768 without sending
   a Kyber-capable ClientHello. All hybrid PQC capable servers labeled
   "not detected — sslyze limitation." Actual PQC adoption is likely higher than reported.

2. **HNDL exposure is estimated** — Derived from domain/path category and data-type
   endurance heuristics, not from actual measured data retention policies.
   Always labeled "estimated" in paper and output.

3. **CDN-terminated = LOW confidence** — TLS configuration belongs to the CDN, not the
   origin server. Cannot assess origin server cryptography through CDN termination.
   Confidence: low. Label: "CDN-terminated — origin unknown."

4. **Snapshot in time** — All findings reflect the cryptographic posture at scan time.
   Organisations may have updated their configuration since scanning.
   All paper findings labeled with scan_confidence: high (direct) / medium (cloud IP) / low (CDN).
