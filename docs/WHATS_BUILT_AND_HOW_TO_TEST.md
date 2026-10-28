# What's Built & How To Test It

Canonical index of everything in the repo: where each piece lives, and the exact
command to verify it works. Last updated 2026-06-21.

> **One-line setup:** Python 3.11+, `pip install -e shared-scanner` (or run tests from
> each dir). For active PQC: OpenSSL 3.5+ (`scoop install openssl` → set
> `$env:SEQR_OPENSSL` to the openssl.exe path).

---

## 0. The fastest "is everything OK" check

```bash
cd shared-scanner && python -m pytest -q      # ~460 engine tests
cd cli            && python -m pytest -q      # 52 CLI tests
cd audit/backend  && python -m pytest -q      # 78 backend tests (auth, tenancy, security)
```
Green across all three = the whole engine + CLI + backend behave as specified.

---

## 1. CLI — the free LITE tool (`cli/`)

**What:** `seqr` command, published on PyPI (passive, offline, MIT).
**Where:** `cli/seqr/` (`cli.py`, `output/terminal.py`, vendored engine in `_scanner/`).
**Test it yourself:**
```bash
pip install seqr                      # from PyPI (live: pypi.org/project/seqr)
seqr scan domain razorpay.com         # passive TLS posture
seqr scan domain razorpay.com --verbose
seqr scan ssh github.com              # SSH PQC key exchange + host-key posture
seqr scan mail smtp.gmail.com --protocol smtp   # SMTP/IMAP/POP3 STARTTLS
seqr scan code ./some-repo            # code crypto patterns
seqr --help
```
LITE now scans web + SSH + mail (passive). Active PQC + compliance/CBOM are PRO.
Backend asset types: domain, ssh, smtp, imap, pop3, postgres (all feed the CBOM).
**Run the tests:** `cd cli && python -m pytest -q` → 52 pass.
**Note:** published 0.1.0 still has the old `seqrlabs.in` footer — bump to 0.1.1 before promoting.

---

## 2. Scanner engine (`shared-scanner/`)

The core. Used by the backend + scan-demo-service (via the `seqr_scanner` package).

| Component | File | How to test |
|---|---|---|
| TLS / network scanner | `scanner/network.py` | `python -c "from seqr_scanner import NetworkScanner; print(NetworkScanner().scan_domain('google.com').tls_version)"` |
| Active PQC probe | `scanner/pqc_probe.py` | with `SEQR_OPENSSL` set: `python -c "from scanner.pqc_probe import probe_active_pqc; print(probe_active_pqc('cloudflare.com'))"` → `supported=True group='X25519MLKEM768'` |
| SSH scanner | `scanner/ssh_scanner.py` | `python -c "from scanner.ssh_scanner import scan_ssh; r=scan_ssh('github.com'); print(r.pqc_kex_methods, r.host_key_algorithms[:2])"` |
| SMTP/IMAP/POP3/Postgres | `scanner/network.py` (`protocol=`) | `NetworkScanner(active_pqc=True).scan_domain('smtp.gmail.com', protocol='smtp')` |
| Algorithm classifier | `engines/classifier.py` | `python -c "from engines.classifier import recommended_algorithm; print(recommended_algorithm('RSA-4096'))"` → ML-KEM-1024/ML-DSA-87 |
| Risk engine | `engines/risk.py` | covered by `tests/test_risk_engine.py` |
| Compliance registry | `engines/compliance.py` | `python -c "from engines.compliance import DEFAULT_FRAMEWORKS; print([f.name for f in DEFAULT_FRAMEWORKS])"` |
| CBOM export | `engines/cbom.py` | `tests/test_cbom.py` — CycloneDX 1.6 |

**Run all engine tests:** `cd shared-scanner && python -m pytest -q`.
**Scanner self-validation:** `cd research && python scan.py --validate` (checks against badssl.com).

---

## 3. Backend — the PRO SaaS API (`audit/backend/`)

**What:** FastAPI + multi-tenant auth, scans, CBOM, risk, compliance, PDF reports.
**Where:** `audit/backend/app/` (`routers/`, `models/`, `security.py`, `config.py`, `deps.py`).
**Run it locally:**
```bash
cd audit/backend
uvicorn app.main:app --reload
# open http://localhost:8000/docs  (dev only) — try register → login → scan → cbom
```
**Test it:** `cd audit/backend && python -m pytest -q` → 78 pass.
**Security-specific tests:** `pytest tests/test_org_boundary.py tests/test_config.py tests/test_public.py`
(multi-tenant isolation, prod-config guardrails, SSRF rebinding).

---

## 4. Frontend (`audit/frontend/`)

**What:** Next.js marketing site + dashboard.
**Where:** `audit/frontend/src/` (`components/marketing/`, `app/`).
**Run it:** `npm --prefix audit/frontend run dev` → http://localhost:3000.
**What to check:** the "Why now" section (`components/marketing/WhyNow.tsx`) — accurate
framework framing (SEBI, RBI Q-SAFE, DST 2027, DPDP enforceable 2027-05-13). Favicon =
ring mark (`app/icon.svg`).

---

## 5. Live demo scanner (`scan-demo-service/`)

**What:** standalone FastAPI scanner behind the landing page "Try It Live" (Render).
**Where:** `scan-demo-service/main.py`. Active PQC on (trixie image = OpenSSL 3.5).
**Test it (live):**
```bash
curl -X POST https://seqr-labs.onrender.com/api/v1/public/scan \
  -H "Content-Type: application/json" -d '{"domain":"razorpay.com"}'
```
Look for `pqc_active_supported` in the response.

---

## 6. Research (`research/`)

**What:** the measurement study behind the paper.
**Where:**
- `scan.py` — the scanner (passive + `--active`)
- `domains.csv`, `domains_india_extended.csv`, `domains_global.csv` — corpora
- `results_*.json` — raw datasets (passive + active runs)
- `FINDINGS_2026-06-21.md` — the analysis (0% passive vs 60% active, cross-country)
- `paper/PQC_India_Measurement_draft.md` — the arXiv draft
**Re-run it:**
```bash
cd research
python scan.py --validate                 # self-test
python scan.py --limit 5                   # quick 5-domain passive run
$env:SEQR_OPENSSL="...openssl.exe"; python scan.py --active   # full active run
```

---

## 7. Compliance reference (`docs/09_Compliance_Frameworks.md`)

Source of truth for every framework + date + citation. **Re-verify against primary
sources before each release** (banner at top of the file says so).

---

## 8. The audit trail = git history

Every change is a descriptive commit. `git log --oneline` shows them. Key recent ones:
`9fe4105` SMTP/IMAP/POP3/Postgres · `275a376` SSH scanner · `5d6d8ff` active PQC ·
`0cf481b` security hardening · plus the `research:` commits for the paper data.
The dated changelog in `CLAUDE.md` summarizes the big passes.
