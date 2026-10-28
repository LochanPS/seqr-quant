# SeQr CLI — Engineering PRD v1.1
### seqr · Command-Line PQC Audit Tool
**Hand this entire document to Claude Code.**

---

## PRODUCT SUMMARY

SeQr CLI is a standalone command-line tool that runs locally on a developer's
machine and scans their codebase, local certificates, and network endpoints for
quantum-vulnerable cryptography. It is the free, open-source entry point into the
SeQr ecosystem.

Distribution: pip (Python), Homebrew (macOS), apt/deb (Ubuntu), binary releases (GitHub)
License: Open source core (MIT) — report export and compliance mapping require API key
Revenue model: CLI is free. API key (₹3,000/month or linked to SeQr Audit license)
  unlocks: PDF reports, compliance mapping (PCI DSS/DST), CBOM JSON export

The CLI serves three purposes:
  1. Acquisition: developers find it, use it, tell their CISO who buys the full platform
  2. CI/CD integration: `seqr scan` in pipelines catches new crypto vulnerabilities
  3. Research tool: the scanner code used in Doc 04 research paper is this CLI

---

## PROJECT STRUCTURE

```
seqr-cli/
├── seqr/
│   ├── __init__.py
│   ├── cli.py                    # Click CLI entry point (all commands)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── network.py            # TLS/domain scanner (sslyze)
│   │   ├── code.py               # AST code scanner (tree-sitter)
│   │   ├── filesystem.py         # Local cert/config file scanner
│   │   └── patterns/             # Same pattern JSON files as audit platform
│   │       ├── python.json
│   │       ├── javascript.json
│   │       ├── java.json
│   │       └── go.json
│   ├── engines/
│   │   ├── classifier.py         # Algorithm → vulnerability classification
│   │   ├── risk.py               # Risk scoring (same logic as audit platform)
│   │   └── cbom.py               # CBOM aggregation
│   ├── output/
│   │   ├── terminal.py           # Rich terminal output (tables, colours)
│   │   ├── json_export.py        # JSON/CBOM export
│   │   ├── sarif.py              # SARIF format (for GitHub Code Scanning)
│   │   └── pdf.py                # PDF via API (requires API key)
│   ├── api/
│   │   └── client.py             # SeQr cloud API client (for paid features)
│   └── config.py                 # ~/.seqr/config.toml reader
├── tests/
│   ├── fixtures/
│   │   ├── sample_project_python/ # Known-vulnerable Python project for testing
│   │   ├── sample_project_node/
│   │   └── certs/                 # Known-algorithm test certificates
│   ├── test_cli.py
│   ├── test_network_scanner.py
│   ├── test_code_scanner.py
│   └── test_classifier.py
├── pyproject.toml
├── README.md
├── CHANGELOG.md
└── .github/
    └── workflows/
        ├── test.yml
        ├── release.yml            # Build + publish to PyPI on tag
        └── homebrew.yml           # Update Homebrew formula on release
```

---

## COMPLETE CLI COMMAND SPEC

```
seqr [OPTIONS] COMMAND [ARGS]

Global options:
  --api-key TEXT      SeQr API key (or set SEQR_API_KEY env var)
  --output FORMAT     Output format: terminal (default), json, sarif, pdf
  --no-colour         Disable coloured terminal output (for CI environments)
  --quiet             Only print findings, no progress output
  --verbose           Extended output (show all scanned files, not just findings)
  --version           Show version and exit
  --help              Show help

Exit codes:
  0  Always — unless --fail-on is explicitly set. Never break CI/CD by default.
  1  Only when --fail-on LEVEL is set and findings at that level exist.

Commands:
  scan                Run a scan (subcommands below)
  explain             Explain a finding and show migration guidance (offline)
  migrate             Generate migration code for a finding (requires API key)
  history             Show scan history and diffs
  report              Generate reports from saved scan data
  config              Manage configuration
  auth                Authenticate with SeQr cloud
  update              Update pattern library to latest version

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr scan code [PATH] [OPTIONS]

Scan a local code directory for quantum-vulnerable cryptography.

Arguments:
  PATH                Directory to scan. Defaults to current directory (.)

Options:
  --language TEXT     Only scan this language (python|javascript|java|go|all)
  --exclude TEXT      Glob pattern to exclude (can use multiple times)
                      Default excludes: node_modules/, .venv/, vendor/, __pycache__/
  --include TEXT      Only scan files matching this glob
  --severity LEVEL    Only show findings at this level or above (low|medium|high|critical)
  --fail-on LEVEL     Exit 1 if findings at IMMEDIATE|URGENT|high|critical exist (CI gate).
                      Default: exit 0 always (never block CI by default).
  --policy strict|lax Apply named policy: strict=fail on IMMEDIATE, lax=fail on nothing.
  --output FORMAT     terminal | json | sarif | cbom
  --save PATH         Save results to file

Example:
  seqr scan code ./src --exclude "tests/" --severity high --fail-on IMMEDIATE
  seqr scan code . --output json --save results.json
  seqr scan code . --output sarif --save results.sarif  # GitHub Code Scanning
  seqr scan code . --policy strict                       # fail on IMMEDIATE only

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr scan domain DOMAIN [OPTIONS]

Scan a domain's TLS configuration.

Arguments:
  DOMAIN              Domain to scan (e.g., api.company.com)
                      Can scan multiple: seqr scan domain a.com b.com c.com

Options:
  --port INTEGER      Port to scan (default: 443)
  --timeout INTEGER   Connection timeout in seconds (default: 10)
  --file PATH         CSV/text file with one domain per line (batch mode)
  --output FORMAT     terminal | json | cbom
  --save PATH         Save results to file

Output standards for domain scan (≤20 lines per domain):
  - Deployment Level 0-4 (0=classical-only, 4=native PQC)
  - Crypto Agility Score 0-10
  - CDN-terminated domains: mark as LOW scan confidence, LOW remediation effort
    ("Remediation effort: LOW — CDN provider controls TLS configuration")
  - HNDL risk: label "estimated" or "assumed" — never "confirmed"
  - pqc_migration_priority: IMMEDIATE / URGENT / PLANNED / MONITORING
  - CNSA 2.0: never mention — not applicable to Indian companies
  - DST Task Force compliance status (IMMEDIATE if CII entity, PLANNED otherwise)

Example:
  seqr scan domain api.mycompany.com
  seqr scan domain api.mycompany.com auth.mycompany.com --output json
  seqr scan domain --file domains.txt --output json --save results.json

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr scan certs PATH [OPTIONS]

Scan local certificate files and SSH keys.

Arguments:
  PATH                Directory or file to scan for certificates

Options:
  --recursive         Scan recursively (default: true)
  --types TEXT        File types to scan (default: pem,crt,cer,key,pub,jks,p12)

Example:
  seqr scan certs /etc/ssl/certs/
  seqr scan certs ~/.ssh/
  seqr scan certs /etc/ --types pem,key

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr scan all [PATH] [OPTIONS]

Run all available scanners: code + certs + any domains specified.
This is the "full local audit" command.

Options:
  --domain TEXT       Domain(s) to include in the scan (can use multiple times)
  --path PATH         Code directory (default: current directory)
  --cert-path PATH    Certificate directory (default: /etc/ssl + ~/.ssh)
  --output FORMAT     terminal | json | pdf (pdf requires API key)
  --save PATH         Save results

Example:
  seqr scan all --domain api.mycompany.com --path ./src
  seqr scan all --output pdf --save audit.pdf  # requires API key

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr explain FINDING_ID

Explain a finding with migration guidance. Works OFFLINE — no API call.
Uses a static lookup dictionary bundled in the package.
Air-gapped safe. Never calls Claude API or any network.

Arguments:
  FINDING_ID          Finding ID from scan output (e.g., PY-JWT-RS256)

Output:
  - What the finding means in plain English
  - Why it's quantum-vulnerable (Shor's algorithm explanation)
  - Migration path with specific library + function names
  - Estimated effort hours
  - Relevant NIST FIPS standard reference
  - DST Task Force compliance implication

Example:
  seqr explain PY-JWT-RS256
  seqr explain JS-CRYPTO-RSA-001

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr migrate --finding FINDING_ID [OPTIONS]

Generate migration code for a specific finding.
Requires API key (calls Claude API — NOT air-gapped).

Options:
  --finding TEXT      Finding ID to generate migration code for
  --context PATH      Path to the file containing the finding (for better context)
  --output FORMAT     terminal | json (default: terminal)

Example:
  seqr migrate --finding PY-JWT-RS256
  seqr migrate --finding PY-JWT-RS256 --context src/auth/jwt_handler.py

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr history [OPTIONS]

Show scan history. Lists past scans with summary.

Options:
  --limit INTEGER     Show last N scans (default: 10)

COMMAND: seqr history diff SCAN_ID_1 SCAN_ID_2

Compare two scans — show new findings, resolved findings, risk score change.

Example:
  seqr history
  seqr history diff scan_20260601 scan_20260615
  # Output: +3 new IMMEDIATE findings, -1 resolved, risk score 72 → 85

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr scan ssh HOSTNAME [OPTIONS]  [v2 — NOT BUILT YET]

Scan SSH server configuration for quantum-vulnerable key algorithms.
Currently deferred to v2. Note in output if user tries to use it.

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr scan email DOMAIN [OPTIONS]  [v2 — NOT BUILT YET]

Scan email server (MX records, STARTTLS, certificate) for quantum-vulnerable config.
Currently deferred to v2.

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr report generate [OPTIONS]

Generate a formatted report from a previous scan (saved as JSON).
Requires API key for PDF and compliance-mapped reports.

Options:
  --input PATH        Path to saved scan JSON
  --type TEXT         Report type: summary | technical | compliance-pci | compliance-dst
  --output FORMAT     pdf | html | terminal
  --save PATH         Save report to file

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr config [SUBCOMMAND]

  seqr config init        Create ~/.seqr/config.toml with defaults
  seqr config set KEY VAL Set a config value
  seqr config show        Show current config
  seqr config patterns    Show pattern library version + update

───────────────────────────────────────────────────────────────────────────────

COMMAND: seqr auth login

Authenticate with SeQr cloud.
Opens browser to auth.seqrlabs.com, saves token to ~/.seqr/config.toml

  seqr auth login
  seqr auth status        Show current auth status + plan
  seqr auth logout
```

---

## TERMINAL OUTPUT DESIGN

```
Use the `rich` Python library for all terminal output.

Example output for: seqr scan code ./src

┌─────────────────────────────────────────────────────────┐
│ SeQr PQC Scanner v0.3.1                            │
│ Scanning: ./src  │  Language: auto-detect               │
└─────────────────────────────────────────────────────────┘

  Scanning Python files...  ████████████████████  42/42 files

  ┌─ FINDINGS ──────────────────────────────────────────────────────────────────┐
  │                                                                              │
  │  CRITICAL (2)                                                                │
  │  ─────────────────────────────────────────────────────────────────────────  │
  │  src/auth/jwt_handler.py:42                                                  │
  │    jwt.encode(payload, key, algorithm='RS256')                               │
  │    Algorithm: RSA-SHA256 (RS256)  │  Risk: CRITICAL  │  Confidence: HIGH    │
  │    ▶ Replace with ML-DSA-65 via pqcmap: PQCToken.encode(payload, key)       │
  │                                                                              │
  │  src/keys/generate.py:17                                                     │
  │    ec.generate_private_key(ec.SECP256K1())                                   │
  │    Algorithm: ECDSA secp256k1  │  Risk: HIGH  │  Confidence: HIGH           │
  │    ▶ Replace with: pqcmap.Signature('ML-DSA-44').generate_keypair()         │
  │                                                                              │
  │  HIGH (1)                                                                    │
  │  ─────────────────────────────────────────────────────────────────────────  │
  │  src/payments/client.py:8                                                    │
  │    from cryptography.hazmat.primitives.asymmetric import rsa                 │
  │    Algorithm: RSA (import)  │  Risk: HIGH  │  Confidence: MEDIUM            │
  │    ▶ Check usage — if signing/encryption, replace with ML-DSA/ML-KEM        │
  │                                                                              │
  └──────────────────────────────────────────────────────────────────────────────┘

  SUMMARY
  ────────────────────────────────────────────────────
  Files scanned:      42
  Findings:           3 (2 critical, 1 high, 0 medium, 0 low)
  Quantum-safe:       38 components
  Est. fix effort:    16–24 hours total

  ⚡ HNDL RISK (estimated): 1 component (jwt_handler.py) — public API using RSA key exchange.
     pqc_migration_priority: IMMEDIATE

  ──────────────────────────────────────────────────────────────────────────────
  HNDL DISCLAIMER: HNDL exposure scores are predictive cryptographic risk metrics
  based on data-type endurance and endpoint exposure classification, not indicators
  of active data interception or confirmed network breaches.
  ─────────────────────────────────────────────────────
  Free plan: terminal output only.
  Run `seqr auth login` for PDF reports + compliance mapping (PCI DSS, DST Task Force).
  ─────────────────────────────────────────────────────
```

---

## JSON OUTPUT FORMAT

```json
{
  "seqr_version": "0.3.1",
  "scan_timestamp": "2026-06-12T14:32:00Z",
  "scan_type": "code",
  "target": "./src",
  "pattern_library_version": "1.4.2",
  "summary": {
    "files_scanned": 42,
    "components_found": 3,
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0,
    "quantum_safe_count": 38,
    "hndl_risk_count": 1,
    "estimated_effort_hours": {"min": 16, "max": 24}
  },
  "findings": [
    {
      "id": "PY-JWT-RS256",
      "file": "src/auth/jwt_handler.py",
      "line": 42,
      "snippet": "jwt.encode(payload, key, algorithm='RS256')",
      "algorithm": "RSA-SHA256",
      "algorithm_family": "RSA",
      "quantum_status": "vulnerable",
      "severity": "critical",
      "confidence": "high",
      "hndl_risk": true,
      "recommended_replacement": "ML-DSA-65",
      "recommended_fips": "FIPS 204",
      "migration_guide": "Replace PyJWT RS256 with pqcmap.jwt.PQCToken",
      "estimated_effort_hours": {"min": 3, "max": 5}
    }
  ]
}
```

---

## SARIF OUTPUT FORMAT (GitHub Code Scanning)

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "SeQr PQC Scanner",
        "version": "0.3.1",
        "rules": [
          {
            "id": "PY-JWT-RS256",
            "name": "RSAJWTSigningAlgorithm",
            "shortDescription": {"text": "RSA JWT signing is quantum-vulnerable"},
            "fullDescription": {"text": "JWT tokens signed with RS256/RS384/RS512 use RSA, which will be broken by Shor's algorithm on quantum computers. Replace with ML-DSA (FIPS 204)."},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "quantum", "pqc"]}
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "PY-JWT-RS256",
        "level": "error",
        "message": {"text": "RSA JWT signing (RS256) is quantum-vulnerable. Replace with ML-DSA-65 via pqcmap."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "src/auth/jwt_handler.py"},
            "region": {"startLine": 42}
          }
        }]
      }
    ]
  }]
}
```

Why SARIF matters: GitHub Security tab natively reads SARIF. When used in CI, findings
appear inline in PRs and in the repository's Security → Code scanning alerts view.
This is free GitHub distribution — no GitHub App needed.

---

## CI/CD INTEGRATION EXAMPLES

```yaml
# .github/workflows/pqc-scan.yml
# Works WITHOUT the paid GitHub App — just uses the CLI

name: PQC Security Scan
on: [push, pull_request]

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF to GitHub Security tab

    steps:
      - uses: actions/checkout@v4

      - name: Install SeQr CLI
        run: pip install seqr

      - name: Run PQC scan
        run: |
          seqr scan code . \
            --output sarif \
            --save results.sarif \
            --severity medium

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        if: always()   # upload even if findings exist

      - name: Fail on critical findings
        run: seqr scan code . --fail-on critical --quiet
```

```yaml
# GitLab CI (.gitlab-ci.yml)
pqc-scan:
  image: python:3.12-slim
  script:
    - pip install seqr
    - seqr scan code . --output json --save pqc-results.json
    - seqr scan code . --fail-on high --quiet
  artifacts:
    reports:
      sast: pqc-results.json
    when: always
```

```bash
# Pre-commit hook: .git/hooks/pre-commit
#!/bin/bash
# Install: pip install seqr && cp this-file .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
echo "Running SeQr PQC check..."
seqr scan code . --fail-on critical --quiet
if [ $? -ne 0 ]; then
    echo "❌ Critical quantum vulnerabilities found. Fix before committing."
    echo "Run: seqr scan code . for details"
    exit 1
fi
echo "✅ No critical PQC issues found"
```

---

## CONFIG FILE FORMAT

```toml
# ~/.seqr/config.toml

[auth]
api_key = "sq_live_xxxxxxxx"     # Set by: seqr auth login OR manually
api_url = "https://api.seqrlabs.com"

[scan]
default_severity = "medium"      # Only show findings at this level and above
default_output = "terminal"
exclude_patterns = [
    "node_modules/",
    ".venv/",
    "__pycache__/",
    "vendor/",
    "*.test.*",
    "*.spec.*"
]
languages = ["python", "javascript", "java", "go"]

[patterns]
version = "1.4.2"               # Current installed version
auto_update = true              # Check for pattern updates on each run
update_channel = "stable"       # stable | beta
```

---

## pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "seqr"
version = "0.1.0"
description = "Scan your codebase for quantum-vulnerable cryptography. Free & open source."
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "Lochan", email = "lochan@seqrlabs.com"}]
keywords = ["post-quantum", "cryptography", "security", "PQC", "quantum", "audit", "scanner"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Topic :: Security",
    "Topic :: Security :: Cryptography",
    "Environment :: Console",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
requires-python = ">=3.10"
dependencies = [
    "click>=8.1.7",
    "rich>=13.7.0",
    "sslyze>=6.0.0",
    "cryptography>=43.0.0",
    "tree-sitter>=0.23.0",
    "tree-sitter-python>=0.23.0",
    "tree-sitter-javascript>=0.23.0",
    "tree-sitter-java>=0.23.0",
    "tree-sitter-go>=0.23.0",
    "httpx>=0.27.2",
    "toml>=0.10.2",
    "pydantic>=2.9.2",
]

[project.optional-dependencies]
dev = ["pytest", "pytest-cov", "black", "ruff"]

[project.scripts]
seqr = "seqr.cli:main"   # installs the `seqr` command

[project.urls]
Homepage = "https://seqrlabs.com"
Documentation = "https://docs.seqrlabs.com/cli"
Repository = "https://github.com/seqrlabs/cli"
"Report Issues" = "https://github.com/seqrlabs/cli/issues"
```

---

## Homebrew Formula (for macOS distribution)

```ruby
# Formula/seqr.rb
# Published at: github.com/seqrlabs/homebrew-tap
class Seqr < Formula
  desc "Scan your codebase for quantum-vulnerable cryptography"
  homepage "https://seqrlabs.com"
  url "https://github.com/seqrlabs/cli/archive/v0.1.0.tar.gz"
  sha256 "..." # filled in by release automation

  depends_on "python@3.12"

  def install
    system "pip3", "install", "--prefix=#{prefix}", "."
  end

  test do
    system "#{bin}/seqr", "--version"
  end
end

# Install command for users:
# brew tap seqrlabs/tap
# brew install seqr
```

---

## PATTERN LIBRARY UPDATE MECHANISM

```python
# seqr/scanner/patterns/__init__.py
"""
Pattern library is fetched from:
  https://patterns.seqrlabs.com/v1/patterns.json

On each CLI run (if auto_update=true):
  1. Check local version in config vs remote version header
  2. If remote is newer: download new patterns.json
  3. Cache at: ~/.seqr/patterns.json
  4. Fall back to bundled patterns.json if offline

Bundled patterns (in package): patterns are included in the pip package
  so the CLI works completely offline with the version bundled at release time.

Update command:
  seqr config patterns update   # force update now
  seqr config patterns version  # show current version
"""
```

---

## TESTS

```python
# tests/test_cli.py
from click.testing import CliRunner
from seqr.cli import main

def test_scan_code_detects_rsa():
    runner = CliRunner()
    result = runner.invoke(main, ['scan', 'code', 'tests/fixtures/sample_project_python/'])
    assert result.exit_code == 0
    assert 'RSA' in result.output or 'ECDSA' in result.output

def test_scan_code_json_output():
    runner = CliRunner()
    result = runner.invoke(main, ['scan', 'code', 'tests/fixtures/sample_project_python/',
                                   '--output', 'json'])
    import json
    data = json.loads(result.output)
    assert 'findings' in data
    assert data['summary']['components_found'] > 0

def test_fail_on_critical_exits_1():
    runner = CliRunner()
    result = runner.invoke(main, ['scan', 'code', 'tests/fixtures/sample_project_python/',
                                   '--fail-on', 'critical', '--quiet'])
    # fixture has known critical finding
    assert result.exit_code == 1

def test_clean_project_exits_0():
    runner = CliRunner()
    result = runner.invoke(main, ['scan', 'code', 'tests/fixtures/sample_project_safe/'])
    assert result.exit_code == 0
    assert '0 findings' in result.output or 'No issues found' in result.output

def test_domain_scan():
    # Integration test — needs network
    # Use a test server from fixtures/tls/
    runner = CliRunner()
    result = runner.invoke(main, ['scan', 'domain', 'localhost', '--port', '18443'])
    assert 'RSA' in result.output or 'TLS' in result.output
```

---

## BUILD ORDER

CLI is built AFTER the audit platform scanner modules exist.
The CLI imports directly from the scanner modules — it is not a separate implementation.

```
shared-scanner/           ← extract scanner/ and engines/ into shared package
├── scanner/
│   ├── network.py
│   ├── code.py
│   └── patterns/
└── engines/
    ├── classifier.py
    ├── risk.py
    └── cbom.py

seqr-audit/backend/  ← imports shared-scanner
seqr-cli/            ← also imports shared-scanner

This way: one scanner codebase, two products using it.
Pattern library updates benefit both products simultaneously.
```

