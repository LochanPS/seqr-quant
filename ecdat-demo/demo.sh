#!/usr/bin/env bash
# ECDAT — live terminal demo (bash fallback)
# Run:  bash demo.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$HERE/sample-repo"

banner() { echo; printf '=%.0s' {1..68}; echo; echo "  $1"; printf '=%.0s' {1..68}; echo; echo; }
pause() { read -r -p "  [Enter] to continue"; }

clear || true
banner "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool"
echo "  Scenario: 'ACME Bank' hands us a code repository."
echo "  They do NOT know what encryption is inside it. We will find out."
pause

banner "STEP 1 - The customer's codebase (5 languages)"
find "$REPO" -type f | sed "s#$REPO#sample-repo#"
echo; echo "  No inventory exists. Let's build one."
pause

banner "STEP 2 - Discover & assess (seqr scan code)"
seqr scan code "$REPO"
pause

banner "STEP 3 - Produce a standards-compliant CBOM (CycloneDX 1.6)"
python "$HERE/generate_cbom.py"
pause

banner "STEP 4 - Look inside the CBOM"
python -c "import json; d=json.load(open('$HERE/acme-bank.cbom.cdx.json')); print(json.dumps(d['components'][0], indent=2))"
echo; echo "  Full CBOM: $HERE/acme-bank.cbom.cdx.json"
pause

banner "STEP 5 (optional) - Live scan of a real service"
read -r -p "  Run a live TLS scan of a real domain? (y/N) " ans
if [ "$ans" = "y" ]; then
  read -r -p "  Domain (default razorpay.com): " d
  seqr scan domain "${d:-razorpay.com}"
fi

banner "Done - Discover -> Assess -> Recommend, in minutes not months."
echo "  Everything ran locally. No data left this machine."
