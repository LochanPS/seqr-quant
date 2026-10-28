# ECDAT — live terminal demo (Windows PowerShell)
# Run:  powershell -ExecutionPolicy Bypass -File .\demo.ps1
# Press Enter between steps so you control the pacing on stage.

$ErrorActionPreference = "Stop"
$repo = Join-Path $PSScriptRoot "sample-repo"

function Banner($t) {
  Write-Host ""
  Write-Host ("=" * 68) -ForegroundColor DarkCyan
  Write-Host ("  " + $t) -ForegroundColor Cyan
  Write-Host ("=" * 68) -ForegroundColor DarkCyan
  Write-Host ""
}
function Pause-Demo { Read-Host "  [Enter] to continue" | Out-Null }

Clear-Host
Banner "ECDAT  -  Enterprise Cryptographic Discovery & Analysis Tool"
Write-Host "  Scenario: 'ACME Bank' hands us a code repository." -ForegroundColor White
Write-Host "  They do NOT know what encryption is inside it. We will find out." -ForegroundColor Gray
Pause-Demo

Banner "STEP 1  -  The customer's codebase (5 languages)"
Get-ChildItem -Recurse -File $repo | ForEach-Object {
  Write-Host ("    " + $_.FullName.Replace($repo, "sample-repo")) -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Nobody has an inventory of the cryptography in here. Let's build one." -ForegroundColor White
Pause-Demo

Banner "STEP 2  -  Discover & assess  (seqr scan code)"
Write-Host "  Scanning every file for quantum-vulnerable cryptography..." -ForegroundColor White
Write-Host ""
seqr scan code $repo
Pause-Demo

Banner "STEP 3  -  Produce a standards-compliant CBOM (CycloneDX 1.6)"
Write-Host "  Aggregating findings into a Cryptographic Bill of Materials..." -ForegroundColor White
Write-Host ""
python (Join-Path $PSScriptRoot "generate_cbom.py")
Write-Host "  This is a real, standard CBOM any compliance tool can ingest." -ForegroundColor White
Pause-Demo

Banner "STEP 4  -  Look inside the CBOM"
$cbom = Join-Path $PSScriptRoot "acme-bank.cbom.cdx.json"
Write-Host "  First cryptographic-asset entry in the CBOM:" -ForegroundColor Gray
Write-Host ""
python -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d['components'][0], indent=2))" $cbom
Write-Host ""
Write-Host "  Full CBOM saved at: $cbom" -ForegroundColor Green
Pause-Demo

Banner "STEP 5 (optional)  -  Live scan of a real service (needs internet)"
$ans = Read-Host "  Run a live TLS scan of a real domain? (y/N)"
if ($ans -eq "y") {
  $d = Read-Host "  Domain (e.g. razorpay.com)"
  if ([string]::IsNullOrWhiteSpace($d)) { $d = "razorpay.com" }
  seqr scan domain $d
}

Banner "Done  -  Discover -> Assess -> Recommend, in minutes not months."
Write-Host "  Everything ran locally. No data left this machine." -ForegroundColor White
Write-Host ""
