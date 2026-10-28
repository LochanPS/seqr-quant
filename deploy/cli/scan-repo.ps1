# scan-repo.ps1 — give a GitHub URL, get a live PQC code scan.
# Usage:
#   powershell -File scan-repo.ps1 https://github.com/jpadilla/pyjwt
param([Parameter(Mandatory=$true)][string]$Url)

$seqr = "C:\Users\pokka\.seqr-cli\Scripts\seqr.exe"
$dir  = Join-Path $env:TEMP ("seqrscan_" + [guid]::NewGuid().ToString('N').Substring(0,8))

Write-Host "==> cloning $Url ..." -ForegroundColor Cyan
git clone --depth 1 $Url $dir 2>&1 | Select-Object -Last 2
Write-Host "==> scanning $dir ..." -ForegroundColor Cyan
& $seqr scan code $dir
Write-Host "==> done. (clone left at $dir)" -ForegroundColor DarkGray
