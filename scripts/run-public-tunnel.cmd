@echo off
REM Free public HTTPS link to the local SeQr dashboard (port 3000). No AWS, no
REM account, no card. Run AFTER run-local-backend.cmd and run-public-frontend.cmd.
REM
REM Look for a line like:  https://<random-words>.trycloudflare.com
REM Share that link. Keep this window OPEN during the demo; closing it ends the link.
REM Each run gives a NEW url, so start this right before you present.
setlocal
set CF=%~dp0..\.local\cloudflared.exe
if not exist "%CF%" (
  echo Downloading cloudflared ^(one time^)...
  if not exist "%~dp0..\.local" mkdir "%~dp0..\.local"
  curl -L -o "%CF%" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
)
echo.
echo ================================================================
echo  Starting the public link. Your URL appears below as
echo  https://^<random^>.trycloudflare.com  -- share that.
echo  Keep this window OPEN during the demo.
echo ================================================================
echo.
"%CF%" tunnel --url http://localhost:3000
