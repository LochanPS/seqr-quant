@echo off
REM SeQr dashboard against the LOCAL backend (overrides any prod URL in .env.local).
REM Open http://localhost:3000 and sign in with demo@seqrlabs.com / demodemo123
setlocal
cd /d "%~dp0..\audit\frontend"
if not exist node_modules call npm install
set NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
set NEXT_PUBLIC_WS_URL=ws://localhost:8000
set BACKEND_URL=http://localhost:8000
set INTERNAL_API_URL=http://localhost:8000
npx next dev -p 3000
