@echo off
REM SeQr dashboard prepared for a PUBLIC tunnel.
REM API calls go to a RELATIVE /api/v1 path, which Next.js proxies to the local
REM backend server-side (no CORS, and the backend is never exposed directly).
REM
REM Order on demo day:
REM   1) scripts\run-local-backend.cmd      (port 8000)
REM   2) scripts\run-public-frontend.cmd    (this, port 3000)
REM   3) scripts\run-public-tunnel.cmd      (prints the public https link)
setlocal
cd /d "%~dp0..\audit\frontend"
if not exist node_modules call npm install
set NEXT_PUBLIC_API_URL=/api/v1
set INTERNAL_API_URL=http://localhost:8000
set BACKEND_URL=http://localhost:8000
npx next dev -p 3000
