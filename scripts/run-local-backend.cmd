@echo off
REM SeQr backend, fully local: SQLite + in-memory Redis + inline scan jobs. No Docker.
REM Seeds demo@seqrlabs.com / demodemo123 on first boot. API at http://localhost:8000
setlocal
set ROOT=%~dp0..
if not exist "%ROOT%\.local" mkdir "%ROOT%\.local"
cd /d "%ROOT%\audit\backend"
set ENVIRONMENT=development
set DATABASE_URL=sqlite+aiosqlite:///%ROOT:\=/%/.local/seqr_local.db
set USE_FAKE_REDIS=true
set CELERY_ALWAYS_EAGER=true
set SEED_DEMO_ON_BOOT=true
set FRONTEND_URL=http://localhost:3000
set PYTHONIOENCODING=utf-8
"%ROOT%\.venv-seqr\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
