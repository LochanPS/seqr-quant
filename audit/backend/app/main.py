import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt

from app.config import settings
from app.routers import auth, organisation, assets, scans, cbom, risk, reports, public, admin, blog, spine, migration, ci, github_app, agent, audit, sso, saml


@asynccontextmanager
async def lifespan(app):
    # Dev convenience: create any missing tables on startup (no Alembic wired yet).
    # Safe + idempotent for SQLite/dev; production should use real migrations.
    if settings.DATABASE_URL.startswith("sqlite"):
        from app.database import Base, engine
        import app.models  # noqa: F401 — ensure all models are registered
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # Boot-seed the demo org for hosts without a shell (e.g. Render free tier). Idempotent:
    # seeds only when empty, so it's safe to leave enabled and it self-heals if a free-tier
    # database is wiped. Never blocks startup on failure.
    if settings.SEED_DEMO_ON_BOOT:
        try:
            from app.migration.seed_db import seed_if_empty
            seeded = seed_if_empty()
            print(f"[boot-seed] demo org {'seeded' if seeded else 'already present'}")
        except Exception as e:  # pragma: no cover — never crash boot on seed failure
            print(f"[boot-seed] skipped: {e}")

    if settings.DEPLOYMENT_MODE == "onprem":
        from app.license.validator import validate_license
        if not settings.LICENSE_KEY:
            if settings.ENVIRONMENT == "production":
                raise RuntimeError("LICENSE_KEY required in production")
        elif settings.LICENSE_PUBLIC_KEY:
            info = validate_license(settings.LICENSE_KEY, settings.LICENSE_PUBLIC_KEY)
            if not info.valid:
                raise RuntimeError(f"Invalid license: {info.error}")
            if info.expired and not info.grace_period:
                raise RuntimeError("License expired. Contact support.")
            if info.expired and info.grace_period:
                print(
                    "WARNING: License expired. "
                    "30-day grace period active. "
                    "Renew immediately."
                )
    yield


app = FastAPI(
    title="SeQr Audit API",
    version="1.0.0",
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    lifespan=lifespan,
)

# FRONTEND_URL may be a comma-separated list (e.g. custom domain + vercel URL).
_cors_origins = [o.strip() for o in settings.FRONTEND_URL.split(",") if o.strip()]
if settings.ENVIRONMENT != "production":
    _cors_origins.append("http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    """Baseline security headers — expected of any product sold to security teams."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# Append-only audit log: records every authenticated mutating request (A5).
from app.audit_log import AuditMiddleware  # noqa: E402

app.add_middleware(AuditMiddleware)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(organisation.router, prefix="/api/v1/org", tags=["org"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(cbom.router, prefix="/api/v1/cbom", tags=["cbom"])
app.include_router(risk.router, prefix="/api/v1/risk", tags=["risk"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(public.router, prefix="/api/v1/public", tags=["public"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(blog.router, prefix="/api/v1/blog", tags=["blog"])
app.include_router(spine.router, prefix="/api/v1/graph", tags=["graph"])
app.include_router(migration.router, prefix="/api/v1/migration", tags=["migration"])
app.include_router(ci.router, prefix="/api/v1/ci", tags=["ci"])
app.include_router(github_app.router, prefix="/api/v1/github", tags=["github-app"])
app.include_router(agent.router, prefix="/api/v1/agent", tags=["agent"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])
app.include_router(sso.router, prefix="/api/v1/sso", tags=["sso"])
app.include_router(saml.router, prefix="/api/v1/saml", tags=["saml"])


@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "mode": settings.DEPLOYMENT_MODE,
    }


@app.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(...),
):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "access":
            await websocket.close(code=1008)
            return
        token_org_id = payload.get("org_id")
        if not token_org_id:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    # Tenancy: the scan MUST belong to the caller's org, or this channel would
    # leak another org's live scan progress. Validate before subscribing.
    import uuid as _uuid

    from app.database import AsyncSessionLocal
    from app.models.scan import Scan

    try:
        scan_uuid = _uuid.UUID(scan_id)
    except ValueError:
        await websocket.close(code=1008)
        return

    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_uuid)
        if not scan or str(scan.org_id) != str(token_org_id):
            await websocket.close(code=1008)
            return

    await websocket.accept()

    import redis.asyncio as aredis

    r = aredis.from_url(settings.REDIS_URL)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data_bytes = message["data"]
                text = data_bytes.decode() if isinstance(data_bytes, bytes) else data_bytes
                await websocket.send_text(text)
                data = json.loads(text)
                if data.get("type") in ("complete", "failed"):
                    break
    except Exception:
        pass
    finally:
        await pubsub.unsubscribe(f"scan:{scan_id}")
        await r.aclose()
