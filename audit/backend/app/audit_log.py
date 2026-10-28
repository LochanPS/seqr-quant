"""
Append-only audit logging (A5): one row per authenticated mutating request.

An HTTP middleware records who/what/when for every successful mutating call under
``/api/v1`` made by an authenticated principal. Coverage is automatic — new mutating
routes are captured without per-handler wiring — as long as the route authenticates via
``get_current_user`` / ``get_current_agent`` (which stamp the principal onto
``request.state``; see :func:`app.security._stamp_audit_principal`). Auth endpoints that
mint their own tokens stamp the principal explicitly.

Writes never break the request: any failure to log is swallowed (and logged to stderr).
The log is write-only — there is no update/delete path.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("seqr.audit")

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


async def _write(**fields) -> None:
    """Persist one AuditEvent.

    Uses a fresh session (durability decoupled from the request). In tests the app
    overrides ``get_db`` with a shared in-memory session; honour that override so the
    audit rows land in the same database the test reads from.
    """
    import uuid as _uuid

    from app.database import AsyncSessionLocal, get_db
    from app.models.audit_event import AuditEvent

    org_id = fields.pop("org_id", None)
    oid = None
    if org_id:
        try:
            oid = _uuid.UUID(str(org_id))
        except (ValueError, TypeError, AttributeError):
            oid = None

    def _event():
        return AuditEvent(org_id=oid, **fields)

    from app.main import app  # lazy: avoids import cycle at module load

    override = app.dependency_overrides.get(get_db)
    if override is not None:
        # Test path: reuse the fixture's shared session (do not close it — the fixture owns it).
        agen = override()
        session = await agen.__anext__()
        session.add(_event())
        await session.commit()
        return

    async with AsyncSessionLocal() as session:
        session.add(_event())
        await session.commit()


async def record(
    *,
    org_id=None,
    actor: str | None = None,
    actor_type: str = "user",
    action: str,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
    target: str | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> None:
    """Write one audit event explicitly.

    For actions the middleware can't infer — notably GET-based flows like the OIDC
    callback (a login is a state change even though the HTTP method is GET). Never raises.
    """
    try:
        await _write(
            org_id=org_id,
            actor=actor,
            actor_type=actor_type,
            action=action,
            method=method,
            path=path,
            status_code=status_code,
            target=target,
            ip=ip,
            detail=detail,
        )
    except Exception:
        logger.exception("explicit audit record failed")


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        try:
            if (
                request.method in _MUTATING
                and response.status_code < 400
                and request.url.path.startswith("/api/v1")
            ):
                actor = getattr(request.state, "audit_actor", None)
                if actor:
                    route = request.scope.get("route")
                    template = getattr(route, "path", None) or request.url.path
                    params = request.scope.get("path_params") or {}
                    target = next(
                        (str(v) for k, v in params.items() if k == "id" or k.endswith("_id")),
                        None,
                    )
                    action = getattr(request.state, "audit_action", None) or f"{request.method} {template}"
                    await _write(
                        org_id=getattr(request.state, "audit_org_id", None),
                        actor=actor,
                        actor_type=getattr(request.state, "audit_actor_type", "user"),
                        action=action,
                        method=request.method,
                        path=request.url.path,
                        status_code=response.status_code,
                        target=target,
                        ip=_client_ip(request),
                        detail=getattr(request.state, "audit_detail", None),
                    )
        except Exception:  # never let audit logging break the response
            logger.exception("audit log write failed")
        return response
