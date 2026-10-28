"""
Role-based access control — the org-level permission matrix (A5).

A user's ``role`` (a column on :class:`app.models.user.User`) maps to a fixed set of
permissions. Routes depend on a *permission*, never a hard-coded role string, so the
matrix can grow without touching every handler (see :func:`app.deps.require_permission`).

This is ORG-level RBAC and is distinct from the *platform operator* concept
(``OPERATOR_EMAILS`` / ``require_operator``), which gates SeQr Labs staff across every
tenant. The kickoff's "operator" role is named ``analyst`` here to avoid that collision.

Roles
-----
- ``admin``   — full control of the org: settings, users, billing-plan, audit log, all writes.
- ``analyst`` — does the work: assets, scans, migration plans/bundles, policy, attestation.
- ``auditor`` — read everything **plus** the audit log; no writes (compliance / SOC reviewer).
- ``viewer``  — read everything except the audit log; no writes.
- ``member``  — legacy default. Kept as an alias of ``analyst`` for back-compat with users
                created before this matrix existed.
"""
from __future__ import annotations

# --- Permissions (capabilities) ------------------------------------------------
# Dotted "<resource>:<verb>" strings. Reads are separated from writes so the
# read-only roles (viewer/auditor) can be expressed as "everything ending in :read".
ORG_READ = "org:read"
ORG_MANAGE = "org:manage"          # edit org profile, plan, settings
USERS_READ = "users:read"
USERS_MANAGE = "users:manage"      # invite users, change roles
ASSETS_READ = "assets:read"
ASSETS_WRITE = "assets:write"      # create / delete assets
SCANS_READ = "scans:read"
SCANS_RUN = "scans:run"
MIGRATION_READ = "migration:read"
MIGRATION_WRITE = "migration:write"
POLICY_WRITE = "policy:write"
REPORTS_READ = "reports:read"
ATTESTATION_WRITE = "attestation:write"
APIKEYS_MANAGE = "apikeys:manage"
AUDIT_READ = "audit:read"          # read the append-only audit log

# Every read capability. viewer/auditor get exactly this set of reads.
_READS = frozenset(
    {ORG_READ, USERS_READ, ASSETS_READ, SCANS_READ, MIGRATION_READ, REPORTS_READ}
)

# Every write / action capability an analyst may perform.
_WRITES = frozenset(
    {
        ASSETS_WRITE,
        SCANS_RUN,
        MIGRATION_WRITE,
        POLICY_WRITE,
        ATTESTATION_WRITE,
        APIKEYS_MANAGE,
    }
)

# Admin-only management capabilities.
_ADMIN_ONLY = frozenset({ORG_MANAGE, USERS_MANAGE, AUDIT_READ})

ALL_PERMISSIONS = _READS | _WRITES | _ADMIN_ONLY

# --- Role → permission matrix --------------------------------------------------
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": ALL_PERMISSIONS,
    "analyst": _READS | _WRITES,
    "member": _READS | _WRITES,               # legacy alias of analyst
    "auditor": _READS | frozenset({AUDIT_READ}),
    "viewer": _READS,
}

# Roles an admin may assign (validated on invite / role change).
VALID_ROLES = frozenset(ROLE_PERMISSIONS)


def has_permission(role: str | None, permission: str) -> bool:
    """True if ``role`` grants ``permission``. Unknown roles grant nothing."""
    return permission in ROLE_PERMISSIONS.get(role or "", frozenset())


def permissions_for(role: str | None) -> frozenset[str]:
    """The full permission set for a role (empty for an unknown role)."""
    return ROLE_PERMISSIONS.get(role or "", frozenset())
