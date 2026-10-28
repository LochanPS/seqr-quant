"""The four SeQr capabilities exposed to the reasoning model as tools (A4 / PRD 15).

Each tool is a thin, read-mostly shim over an existing org-scoped FastAPI endpoint — no new
backend logic lives here. The model calls them to build a picture of an org's crypto posture
and then proposes a migration order. The agent is advisory: ``propose_migration_order`` runs
the migration engine's *dry-run* (nothing is persisted, no bundle is signed, no customer infra
is touched) — humans apply.

Named exactly as the A4 spec requires: scan_domain, get_cbom, get_policy_violations,
propose_migration_order. Wrapped as Strands ``@tool`` functions so they run inside the
AgentCore Runtime container; the Gateway-hosted MCP variant is an optional upgrade documented
in the README (it costs an extra authorizer + Gateway resource, so the lean default keeps the
tools in-runtime).
"""

import time

from strands import tool

from .seqr_client import SeqrClient, SeqrClientError

# One client per process; env-configured. Constructed lazily so import never fails.
_client: SeqrClient | None = None


def _c() -> SeqrClient:
    global _client
    if _client is None:
        _client = SeqrClient()
    return _client


def _err(name: str, exc: Exception) -> dict:
    # Return the error as data so the model can reason/retry instead of the turn aborting.
    return {"ok": False, "tool": name, "error": str(exc)}


@tool
def scan_domain(target: str, wait: bool = True) -> dict:
    """Trigger a fresh crypto scan of one asset and return when it finishes.

    Args:
        target: the asset's id (uuid) or its host/domain name (e.g. "api.example.com").
        wait: if true, poll until the scan completes (up to ~90s) before returning.

    Returns a summary of the completed scan, or the enqueued job if wait is false. Use this
    only when posture may be stale; if a recent CBOM already exists, prefer get_cbom.
    """
    try:
        c = _c()
        asset_id = target
        # Resolve a domain to an asset id if a bare host was given.
        if "-" not in target or "." in target:
            assets = c.get("/assets") or []
            match = next(
                (a for a in assets if target in (a.get("name", ""), a.get("id", ""),
                                                 a.get("target", ""), a.get("host", ""))),
                None,
            )
            if match:
                asset_id = match["id"]
        job = c.post(f"/assets/{asset_id}/scan")
        scan_id = (job or {}).get("scan_id") or (job or {}).get("id")
        if not wait or not scan_id:
            return {"ok": True, "enqueued": True, "asset_id": asset_id, "job": job}
        for _ in range(30):  # ~90s cap; scans finish in seconds-to-a-minute
            time.sleep(3)
            scan = c.get(f"/scans/{scan_id}") or {}
            if scan.get("status") in ("complete", "completed", "failed", "error"):
                return {"ok": True, "asset_id": asset_id, "scan": scan}
        return {"ok": True, "asset_id": asset_id, "scan_id": scan_id, "note": "still running"}
    except SeqrClientError as exc:
        return _err("scan_domain", exc)


@tool
def get_cbom() -> dict:
    """Return the org's cryptographic bill of materials: a component roll-up plus the most
    quantum-vulnerable components. This is the primary posture read — call it first.

    Counts are by quantum_status, algorithm family, threat timeline (IMMEDIATE/URGENT/
    PLANNED/ROADMAP) and deployment level, with the average crypto-agility score.
    """
    try:
        c = _c()
        summary = c.get("/cbom/summary") or {}
        listing = c.get("/cbom", params={"page_size": 50}) or {}
        items = listing.get("items", []) if isinstance(listing, dict) else (listing or [])
        # Surface the worst offenders so the model does not have to page the full list.
        vulnerable = [
            x for x in (items or [])
            if isinstance(x, dict) and x.get("quantum_status") == "vulnerable"
        ][:20]
        return {"ok": True, "summary": summary, "top_vulnerable": vulnerable}
    except SeqrClientError as exc:
        return _err("get_cbom", exc)


@tool
def get_policy_violations() -> dict:
    """Return the org's current policy violations together with the HNDL exposure list and
    compliance-framework status — the risk context the migration order must respect.

    HNDL (harvest-now-decrypt-later) scores are predictive risk metrics based on data-type
    endurance, not evidence of interception. Compliance covers the live Indian hooks
    (PCI DSS 12.3.3, SEBI CSCRF) and the emerging ones (RBI Q-SAFE, DST 2027, DPDP 2027).
    """
    try:
        c = _c()
        violations = c.get("/graph/violations/current") or []
        hndl = c.get("/risk/hndl") or []
        compliance = c.get("/risk/compliance") or {}
        return {
            "ok": True,
            "current_violations": violations,
            "hndl_exposure": hndl,
            "compliance": compliance,
        }
    except SeqrClientError as exc:
        return _err("get_policy_violations", exc)


@tool
def propose_migration_order() -> dict:
    """Run the migration engine's dry-run for the latest evaluation and return the ordered,
    non-destructive change set (converge actual crypto -> policy). Nothing is persisted and no
    infrastructure is changed — this is the advisory plan the agent reasons over and presents
    for a human to apply as a signed bundle + runbook.
    """
    try:
        return {"ok": True, "dry_run": _c().post("/migration/dry-run")}
    except SeqrClientError as exc:
        return _err("propose_migration_order", exc)


# The exact set handed to the agent, in call-order preference.
ALL_TOOLS = [get_cbom, get_policy_violations, propose_migration_order, scan_domain]
