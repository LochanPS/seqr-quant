"""Remediation planner API — budget-constrained fix selection over risk-v2 findings.

Stateless and read-only: the caller posts a risk-v2 report (``seqr scan code --context ...
--output json``) or asks for the bundled ACME sample, plus an engineer-hour budget. Nothing is
stored and no org data is read, so there is no tenancy surface beyond authentication.

Solvers: greedy (value per hour), exhaustive (certified optimum, small instances), QpiAI Opt
(native HUBO, needs the Opt key + network), optional QpiAI QCloud QAOA (alternative plans).
A solver that is unavailable reports an error in its slot instead of failing the request.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.migration import remediation as rem
from app.models.user import User
from app.routers.spine import ranked_components
from app.security import get_current_user

router = APIRouter()

_SAMPLE = Path(__file__).resolve().parents[4] / "examples" / "acme-risk-v2.json"
_MAX_FINDINGS = 2000

HNDL_DISCLAIMER = (
    "HNDL exposure scores are predictive cryptographic risk metrics based on data-type "
    "endurance, not indicators of active data interception or confirmed network breaches."
)


QCloudDevice = Literal["QpiAI-QSV-Simulator", "QpiAI-QDM-Simulator", "QpiAI-QTN-Simulator",
                       "QpiAI-QSV-Lite", "QpiAI-QDM-Lite", "QpiAI-Indus-1"]


class PlanRequest(BaseModel):
    report: Optional[dict[str, Any]] = Field(
        default=None, description="risk-v2 report; omit to use the bundled ACME sample")
    budget: float = Field(default=40, gt=0, le=10_000, description="engineer-hours available")
    use_opt: bool = True
    use_qaoa: bool = False
    curve: list[float] = Field(default_factory=lambda: [20, 40, 80], max_length=8)
    qaoa_device: Optional[QCloudDevice] = Field(
        default=None, description="sample the trained QAOA circuit on this QpiAI QCloud backend (one job)")
    qaoa_warm_start: bool = Field(default=False, description="warm-start QAOA from the best classical plan")
    opt_platform: bool = Field(default=False, description="also solve on QpiAI's hosted Opt platform (one job)")


def _plan_out(p: rem.Plan | None) -> dict | None:
    if p is None:
        return None
    return {"method": p.method, "chosen": p.chosen, "effort": p.effort, "budget": p.budget,
            "residual": p.residual, "removed_pct": round(p.removed_pct, 1),
            "feasible": p.feasible, "solver_time_s": p.solver_time_s, "detail": p.detail}


_FINDING_KEYS = ("rel_path", "line_number", "algorithm", "score", "tier", "role",
                 "exposure", "hndl", "effort_hours", "top_reason", "slot_key", "asset_type")


def _compute(report: dict, req: PlanRequest) -> dict:
    findings = rem.findings_from_dict(report)
    return _solve(findings, rem.build_actions(findings), report["findings"], req)


def _solve(findings: list[rem.Finding], actions: list[rem.Action], shown: list[dict],
           req: PlanRequest) -> dict:
    out: dict[str, Any] = {
        "baseline_risk": round(sum(f.score for f in findings), 1),
        "budget": req.budget,
        "actions": [{"id": a.id, "label": a.label, "effort": a.effort, "covers": len(a.covers)}
                    for a in actions],
        "findings": [{k: f.get(k) for k in _FINDING_KEYS}
                     for f in sorted(shown, key=lambda f: -float(f["score"]))],
        "plans": {}, "errors": {},
        "notes": [
            "Coverage fractions and efforts are stated assumptions, not measurements.",
            HNDL_DISCLAIMER,
        ],
    }
    greedy = rem.plan_greedy(findings, actions, req.budget)
    exact = rem.plan_exhaustive(findings, actions, req.budget)
    out["plans"]["greedy"] = _plan_out(greedy)
    out["plans"]["exhaustive"] = _plan_out(exact)

    opt = None
    if req.use_opt:
        try:
            opt = rem.plan_opt(findings, actions, req.budget)
            out["plans"]["opt"] = _plan_out(opt)
        except Exception as e:  # missing key, auth service down, local limits
            out["errors"]["opt"] = f"{type(e).__name__}: {e}"

    # Risk curve: exhaustive is instant and certified on small instances; Opt otherwise.
    curve = []
    for b in sorted({float(x) for x in req.curve if x > 0}):
        try:
            p = rem.plan_exhaustive(findings, actions, b) if exact else rem.plan_opt(findings, actions, b)
            curve.append({"budget": b, "removed_pct": round(p.removed_pct, 1), "chosen": p.chosen,
                          "method": p.method})
        except Exception as e:
            out["errors"].setdefault("curve", f"{type(e).__name__}: {e}")
            break
    out["curve"] = curve

    if req.use_qaoa:
        try:
            known = [p for p in (opt, exact, greedy) if p and p.feasible]
            focus = rem.contested_actions(known, findings, actions)
            best = min(known, key=lambda p: p.residual) if known else None
            out["qaoa"] = rem.plan_alternatives_qaoa(
                findings, actions, req.budget, focus,
                best_known=best.residual if best else None,
                warm_start_plan=best.chosen if (req.qaoa_warm_start and best) else None,
                device=req.qaoa_device)
            out["notes"].append(
                f"QAOA explores {2 ** len(focus)} plans with 1024 shots, so sampling covers the space; "
                "the alternatives menu is not evidence of quantum advantage.")
        except Exception as e:
            out["errors"]["qaoa"] = f"{type(e).__name__}: {e}"

    if req.opt_platform:
        try:
            out["plans"]["opt_platform"] = _plan_out(rem.plan_opt(findings, actions, req.budget, mode="platform"))
        except Exception as e:  # quota / access: QpiAI's message, local Opt result stands
            out["errors"]["opt_platform"] = rem._qcloud_error(e)

    if opt and exact:
        out["opt_gap_to_optimum"] = round(opt.residual - exact.residual, 2)
    return out


@router.post("/plan")
async def plan(req: PlanRequest, current_user: Annotated[User, Depends(get_current_user)]):
    if req.report is None:
        if not _SAMPLE.exists():
            raise HTTPException(status_code=404, detail="bundled sample report not found")
        report = json.loads(_SAMPLE.read_text(encoding="utf-8"))
        source = "sample:acme-risk-v2"
    else:
        report = req.report
        source = "uploaded"
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list) or not findings:
        raise HTTPException(status_code=422, detail="report.findings must be a non-empty list")
    if len(findings) > _MAX_FINDINGS:
        raise HTTPException(status_code=422, detail=f"at most {_MAX_FINDINGS} findings per request")
    try:
        result = await run_in_threadpool(_compute, report, req)
    except (KeyError, TypeError, ValueError) as e:
        raise HTTPException(status_code=422, detail=f"malformed risk-v2 report: {e}")
    result["source"] = source
    rem.log_qpiai_run(result)
    return result


class InfraPlanRequest(BaseModel):
    budget: float = Field(default=24, gt=0, le=10_000, description="engineer-hours available")
    use_opt: bool = True
    use_qaoa: bool = False
    curve: list[float] = Field(default_factory=lambda: [8, 24, 48], max_length=8)
    qaoa_device: Optional[QCloudDevice] = None
    qaoa_warm_start: bool = False
    opt_platform: bool = False


@router.post("/plan-infra")
async def plan_infra(
    req: InfraPlanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Choose infrastructure fixes for the caller's org under an engineer-hour budget.

    Findings come from the org's own crypto graph (same ranking as ``GET /graph/risk``,
    org-scoped); actions are per-asset (hybrid KEX, SSH PQ KEX, cert reissue, origin lock,
    full migration) plus org-wide segmentation. Read-only: nothing is stored.
    """
    _summary, comps = await ranked_components(db, current_user.org_id)
    findings = rem.infra_findings_from_components(comps)
    if not findings:
        raise HTTPException(status_code=422, detail="no quantum-vulnerable crypto in this org's graph yet")
    if len(findings) > _MAX_FINDINGS:
        raise HTTPException(status_code=422, detail=f"at most {_MAX_FINDINGS} findings per plan")
    actions = rem.build_infra_actions(findings)
    shown = [c for c in comps if float(c["score"]) > 0]
    result = await run_in_threadpool(_solve, findings, actions, shown, PlanRequest(
        **req.model_dump()))
    result["notes"].insert(1, "Public WebPKI cannot issue ML-DSA certificates yet: internet-facing "
                              "certificate actions only shorten exposure; internal PKI can migrate fully.")
    result["source"] = "org-graph"
    rem.log_qpiai_run(result)
    return result


def _qcloud_devices() -> list[dict]:
    from qpiai_opt.quantum import QpiAIQuantumAuth
    from qpiai_quantum.jobmanager import JobManager

    _, key = rem._keys()
    if not key:
        raise RuntimeError("QCLOUD_API_KEY not set")
    QpiAIQuantumAuth.login(api_key=key)
    return [{"device": d.get("device_name"), "status": d.get("status"), "usage_rate": d.get("usage_rate"),
             "method": d.get("method")} for d in JobManager().list_compute_resources()]


@router.get("/qpiai/devices")
async def qpiai_devices(current_user: Annotated[User, Depends(get_current_user)]):
    """QpiAI QCloud backends and their status (e.g. the Indus-1 QPU in maintenance).

    Account-level device catalogue only; no job history, so nothing crosses tenants.
    """
    try:
        return {"devices": await run_in_threadpool(_qcloud_devices), "error": None}
    except Exception as e:
        return {"devices": [], "error": rem._qcloud_error(e)}
