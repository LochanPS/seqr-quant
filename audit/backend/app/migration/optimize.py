"""QpiAI Opt migration-wave scheduler — native HUBO formulation (QUANT-A-MAZE / PQC-01).

The baseline planner (``planner.py``) emits ChangeItems with ``depends_on`` edges but leaves the
*order* implicit. This module makes the real combinatorial decision the migration needs:

    Assign every ChangeItem to a migration *wave* so that high-risk crypto is retired earliest,
    nothing runs before something it depends on, and no single maintenance window exceeds the
    change crew's capacity for simultaneous HIGH-RISK changes.

Binary decision variables ``x[i,t] = 1  ⇔  ChangeItem i is applied in wave t``. The objective is
a polynomial over those binaries:

    minimise   Σ_i Σ_t risk_i · t · x[i,t]                         # risk-weighted exposure
             + A · Σ_i ( Σ_t x[i,t] − 1 )²                         # each item in exactly one wave
             + C · Σ_(i dep d) Σ_{a} Σ_{b≥a} x[i,a]·x[d,b]         # d must be in an EARLIER wave
             + K · Σ_t Σ_{risky i<j<k} x[i,t]·x[j,t]·x[k,t]        # ≤2 high-risk changes per wave

That last term is a genuine **degree-3** interaction: a crew can safely supervise at most two
high-consequence changes in one window, and "3 risky together" is a 3-body penalty that does NOT
reduce to pairwise terms without auxiliary variables. QpiAI Opt's native higher-order **HUBO**
solver evaluates it directly — this is the substantive QCloud/Opt decision, not a decoration.

A naive "maximise parallelism" baseline (do every ready change each wave) is crew-unaware and
over-packs windows; QpiAI Opt finds the crew-respecting optimum. Scored on the same objective,
Opt wins. The same HUBO converts to QUBO→Ising (``hubo_to_qubo``) for the QAOA experiment.

DB-free core (plain SchedItems) so it runs in the demo without FastAPI/Postgres; qpiai_opt is
imported lazily so importing this module never drags the solver into the backend.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from itertools import combinations

# ── cost + policy model ───────────────────────────────────────────────────────
_RISK_BY_SEVERITY = {"immediate": 12, "urgent": 10, "planned": 4}
_RISK_DEFAULT = 6
_DOWNTIME_BY_ACTION = {
    "enable_hybrid_kex": 1, "enable_forward_secrecy_kex": 1,
    "harden_origin": 2, "reissue_cert_stronger": 3, "review": 1,
}
_DOWNTIME_DEFAULT = 2

RISKY_THRESHOLD = 8   # risk ≥ this = a HIGH-CONSEQUENCE change that consumes crew attention
CREW_CAP = 2          # at most this many risky changes share one wave (the HUBO constraint)

# penalty weights (hard structural penalties ≫ the exposure objective they guard)
_W_ONCE = 500.0
_W_PREC = 500.0
_W_CREW = 100.0       # per over-cap risky triple — must exceed delaying one item by a wave


@dataclass
class SchedItem:
    id: str
    label: str
    risk: int
    downtime: int = 1
    depends_on: list[str] = field(default_factory=list)

    @property
    def risky(self) -> bool:
        return self.risk >= RISKY_THRESHOLD


@dataclass
class Schedule:
    waves: dict[str, int]
    exposure: float            # Σ risk_i · wave(i)
    scored: float              # exposure + crew penalty (the full objective both methods are judged on)
    crew_overloaded_waves: list[int]
    makespan: int
    feasible: bool
    violations: list[str]
    method: str
    solver_time_s: float | None = None

    def order(self, items: list[SchedItem]) -> list[list[str]]:
        label = {it.id: it.label for it in items}
        by_wave: dict[int, list[str]] = {}
        for iid, w in self.waves.items():
            by_wave.setdefault(w, []).append(label.get(iid, iid))
        return [sorted(by_wave[w]) for w in sorted(by_wave)]


# ── sizing + scoring ──────────────────────────────────────────────────────────
def _chain_length(items: list[SchedItem]) -> int:
    by_id = {it.id: it for it in items}
    memo: dict[str, int] = {}

    def depth(iid, seen):
        if iid in memo:
            return memo[iid]
        it = by_id.get(iid)
        if not it or not it.depends_on or iid in seen:
            memo[iid] = 1
            return 1
        memo[iid] = 1 + max(depth(p, seen | {iid}) for p in it.depends_on if p in by_id)
        return memo[iid]

    return max((depth(it.id, frozenset()) for it in items), default=1)


def _num_waves(items: list[SchedItem], override: int | None) -> int:
    if override:
        return override
    n_risky = sum(1 for it in items if it.risky)
    # enough waves to honour the longest dependency chain AND to spread risky work under the cap
    return max(_chain_length(items), math.ceil(n_risky / CREW_CAP), 1) + 1


def score(items: list[SchedItem], waves: dict[str, int]) -> tuple[float, float, list[int]]:
    """Return (exposure, scored_with_crew_penalty, overloaded_wave_list)."""
    risk = {it.id: it.risk for it in items}
    risky = {it.id for it in items if it.risky}
    exposure = float(sum(risk[iid] * w for iid, w in waves.items()))
    per_wave: dict[int, int] = {}
    for iid, w in waves.items():
        if iid in risky:
            per_wave[w] = per_wave.get(w, 0) + 1
    crew_pen = 0.0
    overloaded = []
    for w, n in per_wave.items():
        if n > CREW_CAP:
            crew_pen += _W_CREW * math.comb(n, 3)  # mirrors Σ triples in the HUBO term
            overloaded.append(w)
    return exposure, exposure + crew_pen, sorted(overloaded)


def check_feasible(items, waves) -> tuple[bool, list[str]]:
    problems: list[str] = []
    by_id = {it.id: it for it in items}
    for it in items:
        if it.id not in waves:
            problems.append(f"{it.label}: not scheduled")
    for it in items:
        w = waves.get(it.id)
        if w is None:
            continue
        for dep in it.depends_on:
            dw = waves.get(dep)
            if dw is None or dw >= w:
                problems.append(f"{it.label}: dep {by_id.get(dep, dep).label if dep in by_id else dep} not earlier")
    return (not problems, problems)


# ── HUBO model + QpiAI Opt solve ───────────────────────────────────────────────
def build_hubo_model(items: list[SchedItem], num_waves: int):
    """Build the penalty-polynomial Model (classifies as HUBO). Reused by the QAOA experiment."""
    from qpiai_opt.opt_modeller import Binary, Model

    T = num_waves
    x = {(it.id, t): Binary(f"x__{it.id}__{t}") for it in items for t in range(T)}
    expr = 0

    # risk-weighted exposure: retire high-risk crypto in the earliest wave
    for it in items:
        for t in range(T):
            if it.risk * t:
                expr = expr + it.risk * t * x[(it.id, t)]

    # each item in exactly one wave: (Σ_t x - 1)^2 = 1 - Σ x_t + 2 Σ_{a<b} x_a x_b   (binary)
    for it in items:
        xs = [x[(it.id, t)] for t in range(T)]
        once = 1
        for xi in xs:
            once = once - xi
        for a in range(T):
            for b in range(a + 1, T):
                once = once + 2 * xs[a] * xs[b]
        expr = expr + _W_PREC * 0 + _W_ONCE * once

    # precedence: item i depends on d ⇒ penalise d scheduled in the same-or-later wave than i
    for it in items:
        for dep in it.depends_on:
            if not any(d.id == dep for d in items):
                continue
            for a in range(T):           # i's wave
                for b in range(a, T):    # d's wave ≥ i's wave = violation
                    expr = expr + _W_PREC * x[(it.id, a)] * x[(dep, b)]

    # crew cap (degree-3 HUBO): ≤ CREW_CAP risky changes per wave
    risky = [it for it in items if it.risky]
    for t in range(T):
        for i, j, k in combinations(risky, 3):
            expr = expr + _W_CREW * x[(i.id, t)] * x[(j.id, t)] * x[(k.id, t)]

    model = Model("migration_wave_schedule_hubo")
    model.minimize(expr)
    return model, x, T


def _decode(result, items, T) -> dict[str, int]:
    """Map the solver result back to one wave per item (handles dict / list / assignment forms)."""
    assign = getattr(result, "variable_assignment", None)
    sol = result.solution
    if assign is None and isinstance(sol, dict):
        assign = sol
    if assign is None and isinstance(sol, (list, tuple)):
        # fall back to declared order x__<id>__<t>, i<outer>, t<inner>
        names = [f"x__{it.id}__{t}" for it in items for t in range(T)]
        assign = {n: v for n, v in zip(names, sol)}
    waves: dict[str, int] = {}
    for it in items:
        picked = [t for t in range(T) if round(float((assign or {}).get(f"x__{it.id}__{t}", 0))) == 1]
        if picked:
            waves[it.id] = picked[0]
    return waves


def schedule_opt(items: list[SchedItem], num_waves: int | None = None, mode: str = "local") -> Schedule:
    from pathlib import Path
    from dotenv import load_dotenv
    from qpiai_opt.opt_solvers import Client, solve

    load_dotenv(Path(__file__).resolve().parents[4] / ".env")
    api_key = os.environ.get("QPIAI_OPT_API_KEY")
    if not api_key:
        raise RuntimeError("QPIAI_OPT_API_KEY not set — fill it into seqr-quant/.env")

    T = _num_waves(items, num_waves)
    model, _x, T = build_hubo_model(items, T)
    result = solve(model, mode=mode, client=Client(api_key=api_key))
    waves = _decode(result, items, T)

    exposure, scored, overloaded = score(items, waves)
    feasible, problems = check_feasible(items, waves)
    return Schedule(
        waves=waves, exposure=exposure, scored=scored, crew_overloaded_waves=overloaded,
        makespan=(max(waves.values()) + 1) if waves else 0, feasible=feasible, violations=problems,
        method=f"qpiai_opt:{getattr(result, 'problem_class', '?')}:{getattr(result, 'execution_mode', mode)}",
        solver_time_s=getattr(result, "solver_time_s", None),
    )


# ── baseline: naive maximise-parallelism (crew-unaware) ─────────────────────────
def schedule_baseline(items: list[SchedItem]) -> Schedule:
    """Layered topological: each wave runs EVERY change whose deps are already done.

    A plausible human policy ("do everything you can this window") — but crew-unaware, so it
    over-packs risky changes into the same wave. This is what QpiAI Opt improves on.
    """
    by_id = {it.id: it for it in items}
    waves: dict[str, int] = {}
    t = 0
    remaining = {it.id for it in items}
    while remaining:
        ready = [iid for iid in remaining
                 if all(d in waves for d in by_id[iid].depends_on if d in by_id)]
        if not ready:
            ready = list(remaining)  # cycle guard
        for iid in ready:
            waves[iid] = t
        remaining -= set(ready)
        t += 1

    exposure, scored, overloaded = score(items, waves)
    feasible, problems = check_feasible(items, waves)
    return Schedule(
        waves=waves, exposure=exposure, scored=scored, crew_overloaded_waves=overloaded,
        makespan=(max(waves.values()) + 1) if waves else 0, feasible=feasible, violations=problems,
        method="baseline:max_parallelism_topological",
    )


def compare(items: list[SchedItem], num_waves: int | None = None) -> dict:
    base = schedule_baseline(items)
    opt = schedule_opt(items, num_waves)
    return {
        "items": len(items),
        "baseline": base,
        "opt": opt,
        "scored_improvement": base.scored - opt.scored,
        "opt_wins_or_ties": opt.feasible and opt.scored <= base.scored,
    }


# ── adapters ──────────────────────────────────────────────────────────────────
def from_change_items(db, plan) -> list[SchedItem]:
    from app.models.migration import ChangeItem
    from app.models.policy import Violation

    out: list[SchedItem] = []
    for ci in db.query(ChangeItem).filter(ChangeItem.plan_id == plan.id).all():
        sev = None
        if ci.violation_id:
            v = db.get(Violation, ci.violation_id)
            sev = v.severity if v else None
        out.append(SchedItem(
            id=str(ci.id), label=f"{ci.action}@{ci.slot_key or ci.provider}",
            risk=_RISK_BY_SEVERITY.get((sev or "").lower(), _RISK_DEFAULT),
            downtime=_DOWNTIME_BY_ACTION.get(ci.action, _DOWNTIME_DEFAULT),
            depends_on=[str(d) for d in (ci.depends_on or [])],
        ))
    return out


def acme_bank_items() -> list[SchedItem]:
    """ACME Bank: 9 change items across 6 services, rooted at the shared cert gateway.

    After the gateway migrates (wave 0), four HIGH-RISK services become ready at once — more than
    the change crew can safely run together. That is where the crew-cap HUBO term bites.
    """
    I = _RISK_BY_SEVERITY["immediate"]
    U = _RISK_BY_SEVERITY["urgent"]
    P = _RISK_BY_SEVERITY["planned"]
    return [
        SchedItem("gw_kex",   "cert-gateway: enable_hybrid_kex",     U, 1),
        SchedItem("gw_cert",  "cert-gateway: reissue_cert_stronger", P, 3),
        SchedItem("pay_kex",  "payment-api: enable_hybrid_kex",      I, 1, ["gw_kex"]),
        SchedItem("auth_kex", "auth-svc: enable_hybrid_kex",         I, 1, ["gw_kex"]),
        SchedItem("kyc_kex",  "kyc-svc: enable_hybrid_kex",          I, 1, ["gw_kex"]),
        SchedItem("pay_orig", "payment-api: harden_origin",          U, 2, ["gw_cert"]),
        SchedItem("int_kex",  "internal-api: enable_forward_secrecy", U, 1, ["auth_kex"]),
        SchedItem("rep_kex",  "reporting: enable_hybrid_kex",        P, 1, ["gw_kex"]),
        SchedItem("rep_cert", "reporting: reissue_cert_stronger",    P, 3, ["rep_kex"]),
    ]


def _print(s: Schedule, items: list[SchedItem]) -> None:
    print(f"  method    : {s.method}")
    print(f"  feasible  : {s.feasible}" + ("" if s.feasible else f"  !! {s.violations}"))
    crew = f"   crew-overloaded waves: {s.crew_overloaded_waves}" if s.crew_overloaded_waves else "   crew OK"
    print(f"  exposure  : {s.exposure}   scored (w/ crew): {s.scored}{crew}")
    print(f"  makespan  : {s.makespan} waves"
          + (f"   solver: {s.solver_time_s:.3f}s" if s.solver_time_s else ""))
    risky = {it.id for it in items if it.risky}
    label = {it.id: it.label for it in items}
    by_wave: dict[int, list[str]] = {}
    for iid, w in s.waves.items():
        tag = "*" if iid in risky else " "
        by_wave.setdefault(w, []).append(tag + label[iid])
    for w in sorted(by_wave):
        print(f"    wave {w}: {', '.join(sorted(by_wave[w]))}")


if __name__ == "__main__":
    items = acme_bank_items()
    print(f"=== ACME Bank migration schedule - {len(items)} change items "
          f"(* = high-risk, crew cap {CREW_CAP}/wave) ===\n")
    r = compare(items)
    print("-- Baseline (naive max-parallelism, crew-unaware) --")
    _print(r["baseline"], items)
    print("\n-- QpiAI Opt (native HUBO) --")
    _print(r["opt"], items)
    print(f"\nscored objective: baseline={r['baseline'].scored}  opt={r['opt'].scored}  "
          f"improvement={r['scored_improvement']}  opt_wins_or_ties={r['opt_wins_or_ties']}")
