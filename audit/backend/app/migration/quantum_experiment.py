"""QpiAI QCloud QAOA experiment on the migration-scheduling problem (QUANT-A-MAZE / PQC-01).

The classical scheduler (``optimize.py``) solves the full higher-order problem with QpiAI Opt's
native HUBO solver. Here we show the SAME decision solved on a quantum circuit.

QAOA is a 2-local (QUBO/Ising) algorithm, so we take a *reduced* instance — the exact crew
bottleneck the full optimiser found: three high-risk changes that all become schedulable at once,
a change crew that can safely run only two together, and two maintenance waves to place them in.

Binary x[i,t] = change i runs in wave t. The objective is the 2-local (QUBO) form of the same
scheduling goal:

    minimise  Σ_i Σ_t risk_i·t·x[i,t]                    # retire high-risk crypto earliest
            + A·Σ_i (Σ_t x[i,t] − 1)²                    # each change in exactly one wave
            + K·Σ_t Σ_{i<j} x[i,t]·x[j,t]                # spread risky work across waves (crew)

We solve this reduced QUBO two ways and compare on the identical objective:
  • QpiAI Opt   — classical QUBO solver (the reference optimum),
  • QpiAI QCloud — QAOA on the local quantum simulator (``QpiAI-QSV-Local``, zero cloud credits).

Honesty: the full crew rule ("≤2 of 3 together") is a degree-3 interaction — native HUBO on the
classical side. QAOA runs its standard 2-local relaxation here; a genuinely higher-order quantum
solve (RecursiveQAOA / ADAPT-QAOA) is a documented next step, not claimed in this experiment.
"""

from __future__ import annotations

import os
from pathlib import Path

from app.migration.optimize import CREW_CAP, SchedItem, score, _RISK_BY_SEVERITY

_W_ONCE = 50.0   # each change in exactly one wave  (hard structural penalty)
_W_CREW = 10.0   # pairwise same-wave repulsion     (spread risky work → respect the crew cap)


def reduced_instance() -> list[SchedItem]:
    """The crew bottleneck, zoomed in: 3 high-risk payment-path changes, all ready together."""
    I = _RISK_BY_SEVERITY["immediate"]
    return [
        SchedItem("pay_kex",  "payment-api: enable_hybrid_kex", I, 1),
        SchedItem("auth_kex", "auth-svc: enable_hybrid_kex",    I, 1),
        SchedItem("kyc_kex",  "kyc-svc: enable_hybrid_kex",     I, 1),
    ]


def build_qubo_model(items: list[SchedItem], num_waves: int = 2):
    """Degree-2 (QUBO) scheduling model over x[i,t]. Reused for both the classical and QAOA solve."""
    from qpiai_opt.opt_modeller import Binary, Model

    T = num_waves
    x = {(it.id, t): Binary(f"x__{it.id}__{t}") for it in items for t in range(T)}
    expr = 0

    # retire high-risk crypto in the earliest wave
    for it in items:
        for t in range(T):
            if it.risk * t:
                expr = expr + it.risk * t * x[(it.id, t)]

    # exactly one wave per change: (Σ_t x − 1)^2 = 1 − Σ x_t + 2 Σ_{a<b} x_a x_b   (binary)
    for it in items:
        xs = [x[(it.id, t)] for t in range(T)]
        once = 1
        for xi in xs:
            once = once - xi
        for a in range(T):
            for b in range(a + 1, T):
                once = once + 2 * xs[a] * xs[b]
        expr = expr + _W_ONCE * once

    # crew: penalise every pair of risky changes sharing a wave → spreads them out
    risky = [it for it in items if it.risky]
    for t in range(T):
        for i in range(len(risky)):
            for j in range(i + 1, len(risky)):
                expr = expr + _W_CREW * x[(risky[i].id, t)] * x[(risky[j].id, t)]

    model = Model("migration_schedule_qubo_reduced")
    model.minimize(expr)
    return model, T


def _waves_from_assignment(items, assignment: dict, T: int) -> dict[str, int]:
    waves: dict[str, int] = {}
    for it in items:
        for t in range(T):
            if round(float(assignment.get(f"x__{it.id}__{t}", 0))) == 1:
                waves[it.id] = t
                break
    return waves


def _login_opt():
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[4] / ".env")
    opt = os.environ.get("QPIAI_OPT_API_KEY")
    qc = os.environ.get("QCLOUD_API_KEY")
    if not opt or not qc:
        raise RuntimeError("QPIAI_OPT_API_KEY / QCLOUD_API_KEY missing — fill seqr-quant/.env")
    return opt, qc


def solve_classical(items, num_waves: int = 2) -> dict:
    """Reference optimum via QpiAI Opt's classical QUBO solver."""
    from qpiai_opt.opt_solvers import Client, solve
    opt_key, _ = _login_opt()
    model, T = build_qubo_model(items, num_waves)
    r = solve(model, mode="local", client=Client(api_key=opt_key))
    assignment = model.decode_qubo_sample(r.solution)
    waves = _waves_from_assignment(items, assignment, T)
    exposure, scored, overloaded = score(items, waves)
    return {"method": f"qpiai_opt:{getattr(r,'problem_class','?')}", "waves": waves,
            "exposure": exposure, "scored": scored, "overloaded": overloaded,
            "solver_objective": r.objective}


def solve_qaoa(items, num_waves: int = 2, reps: int = 3, max_iterations: int = 120) -> dict:
    """Same reduced QUBO on a quantum circuit (QAOA) via QpiAI QCloud's local simulator."""
    from qpiai_opt.opt_solvers import solve
    from qpiai_opt.opt_solvers.qubo import QUBOProblem
    from qpiai_opt.quantum import QAOA, QpiAIQuantumAuth
    _, qc_key = _login_opt()
    QpiAIQuantumAuth.login(api_key=qc_key)

    model, T = build_qubo_model(items, num_waves)
    matrix, offset = model.to_qubo_dict()
    names = model.qubo_variable_names
    problem = QUBOProblem(qubo_dict=matrix, num_variables=len(names), offset=offset,
                          sense="MIN", variable_names=names)
    r = solve(problem, mode="local", algorithm=QAOA(reps=reps, max_iterations=max_iterations))
    assignment = model.decode_qubo_sample(r.solution)
    waves = _waves_from_assignment(items, assignment, T)
    exposure, scored, overloaded = score(items, waves)
    return {"method": f"qaoa:{getattr(r,'problem_class','?')}:local-sim", "qubits": len(names),
            "reps": reps, "waves": waves, "exposure": exposure, "scored": scored,
            "overloaded": overloaded, "solver_objective": r.objective}


def run_experiment() -> dict:
    items = reduced_instance()
    classical = solve_classical(items)
    quantum = solve_qaoa(items)
    quantum["matches_classical_optimum"] = (
        quantum["waves"] and quantum["scored"] <= classical["scored"] + 1e-6
    )
    return {"items": items, "classical": classical, "quantum": quantum}


def _print(tag: str, res: dict, items: list[SchedItem]) -> None:
    label = {it.id: it.label for it in items}
    risky = {it.id for it in items if it.risky}
    by_wave: dict[int, list[str]] = {}
    for iid, w in res["waves"].items():
        by_wave.setdefault(w, []).append(("*" if iid in risky else " ") + label[iid])
    q = f" | qubits={res['qubits']} reps={res['reps']}" if "qubits" in res else ""
    crew = f" crew-overloaded {res['overloaded']}" if res["overloaded"] else " crew OK"
    print(f"  [{tag}] {res['method']}{q}")
    print(f"        exposure={res['exposure']}  scored={res['scored']} ({crew.strip()})  "
          f"solver_obj={res['solver_objective']}")
    for w in sorted(by_wave):
        print(f"        wave {w}: {', '.join(sorted(by_wave[w]))}")


if __name__ == "__main__":
    out = run_experiment()
    items = out["items"]
    print(f"=== QCloud QAOA experiment - reduced migration instance "
          f"({len(items)} high-risk changes, crew cap {CREW_CAP}, 2 waves) ===\n")
    _print("Classical (QpiAI Opt)", out["classical"], items)
    print()
    _print("Quantum (QAOA)", out["quantum"], items)
    print(f"\nQAOA matches classical optimum: {out['quantum']['matches_classical_optimum']}")
