"""Budget-constrained remediation selection with QpiAI Opt (HUBO) + QpiAI QCloud (QAOA sampling).

The question a CISO actually asks: *"I have N engineer-hours. Which fixes remove the most
quantum risk?"* Inputs are the context-aware risk-v2 findings (``seqr scan code --context ...
--output json``); outputs are a chosen remediation plan, the risk it removes, and alternatives.

Actions (each a real SeQr capability):
  fix:<file>        migrate that file's crypto                — removes 100% of its findings' risk
  edge:hybrid-kex   ML-KEM hybrid TLS at the gateway          — transit only: 50% of internet-facing
                                                                key-exchange/encryption, 25% of keygen
  segment:internal  segmentation + mTLS for internal services — 30% of internal/unknown-exposure risk
  sdk:pqcmap-<lang> adopt SeQr's pqcmap SDK in one language   — 70% of that language's findings

Binary y_a = 1 ⇔ action a is selected. Residual risk of finding f, covered by actions C(f):

    minimise  Σ_f  score_f · Π_{a ∈ C(f)} (1 − frac_{a,f} · y_a)
    s.t.      Σ_a  effort_a · y_a  ≤  budget

A finding covered by k actions contributes a degree-k term: overlapping coverage makes this a
genuine higher-order (HUBO) problem. QpiAI Opt solves it natively with the budget compiled as a
constraint. We compare against a greedy value-per-hour heuristic and, for small instances, an
exhaustive search that certifies the optimum.

QpiAI QCloud: QAOA is 2-local, so a reduced instance (the few most decisive actions) is reduced
HUBO → QUBO and sampled on the local simulator. Every sampled plan is re-scored exactly against
the real budget, giving ops a ranked menu of alternative feasible plans — and we report honestly
how much probability QAOA put on the optimum versus uniform sampling.

Coverage fractions and efforts are stated assumptions (see ``Assumptions``), not measurements.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

_LANG = {".py": "python", ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
         ".tsx": "javascript", ".mjs": "javascript", ".java": "java", ".go": "go"}


@dataclass(frozen=True)
class Assumptions:
    edge_effort: float = 6.0
    edge_frac_confidentiality: float = 0.5
    edge_frac_keygen: float = 0.25
    segment_effort: float = 8.0
    segment_frac: float = 0.3
    sdk_base_effort: float = 8.0
    sdk_per_file_effort: float = 3.0
    sdk_frac: float = 0.7


@dataclass(frozen=True)
class Finding:
    id: str
    rel_path: str
    line: int
    algorithm: str
    score: float
    role: str
    exposure: str
    effort: float
    tier: str = ""

    @property
    def language(self) -> str:
        return _LANG.get(PurePosixPath(self.rel_path).suffix.lower(), "other")


@dataclass
class Action:
    id: str
    label: str
    effort: float
    covers: dict[str, float] = field(default_factory=dict)  # finding id -> fraction of risk removed


# ── inputs ────────────────────────────────────────────────────────────────────

def load_findings(path: str | Path) -> list[Finding]:
    """Read risk-v2 JSON (``seqr scan code --ranked --output json``)."""
    return findings_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def findings_from_dict(data: dict) -> list[Finding]:
    """Risk-v2 report dict -> Findings. Raises KeyError/ValueError on malformed input."""
    out = []
    for f in data["findings"]:
        out.append(Finding(
            id=f"{f['rel_path']}:{f['line_number']}:{f['algorithm_family']}",
            rel_path=f["rel_path"], line=int(f["line_number"]), algorithm=f["algorithm"],
            score=float(f["score"]), role=f["role"], exposure=f["exposure"],
            effort=float(f.get("effort_hours") or 8), tier=f.get("tier", ""),
        ))
    return out


def build_actions(findings: list[Finding], a: Assumptions = Assumptions()) -> list[Action]:
    actions: list[Action] = []
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.rel_path, []).append(f)
    for path, fs in sorted(by_file.items()):
        actions.append(Action(f"fix:{path}", f"migrate crypto in {path}",
                              sum(f.effort for f in fs), {f.id: 1.0 for f in fs}))

    edge = {}
    for f in findings:
        if f.exposure == "internet" and f.role in {"key_exchange", "encryption"}:
            edge[f.id] = a.edge_frac_confidentiality
        elif f.exposure == "internet" and f.role == "keygen":
            edge[f.id] = a.edge_frac_keygen
    if edge:
        actions.append(Action("edge:hybrid-kex", "enable X25519MLKEM768 at the edge gateway", a.edge_effort, edge))

    seg = {f.id: a.segment_frac for f in findings if f.exposure in {"internal", "unknown"}}
    if seg:
        actions.append(Action("segment:internal", "network segmentation + mTLS for internal services",
                              a.segment_effort, seg))

    by_lang: dict[str, list[Finding]] = {}
    for f in findings:
        if f.role != "hash" and f.language != "other":
            by_lang.setdefault(f.language, []).append(f)
    for lang, fs in sorted(by_lang.items()):
        files = len({f.rel_path for f in fs})
        actions.append(Action(f"sdk:pqcmap-{lang}", f"adopt pqcmap hybrid KEM / ML-DSA in {lang}",
                              a.sdk_base_effort + a.sdk_per_file_effort * files,
                              {f.id: a.sdk_frac for f in fs}))
    return actions


# ── exact evaluation (ground truth for every method) ─────────────────────────

def residual(findings: list[Finding], actions: list[Action], chosen: set[str]) -> float:
    total = 0.0
    for f in findings:
        keep = f.score
        for act in actions:
            if act.id in chosen and f.id in act.covers:
                keep *= 1.0 - act.covers[f.id]
        total += keep
    return total


def effort(actions: list[Action], chosen: set[str]) -> float:
    return sum(a.effort for a in actions if a.id in chosen)


@dataclass
class Plan:
    method: str
    chosen: list[str]
    effort: float
    budget: float
    residual: float
    baseline_risk: float
    solver_time_s: float | None = None
    detail: str = ""

    @property
    def removed_pct(self) -> float:
        return 100.0 * (1 - self.residual / self.baseline_risk) if self.baseline_risk else 0.0

    @property
    def feasible(self) -> bool:
        return self.effort <= self.budget + 1e-9


def _plan(method, findings, actions, chosen, budget, t=None, detail=""):
    base = sum(f.score for f in findings)
    return Plan(method, sorted(chosen), effort(actions, chosen), budget,
                round(residual(findings, actions, chosen), 2), round(base, 2), t, detail)


# ── baselines ────────────────────────────────────────────────────────────────

def plan_greedy(findings, actions, budget) -> Plan:
    """Pick the best marginal risk-removed per hour that still fits — what a careful human does."""
    chosen: set[str] = set()
    while True:
        cur = residual(findings, actions, chosen)
        best, best_ratio = None, 0.0
        for a in actions:
            if a.id in chosen or effort(actions, chosen) + a.effort > budget:
                continue
            gain = cur - residual(findings, actions, chosen | {a.id})
            ratio = gain / a.effort if a.effort else gain
            if ratio > best_ratio:
                best, best_ratio = a.id, ratio
        if best is None:
            break
        chosen.add(best)
    return _plan("greedy:value_per_hour", findings, actions, chosen, budget)


def plan_exhaustive(findings, actions, budget, max_actions: int = 22) -> Plan | None:
    """Certified optimum by enumeration (2^n). Only for small action sets."""
    if len(actions) > max_actions:
        return None
    t0 = time.perf_counter()
    ids = [a.id for a in actions]
    eff = {a.id: a.effort for a in actions}
    best, best_r = set(), residual(findings, actions, set())
    for mask in range(1, 1 << len(ids)):
        chosen = {ids[i] for i in range(len(ids)) if mask >> i & 1}
        if sum(eff[c] for c in chosen) > budget:
            continue
        r = residual(findings, actions, chosen)
        if r < best_r - 1e-9:
            best, best_r = chosen, r
    return _plan("exhaustive:certified_optimum", findings, actions, best, budget, time.perf_counter() - t0)


# ── QpiAI Opt (HUBO) ─────────────────────────────────────────────────────────

def _var(action_id: str) -> str:
    return "y__" + "".join(ch if ch.isalnum() else "_" for ch in action_id)


def slack_coefficients(budget: int) -> list[int]:
    """Bounded binary encoding of an integer slack in [0, budget]: 1, 2, 4, ... + remainder."""
    coeffs, total, k = [], 0, 1
    while total + k <= budget:
        coeffs.append(k)
        total += k
        k *= 2
    if total < budget:
        coeffs.append(budget - total)
    return coeffs


def build_model(findings, actions, budget=None, budget_penalty: float | None = None):
    """Residual-risk polynomial over y_a.

    budget alone           -> hard linear constraint (QpiAI Opt compiles it).
    budget + budget_penalty -> exact unconstrained encoding for QAOA:
        P * (sum_a effort_a y_a + sum_k c_k s_k - budget)^2 with binary slack s_k.
        Efforts and budget must be whole hours.
    """
    from qpiai_opt.opt_modeller import Binary, Model

    y = {a.id: Binary(_var(a.id)) for a in actions}
    expr = 0
    for f in findings:
        term = f.score
        for a in actions:
            if f.id in a.covers:
                term = term * (1 - a.covers[f.id] * y[a.id])
        expr = expr + term
    model = Model("remediation_selection")
    if budget is not None and budget_penalty is not None:
        if any(float(a.effort) != int(a.effort) for a in actions) or float(budget) != int(budget):
            raise ValueError("exact budget encoding needs whole-hour efforts and budget")
        slack = [Binary(f"s__{i}") for i in range(len(slack_coefficients(int(budget))))]
        gap = sum(int(a.effort) * y[a.id] for a in actions) \
            + sum(c * s for c, s in zip(slack_coefficients(int(budget)), slack)) - int(budget)
        expr = expr + budget_penalty * gap * gap
        model.minimize(expr)
    else:
        model.minimize(expr)
        if budget is not None:
            model.add_constraint(sum(a.effort * y[a.id] for a in actions) <= budget, label="budget")
    return model, y


def _keys():
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[4] / ".env")
    return os.environ.get("QPIAI_OPT_API_KEY"), os.environ.get("QCLOUD_API_KEY")


# The local HUBO solver is simulated annealing; its default schedule is too short for this model
# (it returned a plan 10% worse than the certified optimum). Use the heaviest schedule that fits
# the local work cap (reads x sweeps x interactions <= 10M), stepping down for larger models.
_SWEEP_LADDER = (2400, 1200, 600, 300, 150)
_NUM_READS = 16
_SEED = 42


def plan_opt(findings, actions, budget, mode: str = "local") -> Plan:
    from qpiai_opt.opt_solvers import Client, LocalLimitExceeded, classify, solve

    opt_key, _ = _keys()
    if not opt_key:
        raise RuntimeError("QPIAI_OPT_API_KEY not set — fill it into seqr-quant/.env")
    model, _y = build_model(findings, actions, budget)
    cls = classify(model)
    client = Client(api_key=opt_key)
    t0 = time.perf_counter()
    r, sweeps = None, None
    for sweeps in _SWEEP_LADDER:
        try:
            r = solve(model, mode=mode, client=client, num_reads=_NUM_READS, num_sweeps=sweeps, seed=_SEED)
            break
        except LocalLimitExceeded:
            continue
    if r is None:
        raise RuntimeError("model too large for local HUBO solving even at the lightest schedule")
    dt = time.perf_counter() - t0
    assign = getattr(r, "variable_assignment", None) or {}
    chosen = {a.id for a in actions if round(float(assign.get(_var(a.id), 0))) == 1}
    return _plan(f"qpiai_opt:{getattr(r, 'problem_class', cls)}:{getattr(r, 'execution_mode', mode)}",
                 findings, actions, chosen, budget, getattr(r, "solver_time_s", None) or dt,
                 detail=f"classified {cls}; annealing {_NUM_READS} reads x {sweeps} sweeps, seed {_SEED}")


# ── QpiAI QCloud (QAOA sampling of alternative plans) ────────────────────────

def contested_actions(plans: list[Plan], findings, actions, cap: int = 5) -> list[str]:
    """Actions some plan picks — where the methods disagree — strongest standalone gain first."""
    pool = {i for p in plans if p for i in p.chosen}
    base = residual(findings, actions, set())
    return sorted(pool, key=lambda i: base - residual(findings, actions, {i}), reverse=True)[:cap]


def _subsets(reduced: list[Action]):
    for mask in range(1 << len(reduced)):
        yield frozenset(reduced[i].id for i in range(len(reduced)) if mask >> i & 1)


def plan_alternatives_qaoa(findings, actions, budget, focus: list[str], reps: int = 3,
                           max_iterations: int = 150, cvar_alpha: float = 0.25, top: int = 5) -> dict:
    """QAOA over a reduced action set; every sampled plan re-scored exactly against the budget.

    Only the ``focus`` actions are decided; all others stay unselected. The budget is encoded
    exactly with binary slack qubits (a Lagrangian penalty cannot represent it: some feasible
    optima are unreachable by any weight), and every sample is still re-scored exactly.
    """
    from qpiai_opt.opt_modeller import hubo_to_qubo
    from qpiai_opt.opt_solvers import solve
    from qpiai_opt.opt_solvers.qubo import QUBOProblem
    from qpiai_opt.quantum import CVaR, QAOA, QpiAIQuantumAuth

    _, qc_key = _keys()
    if not qc_key:
        raise RuntimeError("QCLOUD_API_KEY not set — fill it into seqr-quant/.env")
    QpiAIQuantumAuth.login(api_key=qc_key)

    reduced = [a for a in actions if a.id in focus]
    # Penalty above the total risk at stake: any over-budget plan always scores worse than any
    # feasible one (every violation costs >= 1 hour^2 * P).
    penalty = sum(f.score for f in findings) + 1.0
    model, _y = build_model(findings, reduced, budget=budget, budget_penalty=penalty)
    conv = hubo_to_qubo(model.to_hubo_dict())
    problem = QUBOProblem(qubo_dict=conv.qubo, num_variables=conv.num_variables, offset=conv.offset,
                          sense="MIN", variable_names=conv.variable_names)
    t0 = time.perf_counter()
    # CVaR-QAOA optimises the best alpha-fraction of samples rather than the mean energy, which
    # pushes probability toward good plans instead of a flat distribution.
    algo = QAOA(reps=reps, max_iterations=max_iterations,
                aggregation=CVaR(alpha=cvar_alpha) if cvar_alpha < 1 else None)
    r = solve(problem, mode="local", algorithm=algo)
    dt = time.perf_counter() - t0

    plans: dict[frozenset, dict] = {}
    for c in r.quantum.candidates:
        assign = c.variable_assignment
        chosen = frozenset(a.id for a in reduced if round(float(assign.get(_var(a.id), 0))) == 1)
        p = plans.setdefault(chosen, {"chosen": sorted(chosen), "probability": 0.0})
        p["probability"] += float(c.probability)
    scored = []
    for chosen, p in plans.items():
        e = effort(actions, set(chosen))
        p.update(effort=e, residual=round(residual(findings, actions, set(chosen)), 2),
                 feasible=e <= budget + 1e-9)
        scored.append(p)
    feasible = sorted((p for p in scored if p["feasible"]), key=lambda p: p["residual"])
    best_r = feasible[0]["residual"] if feasible else None
    p_opt = sum(p["probability"] for p in feasible if best_r is not None and p["residual"] <= best_r + 1e-6)
    n_states = 2 ** len(reduced)
    return {
        "qubits": conv.num_variables, "reduced_actions": [a.id for a in reduced], "reps": reps,
        "cvar_alpha": cvar_alpha,
        "seconds": round(dt, 2), "budget_penalty": round(penalty, 1),
        "slack_bits": len(slack_coefficients(int(budget))),
        "alternatives": feasible[:top],
        "p_optimal": round(p_opt, 4), "p_uniform": round(1 / n_states, 4),
        "amplification": round(p_opt * n_states, 2) if n_states else None,
    }


# ── reporting ─────────────────────────────────────────────────────────────────

def compare(findings, actions, budget) -> dict:
    out = {"budget": budget, "greedy": plan_greedy(findings, actions, budget),
           "opt": plan_opt(findings, actions, budget),
           "exhaustive": plan_exhaustive(findings, actions, budget)}
    return out


def _fmt(p: Plan) -> str:
    t = f"  [{p.solver_time_s:.2f}s]" if p.solver_time_s else ""
    return (f"{p.method:38} residual {p.residual:7.1f}  removed {p.removed_pct:5.1f}%  "
            f"effort {p.effort:5.1f}/{p.budget:g}h{t}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Choose quantum-risk remediations under an effort budget")
    ap.add_argument("--input", default=str(Path(__file__).resolve().parents[4] / "examples" / "acme-risk-v2.json"))
    ap.add_argument("--budget", type=float, default=40.0, help="engineer-hours available")
    ap.add_argument("--sweep", default="20,40,80", help="comma-separated budgets for the risk curve")
    ap.add_argument("--no-qaoa", action="store_true")
    args = ap.parse_args(argv)

    findings = load_findings(args.input)
    actions = build_actions(findings)
    base = sum(f.score for f in findings)
    print(f"=== Remediation selection — {len(findings)} findings, total risk {base:.0f}, "
          f"{len(actions)} candidate actions ===")
    for a in actions:
        print(f"  {a.id:34} {a.effort:5.1f}h  covers {len(a.covers):2} findings")

    print(f"\n-- Budget {args.budget:g} engineer-hours --")
    r = compare(findings, actions, args.budget)
    for k in ("greedy", "opt", "exhaustive"):
        if r[k]:
            print("  " + _fmt(r[k]))
    print(f"  QpiAI Opt plan: {', '.join(r['opt'].chosen) or '(nothing)'}")
    if r["exhaustive"]:
        gap = r["opt"].residual - r["exhaustive"].residual
        print(f"  Opt vs certified optimum: gap {gap:.2f}  ({'optimal' if abs(gap) < 1e-6 else 'suboptimal'})")
    print(f"  Opt vs greedy: {r['greedy'].residual - r['opt'].residual:+.2f} less residual risk")

    print("\n-- Risk curve (QpiAI Opt) --")
    for b in [float(x) for x in args.sweep.split(",") if x.strip()]:
        p = plan_opt(findings, actions, b)
        print(f"  {b:5g}h -> removes {p.removed_pct:5.1f}% of risk  ({', '.join(p.chosen)})")

    if not args.no_qaoa:
        contested = contested_actions([r["opt"], r["greedy"]], findings, actions)
        q = plan_alternatives_qaoa(findings, actions, args.budget, contested)
        print(f"\n-- QpiAI QCloud CVaR-QAOA: alternative plans over {len(q['reduced_actions'])} contested actions "
              f"({q['qubits']} qubits, reps {q['reps']}, alpha {q['cvar_alpha']}, {q['seconds']}s) --")
        for i, p in enumerate(q["alternatives"], 1):
            print(f"  {i}. residual {p['residual']:7.1f}  effort {p['effort']:5.1f}h  "
                  f"P={p['probability']:.3f}  {', '.join(p['chosen']) or '(nothing)'}")
        print(f"  P(best feasible plan) = {q['p_optimal']:.3f} vs uniform {q['p_uniform']:.3f} "
              f"-> amplification x{q['amplification']}")
        n = len(q["reduced_actions"])
        print(f"  Honest read: {2 ** n} possible plans vs 1024 shots, so sampling covers the space — the menu\n"
              f"  is not evidence of quantum advantage; amplification above x1 is what QAOA itself adds.")


if __name__ == "__main__":
    main()
