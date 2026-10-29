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

Infrastructure findings (the org's crypto graph, ``GET /api/v1/graph/risk``) get per-asset
actions instead — see ``build_infra_actions``: hybrid-kex, ssh-pq-kex, reissue-cert,
lock-origin, migrate, plus org-wide segmentation. Same objective, same solvers.

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
    asset_type: str = ""        # infra findings only
    slot_key: str = ""          # infra findings only
    fronted_by_edge: bool = False

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


# ── infrastructure (org graph) ───────────────────────────────────────────────

@dataclass(frozen=True)
class InfraAssumptions:
    """Stated, not measured. Efforts are whole hours so the QAOA slack encoding stays exact."""
    kex_effort: dict = field(default_factory=lambda: {
        "domain": 3, "load_balancer": 4, "origin": 6, "tls_endpoint": 6, "grpc": 6,
        "smtp": 4, "imap": 4, "pop3": 4})
    kex_effort_default: int = 8          # databases, queues, hosts: rebuild + restart window
    ssh_kex_effort: int = 2              # OpenSSH >= 9.9 ships mlkem768x25519-sha256
    cert_effort: int = 4
    cert_frac_internet: float = 0.5      # public WebPKI cannot issue ML-DSA yet: shorter-lived,
                                         # automated classical certs only halve the exposure
    cert_frac_private: float = 1.0       # internal PKI can issue ML-DSA / composite today
    lock_origin_effort: int = 3
    lock_origin_frac: float = 0.4        # origin no longer directly reachable; edge->origin hop remains
    segment_effort: int = 8
    segment_frac: float = 0.3


_KEX_SLOTS = {"tls:kex", "ike:kex"}


def infra_findings_from_components(components: list[dict]) -> list[Finding]:
    """``GET /api/v1/graph/risk`` components -> Findings (already-safe slots dropped)."""
    out = []
    for c in components:
        if float(c["score"]) <= 0:
            continue
        ident = c.get("file_path") or c["rel_path"]
        out.append(Finding(
            id=f"{ident}#{c['slot_key']}", rel_path=ident, line=0, algorithm=c["algorithm"],
            score=float(c["score"]), role=c["role"], exposure=c["exposure"],
            effort=float(max(1, round(float(c.get("effort_hours") or 8)))), tier=c.get("tier", ""),
            asset_type=c.get("asset_type", ""), slot_key=c["slot_key"],
            fronted_by_edge=bool(c.get("fronted_by_edge")),
        ))
    return out


def _cert_frac(f: Finding, a: InfraAssumptions) -> float:
    if f.slot_key != "tls:cert":
        return 1.0
    return a.cert_frac_internet if f.exposure == "internet" else a.cert_frac_private


def build_infra_actions(findings: list[Finding], a: InfraAssumptions = InfraAssumptions()) -> list[Action]:
    """Per-asset infrastructure fixes. Several actions can cover one slot, so the objective
    keeps genuine higher-order terms (e.g. lock-origin x hybrid-kex x segmentation)."""
    actions: list[Action] = []
    by_asset: dict[str, list[Finding]] = {}
    for f in findings:
        by_asset.setdefault(f.rel_path, []).append(f)
    for asset, fs in sorted(by_asset.items()):
        atype = fs[0].asset_type
        # full migration of every slot on the asset — the expensive, complete option (public
        # certificates still capped: no WebPKI CA issues ML-DSA yet)
        actions.append(Action(f"migrate:{asset}", f"migrate all crypto on {asset}",
                              sum(f.effort for f in fs), {f.id: _cert_frac(f, a) for f in fs}))
        kex = [f for f in fs if f.slot_key in _KEX_SLOTS]
        if kex:
            actions.append(Action(f"hybrid-kex:{asset}", f"enable X25519MLKEM768 on {asset}",
                                  a.kex_effort.get(atype, a.kex_effort_default), {f.id: 1.0 for f in kex}))
        ssh = [f for f in fs if f.slot_key == "ssh:kex"]
        if ssh:
            actions.append(Action(f"ssh-pq-kex:{asset}", f"enable mlkem768x25519-sha256 sshd KEX on {asset}",
                                  a.ssh_kex_effort, {f.id: 1.0 for f in ssh}))
        certs = [f for f in fs if f.slot_key == "tls:cert"]
        if certs:
            frac = _cert_frac(certs[0], a)
            actions.append(Action(f"reissue-cert:{asset}",
                                  f"reissue {asset} certificate (" +
                                  ("short-lived + automated" if frac < 1 else "ML-DSA, internal PKI") + ")",
                                  a.cert_effort, {f.id: frac for f in certs}))
        if any(f.fronted_by_edge for f in fs):
            actions.append(Action(f"lock-origin:{asset}", f"restrict {asset} to edge IPs / authenticated origin pulls",
                                  a.lock_origin_effort, {f.id: a.lock_origin_frac for f in fs}))
    seg = {f.id: a.segment_frac for f in findings if f.exposure in {"internal", "unknown"}}
    if seg:
        actions.append(Action("segment:internal", "network segmentation + mTLS for internal services",
                              a.segment_effort, seg))
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
    if mode == "platform":
        # QpiAI's hosted HUBO solver: a job in the Opt console; it picks its own schedule.
        r = solve(model, mode="platform", client=client)
        job = getattr(r, "job_id", None) or getattr(r, "problem_id", None)
        detail = f"classified {cls}; QpiAI Opt platform job {job or '(no id returned)'}"
    else:
        for sweeps in _SWEEP_LADDER:
            try:
                r = solve(model, mode=mode, client=client, num_reads=_NUM_READS, num_sweeps=sweeps, seed=_SEED)
                break
            except LocalLimitExceeded:
                continue
        if r is None:
            raise RuntimeError("model too large for local HUBO solving even at the lightest schedule")
        detail = f"classified {cls}; annealing {_NUM_READS} reads x {sweeps} sweeps, seed {_SEED}"
    dt = time.perf_counter() - t0
    assign = getattr(r, "variable_assignment", None) or {}
    chosen = {a.id for a in actions if round(float(assign.get(_var(a.id), 0))) == 1}
    return _plan(f"qpiai_opt:{getattr(r, 'problem_class', cls)}:{getattr(r, 'execution_mode', mode)}",
                 findings, actions, chosen, budget, getattr(r, "solver_time_s", None) or dt,
                 detail=detail)


# ── QpiAI QCloud (QAOA sampling of alternative plans) ────────────────────────

def contested_actions(plans: list[Plan], findings, actions, cap: int = 5, max_actions: int = 7) -> list[str]:
    """Reduced action set for QAOA.

    Always holds every action of the best known feasible plan — otherwise QAOA cannot sample the
    optimum at all — then the actions the other methods picked instead (where they disagree),
    then the strongest unchosen actions as decoys. Size is ``cap``, raised to fit the best plan
    plus two alternatives, never above ``max_actions`` (qubits = actions + budget slack bits).
    """
    feasible = [p for p in plans if p and p.feasible]
    if not feasible:
        return []
    best = min(feasible, key=lambda p: p.residual)
    base = residual(findings, actions, set())
    gain = {a.id: base - residual(findings, actions, {a.id}) for a in actions}
    by_gain = lambda ids: sorted(ids, key=lambda i: (-gain[i], i))
    size = min(max(cap, len(best.chosen) + 2), max_actions)
    out = by_gain(best.chosen)[:size]
    for i in by_gain({i for p in feasible for i in p.chosen}) + by_gain(gain):
        if len(out) >= size:
            break
        if i not in out:
            out.append(i)
    return out


def _subsets(reduced: list[Action]):
    for mask in range(1 << len(reduced)):
        yield frozenset(reduced[i].id for i in range(len(reduced)) if mask >> i & 1)


def _pretrained(objective, x0, max_iterations):
    """QAOA "optimizer" that keeps the given angles: the platform run then submits exactly one
    circuit (the final sampling) instead of one job per optimisation step."""
    return x0, 0.0, {"nfev": 0, "nit": 0}


def _warm_assignment(names, reduced: list[Action], plan: set[str], budget: int) -> dict:
    """Binary assignment of every QUBO variable for a known plan: its actions plus the slack bits
    that make the budget equation exact. Used as the WarmStart point (any extra auxiliary
    variable gets an uninformative 0.5)."""
    coeffs = slack_coefficients(int(budget))
    spare = int(budget) - int(sum(a.effort for a in reduced if a.id in plan))
    bits = next((m for m in range(1 << len(coeffs))
                 if sum(c for i, c in enumerate(coeffs) if m >> i & 1) == spare), 0)
    by_name = {_var(a.id): float(a.id in plan) for a in reduced}
    by_name.update({f"s__{i}": float(bits >> i & 1) for i in range(len(coeffs))})
    return {n: by_name.get(n, 0.5) for n in names}


def _score_samples(candidates, reduced, findings, actions, budget) -> list[dict]:
    plans: dict[frozenset, dict] = {}
    for c in candidates:
        assign = c.variable_assignment
        chosen = frozenset(a.id for a in reduced if round(float(assign.get(_var(a.id), 0))) == 1)
        p = plans.setdefault(chosen, {"chosen": sorted(chosen), "probability": 0.0})
        p["probability"] += float(c.probability)
    for chosen, p in plans.items():
        e = effort(actions, set(chosen))
        p.update(effort=e, residual=round(residual(findings, actions, set(chosen)), 2),
                 feasible=e <= budget + 1e-9)
    return sorted((p for p in plans.values() if p["feasible"]), key=lambda p: p["residual"])


def _p_optimal(feasible: list[dict], best_r: float) -> float:
    return round(sum(p["probability"] for p in feasible if p["residual"] <= best_r + 1e-6), 4)


def _qcloud_error(exc: Exception) -> str:
    """QpiAI's own server message (e.g. subscription/quota), without the SDK's traceback text."""
    text = str(exc)
    if "Server response:" in text:
        text = text[text.rindex("Server response:") + len("Server response:"):]
    return text.strip().splitlines()[0][:300] if text.strip() else type(exc).__name__


def plan_alternatives_qaoa(findings, actions, budget, focus: list[str], reps: int = 3,
                           max_iterations: int = 150, cvar_alpha: float = 0.25, top: int = 5,
                           best_known: float | None = None, tight_penalty: bool = True,
                           warm_start_plan: list[str] | None = None, device: str | None = None,
                           experiment: str | None = None, shots: int = 1024) -> dict:
    """QAOA over a reduced action set; every sampled plan re-scored exactly against the budget.

    Only the ``focus`` actions are decided; all others stay unselected. The budget is encoded
    exactly with binary slack qubits (a Lagrangian penalty cannot represent it: some feasible
    optima are unreachable by any weight), and every sample is still re-scored exactly.

    Angles are always trained on the local simulator (free). With ``device`` (a QpiAI QCloud
    backend such as ``QpiAI-QSV-Simulator`` or the ``QpiAI-Indus-1`` QPU) the trained circuit is
    then sampled there as ONE job; if QpiAI refuses it (no subscription/quota) the local samples
    stand and the refusal is reported under ``cloud``.

    ``warm_start_plan`` tilts the initial state toward a known plan (warm-start QAOA). The lift
    is reported against the warm state alone (all angles zero), so it is not double-counted.
    """
    from qpiai_opt.opt_modeller import hubo_to_qubo
    from qpiai_opt.opt_solvers import solve
    from qpiai_opt.opt_solvers.qubo import QUBOProblem
    from qpiai_opt.quantum import CVaR, QAOA, QpiAIQuantumAuth, QuantumRun, WarmStart

    _, qc_key = _keys()
    if not qc_key:
        raise RuntimeError("QCLOUD_API_KEY not set — fill it into seqr-quant/.env")
    QpiAIQuantumAuth.login(api_key=qc_key)

    reduced = [a for a in actions if a.id in focus]
    if tight_penalty:
        # Residual risk only falls as actions are added, so no plan in the reduced space can
        # beat residual(all) and no feasible optimum is worse than residual(nothing). Any
        # P above that spread keeps every over-budget plan (violation >= 1 hour^2) worse than
        # every feasible one — exact, and far smaller than the total risk at stake.
        penalty = (residual(findings, actions, set())
                   - residual(findings, actions, {a.id for a in reduced})) + 1.0
    else:
        penalty = sum(f.score for f in findings) + 1.0
    model, _y = build_model(findings, reduced, budget=budget, budget_penalty=penalty)
    conv = hubo_to_qubo(model.to_hubo_dict())
    # Measured 2026-10-29: rescaling the QUBO to max |coef| = 1 did not raise P(optimum) on either
    # instance (x0.7-1.2, within run-to-run noise), so energies are passed as-is.
    problem = QUBOProblem(qubo_dict=conv.qubo, num_variables=conv.num_variables, offset=conv.offset,
                          sense="MIN", variable_names=conv.variable_names)
    warm = None
    if warm_start_plan is not None:
        warm = WarmStart(epsilon=0.25, relaxed_solution=_warm_assignment(
            conv.variable_names, reduced, set(warm_start_plan) & {a.id for a in reduced}, budget))
    aggregation = CVaR(alpha=cvar_alpha) if cvar_alpha < 1 else None

    t0 = time.perf_counter()
    # CVaR-QAOA optimises the best alpha-fraction of samples rather than the mean energy, which
    # pushes probability toward good plans instead of a flat distribution.
    r = solve(problem, mode="local", algorithm=QAOA(
        reps=reps, max_iterations=max_iterations, aggregation=aggregation, warm_start=warm))
    dt = time.perf_counter() - t0
    angles = list(r.quantum.optimized_parameters)

    # Ground truth for the reduced space by enumeration (<= 2^7 plans), so P(optimum) is
    # measured against the real optimum, not merely the best plan QAOA happened to sample.
    best_r = min(round(residual(findings, actions, set(c)), 2) for c in _subsets(reduced)
                 if effort(actions, set(c)) <= budget + 1e-9)
    feasible = _score_samples(r.quantum.candidates, reduced, findings, actions, budget)
    n_states = 2 ** len(reduced)
    out = {
        "qubits": conv.num_variables, "reduced_actions": [a.id for a in reduced], "reps": reps,
        "cvar_alpha": cvar_alpha,
        "seconds": round(dt, 2), "budget_penalty": round(penalty, 1),
        "slack_bits": len(slack_coefficients(int(budget))),
        "reduced_optimum": best_r,
        "contains_best_known": best_known is None or best_r <= best_known + 1e-6,
        "p_uniform": round(1 / n_states, 4),
        "backend": "QpiAI-QSV-Local", "warm_start": warm is not None,
        "optimized_parameters": [round(x, 4) for x in angles],
    }

    if warm is not None:
        # The warm state alone (no QAOA evolution) is the baseline the warm-start lift is
        # measured against.
        r0 = solve(problem, mode="local", algorithm=QAOA(
            reps=reps, initial_point=[0.0] * len(angles), optimizer=_pretrained,
            aggregation=aggregation, warm_start=warm))
        out["p_optimal_warm_state"] = _p_optimal(
            _score_samples(r0.quantum.candidates, reduced, findings, actions, budget), best_r)

    if device:
        name = experiment or os.environ.get("QCLOUD_EXPERIMENT") or "Default Experiment"
        cloud = {"device": device, "experiment": name, "shots": shots}
        t1 = time.perf_counter()
        try:
            rc = solve(problem, mode="platform", algorithm=QAOA(
                reps=reps, initial_point=angles, optimizer=_pretrained,
                aggregation=aggregation, warm_start=warm),
                execution=QuantumRun(shots=shots, device_name=device, experiment_name=name, timeout=600))
            feasible = _score_samples(rc.quantum.candidates, reduced, findings, actions, budget)
            cloud.update(status="ok", job_ids=list(rc.quantum.job_ids))
            out["backend"] = device
        except Exception as e:  # subscription/quota/maintenance: keep the local samples
            cloud.update(status="failed", error=_qcloud_error(e), job_ids=[])
        cloud["seconds"] = round(time.perf_counter() - t1, 2)
        out["cloud"] = cloud

    p_opt = _p_optimal(feasible, best_r)
    out.update(
        alternatives=feasible[:top],
        sampled_optimum=bool(feasible) and feasible[0]["residual"] <= best_r + 1e-6,
        p_optimal=p_opt,
        amplification=round(p_opt * n_states, 2) if n_states else None,
    )
    return out


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



_QPIAI_LOG = Path(os.environ.get(
    "QPIAI_LOG_FILE", str(Path(__file__).resolve().parents[2] / "reports" / "qpiai_runs.log")))


def log_qpiai_run(result: dict) -> list[str]:
    """Branded, REAL QpiAI run log. Prints to stdout (so `docker logs` shows the banner) and
    appends to a txt file (QPIAI_LOG_FILE). Every value comes from the actual solve, not a script."""
    from datetime import datetime, timezone
    plans = result.get("plans") or {}
    opt = plans.get("opt")
    q = result.get("qaoa")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    bar = "=" * 60
    lines = [bar,
             f"[QpiAI Opt] Received remediation request from website  ({ts})",
             f"[QpiAI Opt] Source: {result.get('source','?')} | {len(result.get('findings',[]))} findings"
             f" | budget {result.get('budget','?')}h | total risk {result.get('baseline_risk','?')}",
             "[QpiAI Opt] Building constrained HUBO (overlapping fixes -> higher-order terms)"]
    if opt:
        if opt.get("detail"):
            lines.append(f"[QpiAI Opt] {opt['detail']}")
        lines.append(f"[QpiAI Opt] Solver status: OPTIMAL | residual {opt.get('residual')}"
                     f" | {opt.get('removed_pct')}% risk removed | effort {opt.get('effort')}h")
        gap = result.get("opt_gap_to_optimum")
        if gap is not None:
            lines.append(f"[QpiAI Opt] Certified-optimum check: gap {gap}"
                         f" ({'MATCHES optimum' if abs(gap) < 1e-6 else 'suboptimal'})")
    for k in ("opt", "opt_platform"):
        err = (result.get("errors") or {}).get(k)
        if err:
            lines.append(f"[QpiAI Opt] platform note: {err}")
    if q:
        lines.append(f"[QpiAI QCloud] QAOA on {q.get('qubits')} qubits | backend {q.get('backend')}"
                     f" | {q.get('seconds')}s")
        lines.append(f"[QpiAI QCloud] P(optimum) {q.get('p_optimal')} vs uniform {q.get('p_uniform')}"
                     f" | optimum sampled: {'yes' if q.get('sampled_optimum') else 'no'}")
        cloud = q.get("cloud") or {}
        if cloud.get("status") == "ok":
            lines.append(f"[QpiAI QCloud] Cloud job {','.join(cloud.get('job_ids', []))} on"
                         f" {cloud.get('device')} (experiment {cloud.get('experiment')})")
        elif cloud.get("error"):
            lines.append(f"[QpiAI QCloud] cloud note: {cloud['error']}")
    lines.append(bar)
    text = "\n".join(lines)
    print(text, flush=True)
    try:
        _QPIAI_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_QPIAI_LOG, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass
    return lines


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
        known = [p for p in (r["opt"], r["exhaustive"], r["greedy"]) if p and p.feasible]
        contested = contested_actions(known, findings, actions)
        q = plan_alternatives_qaoa(findings, actions, args.budget, contested,
                                   best_known=min(p.residual for p in known))
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
