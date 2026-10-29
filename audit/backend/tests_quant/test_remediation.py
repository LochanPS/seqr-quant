"""Tests for remediation.py — budget-constrained remediation selection (offline parts).

Live QpiAI Opt / QAOA runs are in test_integration_qpiai.py (gated).
"""

import json
from pathlib import Path

import pytest

from app.migration.remediation import (Action, Assumptions, Finding, build_actions, build_model,
                                       contested_actions, effort, load_findings, plan_exhaustive,
                                       plan_greedy, residual, slack_coefficients, _var)

ACME = Path(__file__).resolve().parents[3] / "examples" / "acme-risk-v2.json"


def F(i, path, score, role="keygen", exposure="internet", eff=10.0):
    return Finding(id=i, rel_path=path, line=1, algorithm="RSA", score=score, role=role,
                   exposure=exposure, effort=eff)


def test_residual_multiplies_overlapping_coverage():
    fs = [F("f1", "a.py", 100.0)]
    acts = [Action("x", "x", 5, {"f1": 0.5}), Action("y", "y", 5, {"f1": 0.6})]
    assert residual(fs, acts, set()) == 100.0
    assert residual(fs, acts, {"x"}) == pytest.approx(50.0)
    assert residual(fs, acts, {"x", "y"}) == pytest.approx(100 * 0.5 * 0.4)


def test_build_actions_coverage_rules():
    fs = [F("kex", "web/a.js", 90, role="key_exchange", exposure="internet"),
          F("kg", "web/b.js", 60, role="keygen", exposure="internet"),
          F("sig", "core/c.java", 40, role="signature", exposure="internal"),
          F("h", "x/d.py", 10, role="hash", exposure="unknown")]
    a = Assumptions()
    acts = {x.id: x for x in build_actions(fs, a)}
    assert acts["fix:web/a.js"].covers == {"kex": 1.0}
    assert acts["edge:hybrid-kex"].covers == {"kex": a.edge_frac_confidentiality, "kg": a.edge_frac_keygen}
    assert set(acts["segment:internal"].covers) == {"sig", "h"}
    assert set(acts["sdk:pqcmap-javascript"].covers) == {"kex", "kg"}
    assert "h" not in acts.get("sdk:pqcmap-python", Action("", "", 0)).covers  # hashes not SDK-covered
    assert acts["sdk:pqcmap-javascript"].effort == a.sdk_base_effort + a.sdk_per_file_effort * 2


def test_model_is_higher_order_when_coverage_overlaps():
    from qpiai_opt.opt_solvers import classify
    fs = [F("f1", "web/a.js", 80, role="key_exchange")]  # covered by fix + edge + sdk -> degree 3
    acts = build_actions(fs)
    model, _ = build_model(fs, acts, budget=30)
    assert classify(model) == "HUBO"
    unconstrained, _ = build_model(fs, acts)
    assert max(len(k) for k in unconstrained.to_hubo_dict()) == 3


def test_exhaustive_never_worse_than_greedy_and_respects_budget():
    fs = [F("a", "p/a.py", 90, role="key_exchange"), F("b", "p/b.py", 50),
          F("c", "q/c.go", 70, role="key_exchange", exposure="internal")]
    acts = build_actions(fs)
    for budget in (5, 12, 25, 60):
        g, e = plan_greedy(fs, acts, budget), plan_exhaustive(fs, acts, budget)
        assert g.feasible and e.feasible
        assert e.residual <= g.residual + 1e-9


def test_exact_budget_encoding_beats_the_duality_gap():
    """On this instance no Lagrangian weight reaches the feasible optimum (residual 70 at 20h);
    the slack-qubit encoding's global minimum must be exactly that plan."""
    import itertools
    fs = [F("a", "p/a.py", 90, role="key_exchange", eff=12), F("b", "p/b.py", 50, eff=8),
          F("c", "q/c.go", 70, role="key_exchange", eff=10)]
    acts = build_actions(fs)
    reduced = acts[:4]          # fix a, fix b, fix c, edge
    budget = 20
    penalty = sum(f.score for f in fs) + 1
    model, y = build_model(fs, reduced, budget=budget, budget_penalty=penalty)
    poly = model.to_hubo_dict()
    names = sorted({v for k in poly for v in k})
    best, best_val = None, float("inf")
    for bits in itertools.product((0, 1), repeat=len(names)):
        val = dict(zip(names, bits))
        e = sum(c * all(val[v] for v in k) for k, c in poly.items())
        if e < best_val:
            best_val, best = e, val
    chosen = {a.id for a in reduced if best[_var(a.id)]}
    assert chosen == {"fix:p/a.py", "fix:p/b.py"}
    assert residual(fs, acts, chosen) == pytest.approx(70.0)
    assert best_val == pytest.approx(70.0)   # zero penalty at the optimum


def test_slack_coefficients_cover_range_exactly():
    for b in (1, 5, 20, 40, 63, 64, 100):
        c = slack_coefficients(b)
        assert sum(c) == b
        reachable = {sum(x for x, on in zip(c, mask) if on)
                     for mask in __import__("itertools").product((0, 1), repeat=len(c))}
        assert reachable == set(range(b + 1))


@pytest.mark.skipif(not ACME.exists(), reason="examples/acme-risk-v2.json not present")
def test_acme_plan_shapes():
    fs = load_findings(ACME)
    acts = build_actions(fs)
    assert len(fs) == 16 and len(acts) >= 10
    g, e = plan_greedy(fs, acts, 40), plan_exhaustive(fs, acts, 40)
    assert e.residual <= g.residual
    assert 50 < e.removed_pct < 70          # 40h of 150h of work removes ~59% of risk
    focus = contested_actions([e, g], fs, acts)
    assert 1 <= len(focus) <= 5 and set(focus) <= {a.id for a in acts}
