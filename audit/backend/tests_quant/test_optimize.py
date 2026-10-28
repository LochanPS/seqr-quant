"""Tests for optimize.py — the classical/structural parts (no network, no API key).

The live QpiAI Opt solve is covered in test_integration_qpiai.py (gated).
"""

from app.migration.optimize import (CREW_CAP, SchedItem, _chain_length, _num_waves,
                                     acme_bank_items, build_hubo_model, check_feasible,
                                     schedule_baseline, score)


def test_acme_instance_shape():
    items = acme_bank_items()
    assert len(items) == 9
    ids = {it.id for it in items}
    # every dependency references a real item
    for it in items:
        for d in it.depends_on:
            assert d in ids
    assert any(it.risky for it in items)


def test_baseline_is_feasible():
    items = acme_bank_items()
    s = schedule_baseline(items)
    assert s.feasible is True
    assert set(s.waves) == {it.id for it in items}  # each scheduled exactly once
    # dependencies land in strictly earlier waves
    by_id = {it.id: it for it in items}
    for it in items:
        for d in it.depends_on:
            assert s.waves[d] < s.waves[it.id]


def test_score_applies_crew_penalty():
    # three risky items forced into one wave -> crew penalty kicks in
    items = [SchedItem(f"r{i}", f"svc{i}: enable_hybrid_kex", 10) for i in range(3)]
    waves = {"r0": 0, "r1": 0, "r2": 0}
    exposure, scored, overloaded = score(items, waves)
    assert exposure == 0.0            # all in wave 0 -> zero exposure term
    assert scored > exposure          # but crew penalty added
    assert overloaded == [0]


def test_score_no_penalty_when_within_cap():
    items = [SchedItem(f"r{i}", f"svc{i}: enable_hybrid_kex", 10) for i in range(3)]
    waves = {"r0": 0, "r1": 0, "r2": 1}  # 2 then 1 -> within cap
    _, scored, overloaded = score(items, waves)
    assert overloaded == []
    assert scored == score(items, waves)[0]  # scored == exposure, no penalty


def test_check_feasible_catches_dependency_violation():
    items = [SchedItem("a", "a", 10), SchedItem("b", "b", 10, depends_on=["a"])]
    bad = {"a": 1, "b": 0}  # b before its dependency a
    ok, problems = check_feasible(items, bad)
    assert ok is False and problems


def test_num_waves_respects_chain_length():
    items = acme_bank_items()
    assert _num_waves(items, None) >= _chain_length(items)


def test_build_hubo_model_is_higher_order():
    """The crew-cap term must make the model classify as native HUBO (not QUBO/MILP)."""
    from qpiai_opt.opt_solvers import classify
    items = acme_bank_items()
    model, _x, _T = build_hubo_model(items, _num_waves(items, None))
    assert classify(model) == "HUBO"


def test_crew_cap_constant():
    assert CREW_CAP == 2
