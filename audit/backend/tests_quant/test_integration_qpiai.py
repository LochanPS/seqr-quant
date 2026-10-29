"""Live QpiAI integration tests — hit QpiAI Opt / QCloud over the network.

Gated OFF by default so the normal suite stays fast and offline. Enable with:
    RUN_QPIAI_INTEGRATION=1  (and valid keys in seqr-quant/.env)
"""

import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

_enabled = os.environ.get("RUN_QPIAI_INTEGRATION") == "1"
_have_keys = bool(os.environ.get("QPIAI_OPT_API_KEY")) and bool(os.environ.get("QCLOUD_API_KEY"))

pytestmark = pytest.mark.skipif(
    not (_enabled and _have_keys),
    reason="set RUN_QPIAI_INTEGRATION=1 and keys in .env to run live QpiAI tests",
)


def test_opt_beats_baseline_and_is_hubo():
    from app.migration.optimize import acme_bank_items, schedule_baseline, schedule_opt
    items = acme_bank_items()
    base = schedule_baseline(items)
    opt = schedule_opt(items)
    assert "HUBO" in opt.method
    assert opt.feasible is True
    assert opt.scored <= base.scored      # Opt never worse than the naive baseline
    assert not opt.crew_overloaded_waves  # crew-feasible


def test_remediation_opt_reaches_certified_optimum():
    from app.migration.remediation import (build_actions, load_findings, plan_exhaustive, plan_opt)
    acme = Path(__file__).resolve().parents[3] / "examples" / "acme-risk-v2.json"
    fs = load_findings(acme)
    acts = build_actions(fs)
    opt, exact = plan_opt(fs, acts, 40), plan_exhaustive(fs, acts, 40)
    assert "HUBO" in opt.method and opt.feasible
    assert opt.residual == pytest.approx(exact.residual, abs=1e-6)


def test_remediation_qaoa_menu_contains_optimum():
    from app.migration.remediation import (build_actions, contested_actions, load_findings,
                                           plan_alternatives_qaoa, plan_exhaustive, plan_greedy)
    acme = Path(__file__).resolve().parents[3] / "examples" / "acme-risk-v2.json"
    fs = load_findings(acme)
    acts = build_actions(fs)
    e, g = plan_exhaustive(fs, acts, 40), plan_greedy(fs, acts, 40)
    q = plan_alternatives_qaoa(fs, acts, 40, contested_actions([e, g], fs, acts))
    assert q["alternatives"][0]["residual"] == pytest.approx(e.residual, abs=1e-6)
    assert all(p["feasible"] for p in q["alternatives"])


def test_qaoa_matches_classical_optimum():
    from app.migration.quantum_experiment import run_experiment
    out = run_experiment()
    assert out["quantum"]["qubits"] == 6
    assert out["quantum"]["matches_classical_optimum"] is True
