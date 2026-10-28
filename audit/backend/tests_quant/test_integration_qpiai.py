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


def test_qaoa_matches_classical_optimum():
    from app.migration.quantum_experiment import run_experiment
    out = run_experiment()
    assert out["quantum"]["qubits"] == 6
    assert out["quantum"]["matches_classical_optimum"] is True
