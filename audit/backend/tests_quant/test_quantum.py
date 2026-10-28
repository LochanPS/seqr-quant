"""Tests for quantum_experiment.py — model construction (no network).

The live QAOA solve is covered in test_integration_qpiai.py (gated).
"""

from app.migration.quantum_experiment import build_qubo_model, reduced_instance


def test_reduced_instance_shape():
    items = reduced_instance()
    assert len(items) == 3
    assert all(it.risky for it in items)  # all high-risk -> crew bottleneck


def test_build_qubo_model_is_two_local():
    """QAOA is 2-local; the reduced model must classify as QUBO (degree-2), not HUBO."""
    from qpiai_opt.opt_solvers import classify
    items = reduced_instance()
    model, T = build_qubo_model(items, num_waves=2)
    assert T == 2
    assert classify(model) == "QUBO"


def test_qubo_has_expected_variable_count():
    items = reduced_instance()
    model, T = build_qubo_model(items, num_waves=2)
    model.to_qubo_dict()  # compiling the QUBO populates the variable list (as the QAOA path does)
    # x[i,t] for 3 items * 2 waves = 6 binaries (the qubit count)
    assert len(model.qubo_variable_names) == len(items) * T
