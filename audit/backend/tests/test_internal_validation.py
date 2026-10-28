"""Internal validation harness on the realistic enterprise seed (Phase 2 checkpoint)."""

import os

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from app.migration.validate import run_all_templates, run_internal_validation


def test_every_pipeline_stage_validates_on_realistic_data():
    r = run_internal_validation("banking")
    assert r["all_ok"] is True, [s for s in r["stages"] if s["ok"] is False]
    names = {s["stage"] for s in r["stages"]}
    assert {"Asset discovery", "Crypto-asset graph", "Policy evaluation", "Migration planning",
            "Bundle offline verification", "Re-scan + policy convergence",
            "Attestation offline verification", "Complete audit trail"} <= names


def test_all_sector_templates_validate_end_to_end():
    results = run_all_templates()
    assert set(results) >= {"banking", "healthcare", "telecom", "government", "saas"}
    assert all(results.values()), [k for k, ok in results.items() if not ok]
