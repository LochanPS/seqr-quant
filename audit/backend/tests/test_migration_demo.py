"""End-to-end pipeline regression (Phase 2 checkpoint)."""

import os

os.environ.setdefault("SECRET_KEY", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from app.migration.demo import run_demo


def test_full_pipeline_converges_end_to_end():
    status = run_demo()
    assert status["converged"] is True
    assert status["open_violations"] == 0
    assert status["plans"]["by_status"].get("verified") == 1
    assert status["bundles"] == 1
