"""The end-to-end worked example must stay green: BEFORE scans dirty, AFTER scans clean.

Skips cleanly if the SeQr CLI isn't installed (the example needs `pip install seqr`).
"""
import shutil
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "worked_migration"


def _seqr_available() -> bool:
    if shutil.which("seqr"):
        return True
    return (EXAMPLE.parent.parent.parent / "cli" / "seqr" / "cli.py").exists()


@pytest.mark.skipif(not _seqr_available(), reason="SeQr CLI not installed (pip install seqr)")
def test_worked_migration_runs_clean():
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_migration", EXAMPLE / "run_migration.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    before = module.scan(module.BEFORE)
    after = module.scan(module.AFTER)
    assert before["summary"]["components_found"] > 0, "BEFORE service should have findings"
    assert after["summary"]["components_found"] == 0, "AFTER service should scan clean"
    assert module.scan_fails_the_build(module.BEFORE) is True
    assert module.scan_fails_the_build(module.AFTER) is False
