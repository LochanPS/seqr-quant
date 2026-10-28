"""Tests for detection_metrics.py — scanner precision/recall (local, no network).

Needs tree-sitter + the shared-scanner source; skipped cleanly if either is absent.
"""

import pytest

pytest.importorskip("tree_sitter", reason="code scanner needs tree-sitter")

from app.migration.detection_metrics import LABELS, _SCANNER, evaluate  # noqa: E402

pytestmark = pytest.mark.skipif(not _SCANNER.exists(),
                                reason="shared-scanner source not present")


def test_labels_shape():
    assert len(LABELS) == 14
    assert sum(LABELS.values()) == 10      # vulnerable
    assert len(LABELS) - sum(LABELS.values()) == 4  # safe (pqcmap)


def test_perfect_discrimination_on_corpus():
    r = evaluate()
    assert r["tp"] == 10
    assert r["fp"] == 0      # no false positive on real pqcmap ML-KEM/ML-DSA code
    assert r["fn"] == 0
    assert r["tn"] == 4
    assert r["precision"] == 1.0
    assert r["recall"] == 1.0
    assert r["f1"] == 1.0


def test_safe_pqc_files_are_true_negatives():
    """The discriminating claim: safe files USE crypto (pqcmap) but must not be flagged."""
    r = evaluate()
    safe = {rel for rel, truth in LABELS.items() if truth == 0}
    flagged_safe = {rel for rel, truth, pred, _ in r["rows"] if truth == 0 and pred == 1}
    assert flagged_safe == set(), f"false positives on safe files: {flagged_safe}"
    assert len(safe) == 4
