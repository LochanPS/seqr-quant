"""Baseline: accept existing findings so only NEW drift fails."""
import json
from dataclasses import dataclass

from seqr.ci.baseline import (
    Baseline,
    build_baseline,
    fingerprint,
    filter_new,
    find_baseline_file,
    load_baseline,
    save_baseline,
)


@dataclass
class F:
    file_path: str = "src/a.py"
    line_number: int = 10
    pattern_id: str = "py.rsa.keygen"
    algorithm: str = "RSA-2048"
    code_snippet: str = "rsa.generate_private_key()"


def test_fingerprint_is_line_independent():
    a = F(line_number=10)
    b = F(line_number=250)  # same file/pattern/algo/snippet, moved down
    assert fingerprint(a, root=".") == fingerprint(b, root=".")


def test_fingerprint_differs_on_algorithm():
    assert fingerprint(F(algorithm="RSA-2048"), root=".") != fingerprint(F(algorithm="ECDSA"), root=".")


def test_save_then_load_roundtrip(tmp_path):
    findings = [F(file_path="src/a.py"), F(file_path="src/b.py", algorithm="ECDSA")]
    path = tmp_path / "seqr-baseline.json"
    count = save_baseline(path, findings, root=str(tmp_path))
    assert count == 2
    bl = load_baseline(path)
    assert isinstance(bl, Baseline)
    assert all(bl.contains(f, root=str(tmp_path)) for f in findings)


def test_filter_new_subtracts_baselined(tmp_path):
    existing = F(file_path="src/legacy.py", algorithm="RSA-2048")
    path = tmp_path / "seqr-baseline.json"
    save_baseline(path, [existing], root=str(tmp_path))
    bl = load_baseline(path)

    fresh = F(file_path="src/new.py", algorithm="ECDSA")
    new, baselined = filter_new([existing, fresh], bl, root=str(tmp_path))
    assert [f.file_path for f in new] == ["src/new.py"]
    assert [f.file_path for f in baselined] == ["src/legacy.py"]


def test_missing_baseline_is_empty_and_fails_open(tmp_path):
    bl = load_baseline(tmp_path / "nope.json")
    assert bl.fingerprints == set()
    new, baselined = filter_new([F()], bl, root=str(tmp_path))
    assert len(new) == 1 and baselined == []


def test_build_baseline_dedupes_and_sorts():
    body = build_baseline([F(), F()], root=".")  # identical → one entry
    assert body["count"] == 1
    assert body["version"] == 1
    assert body["findings"][0]["algorithm"] == "RSA-2048"


def test_find_baseline_file(tmp_path):
    assert find_baseline_file(tmp_path) is None
    (tmp_path / "seqr-baseline.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert find_baseline_file(tmp_path) is not None
