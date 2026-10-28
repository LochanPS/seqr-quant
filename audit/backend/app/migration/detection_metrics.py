"""Detection precision/recall for the SeQr code scanner (QUANT-A-MAZE / PQC-01).

PQC-01 asks us to "evaluate detection precision/recall on labelled code and configs." We run the
real SeQr code scanner over a hand-labelled ACME Bank corpus and score it at the file level: a
file is flagged if the scanner reports >=1 quantum-vulnerable finding in it.

Ground truth (read by inspection, not inferred from the scanner):
  • sample-repo/*                     — vulnerable by design (RSA / ECDSA / DH)        -> POSITIVE
  • sample-repo-mixed/legacy/*.js     — forge.pki.rsa.generateKeyPair                  -> POSITIVE
  • sample-repo-safe/*                — pqcmap ML-KEM / ML-DSA (quantum-safe)          -> NEGATIVE
  • sample-repo-mixed/{auth,payments} — pqcmap ML-KEM / ML-DSA                         -> NEGATIVE

The safe files are genuine negatives: they USE cryptography (pqcmap), so they test that the
scanner flags *quantum-vulnerable* crypto, not merely "crypto present".

The scanner is loaded standalone (bypassing the package __init__, which pulls sslyze and would
downgrade cryptography) — only tree-sitter is needed for code scanning.

Usage:  python -m app.migration.detection_metrics
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
_SCANNER = _ROOT / "shared-scanner"
_ECDAT = _ROOT / "ecdat-demo"

# file (relative to ecdat-demo) -> 1 vulnerable / 0 safe
LABELS: dict[str, int] = {
    "sample-repo/auth/tokens.py": 1,
    "sample-repo/core/src/CryptoUtil.java": 1,
    "sample-repo/gateway/ecdsa_gateway.go": 1,
    "sample-repo/gateway/rsa_gateway.go": 1,
    "sample-repo/infra/ssh_deploy.py": 1,
    "sample-repo/payments/legacy_dh.py": 1,
    "sample-repo/payments/rsa_keys.py": 1,
    "sample-repo/web/src/auth.js": 1,
    "sample-repo/web/src/legacy_crypto.js": 1,
    "sample-repo-mixed/legacy/statements.js": 1,
    "sample-repo-safe/auth/tokens.py": 0,
    "sample-repo-safe/payments/keys.py": 0,
    "sample-repo-mixed/auth/tokens.py": 0,
    "sample-repo-mixed/payments/keys.py": 0,
}


def _load_code_scanner():
    """Load scanner/code.py standalone — avoids scanner/__init__.py importing sslyze."""
    spec = importlib.util.spec_from_file_location("seqr_code", _SCANNER / "scanner" / "code.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["seqr_code"] = mod
    spec.loader.exec_module(mod)
    return mod.CodeScanner


def flagged_files() -> tuple[set[Path], list]:
    """Scan every labelled repo; return the set of files with >=1 finding + all findings."""
    CodeScanner = _load_code_scanner()
    repos = {p.split("/")[0] for p in LABELS}
    flagged: set[Path] = set()
    all_findings = []
    for repo in sorted(repos):
        findings = CodeScanner().scan_directory(str(_ECDAT / repo))
        all_findings.extend(findings)
        for f in findings:
            flagged.add(Path(f.file_path).resolve())
    return flagged, all_findings


def evaluate() -> dict:
    flagged, findings = flagged_files()
    rows = []
    tp = fp = fn = tn = 0
    for rel, truth in LABELS.items():
        pred = 1 if (_ECDAT / rel).resolve() in flagged else 0
        if truth and pred:
            tp += 1; outcome = "TP"
        elif not truth and pred:
            fp += 1; outcome = "FP"
        elif truth and not pred:
            fn += 1; outcome = "FN"
        else:
            tn += 1; outcome = "TN"
        rows.append((rel, truth, pred, outcome))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(LABELS)
    return {"rows": rows, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
            "total_findings": len(findings), "findings": findings}


def main() -> None:
    r = evaluate()
    print("=== SeQr code-scanner detection metrics (labelled ACME corpus) ===\n")
    print(f"  files labelled : {len(LABELS)}  ({sum(LABELS.values())} vulnerable, "
          f"{len(LABELS) - sum(LABELS.values())} safe)")
    print(f"  raw findings   : {r['total_findings']} across the vulnerable files\n")
    print(f"  {'file':44} {'truth':6} {'pred':5} outcome")
    for rel, truth, pred, outcome in r["rows"]:
        print(f"  {rel:44} {('vuln' if truth else 'safe'):6} "
              f"{('flag' if pred else 'clean'):5} {outcome}")
    print(f"\n  confusion : TP={r['tp']}  FP={r['fp']}  FN={r['fn']}  TN={r['tn']}")
    print(f"  precision : {r['precision']:.3f}   (flagged files that really are vulnerable)")
    print(f"  recall    : {r['recall']:.3f}   (vulnerable files we caught)")
    print(f"  F1        : {r['f1']:.3f}")
    print(f"  accuracy  : {r['accuracy']:.3f}")
    # algorithm breakdown of the raw findings
    from collections import Counter
    algs = Counter(getattr(f, "algorithm_family", getattr(f, "algorithm", "?")) for f in r["findings"])
    print(f"\n  detected algorithm families: {dict(algs)}")


if __name__ == "__main__":
    main()
