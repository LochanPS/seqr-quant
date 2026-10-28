"""ECDAT demo — turn a code scan into a standards-compliant CBOM.

Scans the sample repo, aggregates every cryptographic finding into a
CycloneDX 1.6 Cryptographic Bill of Materials, and writes it to disk.

Usage:  python generate_cbom.py [path-to-repo]
"""

import json
import os
import sys

# Make the SeQr scanner engine importable no matter where this is run from.
# Priority: SEQR_SHARED env var → sibling ../seqr-labs/shared-scanner.
_here = os.path.dirname(os.path.abspath(__file__))
_candidates = [
    os.environ.get("SEQR_SHARED", ""),
    os.path.join(_here, "..", "seqr-labs", "shared-scanner"),
]
for _c in _candidates:
    if _c and os.path.isdir(os.path.join(_c, "seqr_scanner")):
        sys.path.insert(0, os.path.abspath(_c))
        break

from seqr_scanner import CodeScanner
from engines.cbom import CBOMEngine

REPO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "sample-repo"
)
OUT = os.path.join(os.path.dirname(__file__), "acme-bank.cbom.cdx.json")


def main():
    print(f"\n  Scanning {REPO} ...")
    findings = CodeScanner().scan_directory(REPO)

    engine = CBOMEngine()
    components = engine.aggregate(
        code_findings=findings,
        org_data_sensitivity="confidential",
        is_public_facing=True,
    )
    cbom = engine.export_cyclonedx(components)

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(cbom, fh, indent=2)

    summary = engine.summarise(components)
    print(f"  Cryptographic components found : {len(components)}")
    print(f"  BOM format                     : {cbom.get('bomFormat')} "
          f"{cbom.get('specVersion')}")
    print(f"  CBOM written                   : {OUT}")
    print()
    # Show the algorithm families discovered
    families = {}
    for comp in components:
        fam = getattr(comp, "algorithm_family", None) or getattr(
            comp, "algorithm", "?")
        families[fam] = families.get(fam, 0) + 1
    print("  Algorithms in inventory:")
    for fam, n in sorted(families.items()):
        print(f"    - {fam}: {n}")
    print()


if __name__ == "__main__":
    main()
