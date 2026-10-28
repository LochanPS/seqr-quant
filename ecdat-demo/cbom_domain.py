"""ECDAT demo — build a CBOM from a live website (TLS) scan.

Usage:  python cbom_domain.py <domain>
"""
import json, os, sys

_here = os.path.dirname(os.path.abspath(__file__))
for _c in [os.environ.get("SEQR_SHARED", ""),
           os.path.join(_here, "..", "seqr-labs", "shared-scanner")]:
    if _c and os.path.isdir(os.path.join(_c, "seqr_scanner")):
        sys.path.insert(0, os.path.abspath(_c)); break

from seqr_scanner import NetworkScanner
from engines.cbom import CBOMEngine

domain = sys.argv[1] if len(sys.argv) > 1 else "capgemini.com"
out = os.path.join(_here, f"{domain.replace('.', '_')}.cbom.cdx.json")

print(f"\n  Scanning {domain} over TLS ...")
result = NetworkScanner().scan_domain(domain)

engine = CBOMEngine()
components = engine.aggregate(
    network_results=[result],
    org_data_sensitivity="confidential",
    is_public_facing=True,
)
cbom = engine.export_cyclonedx(components)
with open(out, "w", encoding="utf-8") as fh:
    json.dump(cbom, fh, indent=2)

print(f"  Components : {len(components)}")
print(f"  BOM format : {cbom.get('bomFormat')} {cbom.get('specVersion')}")
print(f"  Written    : {out}\n")
print(json.dumps(cbom, indent=2))
