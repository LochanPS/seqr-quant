"""
Origin-leakage analysis for the paper.

For each domain, run passive origin discovery (common origin-leak subdomains via
DNS). Quantifies how many domains expose a non-CDN origin endpoint — a new,
paper-worthy finding ("edge PQC ≠ origin safety; origins are often exposed").

Passive DNS only (no scanning of candidates). Aggregate stats; do not publish
per-entity weakness data without responsible disclosure.
"""
import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "shared-scanner"))
from scanner.origin_discovery import discover_origin_candidates

FILES = ["domains.csv", "domains_india_extended.csv", "domains_global.csv"]


def load(path):
    rows = []
    with open(Path(__file__).parent / path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            d = (r.get("domain") or "").strip()
            if d:
                rows.append({"domain": d, "country": r.get("country", "IN")})
    return rows


def main():
    domains = []
    for fp in FILES:
        if (Path(__file__).parent / fp).exists():
            domains += load(fp)
    # dedup
    seen = set()
    domains = [d for d in domains if not (d["domain"] in seen or seen.add(d["domain"]))]

    print(f"Origin-leakage scan: {len(domains)} domains")
    results = []
    leaked = 0
    for i, item in enumerate(domains, 1):
        d = item["domain"]
        t = time.time()
        disc = discover_origin_candidates(d, timeout=5)
        n = len(disc.candidates)
        if n:
            leaked += 1
        results.append({
            "domain": d, "country": item["country"],
            "candidates": [{"hostname": c.hostname, "ip": c.ip} for c in disc.candidates],
            "candidate_count": n,
        })
        print(f"[{i:>3}/{len(domains)}] {d:<40} candidates={n} ({round(time.time()-t,1)}s)")

    out = Path(__file__).parent / "origin_leakage_results.json"
    out.write_text(json.dumps(results, indent=2))

    print("\n" + "=" * 50)
    print(f"Domains analysed:        {len(domains)}")
    print(f"With exposed origin(s):  {leaked} ({leaked/len(domains)*100:.0f}%)")
    by_c = {}
    for r in results:
        c = r["country"]
        by_c.setdefault(c, [0, 0])
        by_c[c][0] += 1
        if r["candidate_count"]:
            by_c[c][1] += 1
    print("By country:")
    for c, (tot, lk) in sorted(by_c.items(), key=lambda x: -x[1][0]):
        print(f"  {c:<4} {lk}/{tot} ({lk/tot*100:.0f}%)")
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
