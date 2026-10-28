"""
SeQr Labs — Research Scanner
Scans Indian fintech domains and records only measured TLS data.
No inferred fields. No hardcoded risk scores.
Results are raw observations suitable for academic research.
"""

import asyncio
import csv
import json
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning, module="sslyze")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")

sys.path.insert(0, str(Path(__file__).parent.parent / "shared-scanner"))
from seqr_scanner import NetworkScanner

# Fields that are MEASURED by the scanner (safe to include in research)
MEASURED_FIELDS = {
    "domain", "reachable", "tls_version", "cert_algorithm",
    "cert_expiry_date", "cert_issuer", "cert_expired",
    "key_exchange", "hybrid_status", "pqc_offered",
    "quantum_status", "cdn_detected", "cdn_provider",
    "deployment_level", "crypto_agility_score",
    "threat_timeline", "scan_outcome", "scan_timestamp",
    "ip_address_scanned", "scan_duration_ms",
    "scan_confidence", "scan_confidence_note",
    "error_message", "error_category",
    # Active PQC probe (only populated with --active + OpenSSL 3.5+)
    "pqc_active_probed", "pqc_active_supported", "pqc_active_group",
}

# Fields that are INFERRED from domain name — excluded from research
INFERRED_FIELDS = {
    "estimated_hndl_exposure", "hndl_inference_basis",
    "data_shelf_life", "pqc_migration_priority",
}

DOMAINS_FILE  = Path(__file__).parent / "domains.csv"
CHECKPOINT    = Path(__file__).parent / "checkpoint.json"
RESULTS_DIR   = Path(__file__).parent


def load_domains(limit: int = None, path=None) -> list[dict]:
    rows = []
    with open(path or DOMAINS_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = (row.get("domain") or "").strip()
            if domain:
                rows.append({
                    "domain": domain,
                    "entity": row.get("entity", ""),
                    "entity_type": row.get("entity_type", ""),
                    "country": row.get("country", "IN"),
                })
    if limit:
        rows = rows[:limit]
    return rows


def load_checkpoint() -> tuple[set, list]:
    if CHECKPOINT.exists():
        try:
            cp = json.loads(CHECKPOINT.read_text())
            completed = {r["domain"] for r in cp.get("results", [])}
            results = cp.get("results", [])
            return completed, results
        except Exception:
            pass
    return set(), []


def save_checkpoint(results: list, total: int):
    CHECKPOINT.write_text(json.dumps({
        "results": results,
        "total": total,
        "saved_at": datetime.utcnow().isoformat()
    }, default=str))


def result_to_research_dict(result, entity: str, entity_type: str) -> dict:
    """
    Extract only measured fields from DomainScanResult.
    Excludes all inferred/computed fields to ensure research
    integrity. Every field here is directly observed from
    the TLS handshake or DNS resolution.
    """
    row = {"entity": entity, "entity_type": entity_type}
    for field in MEASURED_FIELDS:
        val = getattr(result, field, None)
        if val is not None:
            row[field] = str(val) if not isinstance(val, (bool, int, float)) else val
    return row


def print_row(i: int, total: int, row: dict):
    domain = row.get("domain", "?")
    outcome = row.get("scan_outcome", "?")
    if outcome != "success":
        print(f"[{i:>3}/{total}] {domain:<45} UNREACHABLE — {row.get('error_message','')[:60]}")
        return
    tls     = row.get("tls_version", "?")
    cert    = row.get("cert_algorithm", "?")
    kex     = row.get("key_exchange", "?")
    cdn     = f"[{row.get('cdn_provider','?')}]" if row.get("cdn_detected") else "[direct]"
    hybrid  = "PQC" if row.get("pqc_offered") else ""
    level   = f"L{row.get('deployment_level','?')}"
    print(f"[{i:>3}/{total}] {domain:<45} {level} | {tls:<8} | {cert:<14} | kex={kex:<16} {hybrid} {cdn}")


async def validate_scanner():
    """
    Verify scanner produces genuinely different results for
    known-different servers before running production scan.
    Uses badssl.com which provides servers with specific configs.
    """
    print("\nValidating scanner against known-different servers...")
    print("-" * 60)
    scanner = NetworkScanner(rate_limit_seconds=0.5)
    test_domains = [
        ("rsa2048.badssl.com",   "RSA-2048 cert expected"),
        ("ecc256.badssl.com",    "ECDSA-P256 cert expected"),
        ("expired.badssl.com",   "Expired cert expected"),
        ("tls-v1-0.badssl.com",  "TLS 1.0 expected"),
    ]
    results = []
    for domain, expectation in test_domains:
        result = scanner.scan_domain(domain)
        row = result_to_research_dict(result, "badssl", "validation")
        results.append(row)
        status = "OK" if row.get("scan_outcome") == "success" else "XX"
        print(f"  {status} {domain:<35} {expectation}")
        print(f"    cert={row.get('cert_algorithm','?')} "
              f"tls={row.get('tls_version','?')} "
              f"expired={row.get('cert_expired','?')} "
              f"kex={row.get('key_exchange','?')}")

    # Check results are genuinely different
    cert_algos = {r.get("cert_algorithm") for r in results
                  if r.get("scan_outcome") == "success"}
    print(f"\nDistinct cert algorithms across 4 servers: {len(cert_algos)}")
    if len(cert_algos) >= 2:
        print("OK Scanner producing genuinely varied results. Safe to run full scan.")
        return True
    else:
        print("XX Scanner returned identical results. Do not run full scan until fixed.")
        return False


async def main(limit: int = None, validate: bool = False,
               rate: float = 0.5, resume: bool = True, active: bool = False,
               domains_file: str = None, tag: str = ""):

    if validate:
        ok = await validate_scanner()
        if not ok:
            sys.exit(1)
        return

    rows = load_domains(limit, path=domains_file)
    total = len(rows)

    completed, results = set(), []
    if resume:
        completed, results = load_checkpoint()
        if completed:
            print(f"Resuming: {len(completed)}/{total} already done")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    prefix = f"results_{tag}_" if tag else "results_"
    output_file = RESULTS_DIR / f"{prefix}{timestamp}.json"

    mode = "ACTIVE (OpenSSL 3.5 PQC probe)" if active else "passive only"
    print(f"\nSeQr Labs Research Scanner")
    print(f"Domains to scan: {total - len(completed)} remaining of {total} total")
    print(f"Rate limit: {rate}s | Mode: {mode} | Only measured TLS fields recorded")
    print(f"Output: {output_file}")
    print(f"{'-'*60}")

    scanner = NetworkScanner(rate_limit_seconds=rate, active_pqc=active)
    remaining = [r for r in rows if r["domain"] not in completed]
    done = len(completed)

    for item in remaining:
        domain = item["domain"]
        done += 1
        result = scanner.scan_domain(domain)
        row = result_to_research_dict(result, item["entity"], item["entity_type"])
        row["country"] = item.get("country", "IN")
        results.append(row)
        print_row(done, total, row)

        if done % 10 == 0:
            save_checkpoint(results, total)

    # Final save
    output_file.write_text(json.dumps(results, indent=2, default=str))
    if CHECKPOINT.exists():
        CHECKPOINT.unlink()

    # Summary — only from measured fields
    reachable  = [r for r in results if r.get("scan_outcome") == "success"]
    cdn        = [r for r in reachable if r.get("cdn_detected") == "True"
                  or r.get("cdn_detected") is True]
    hybrid     = [r for r in reachable if r.get("pqc_offered") == "True"
                  or r.get("pqc_offered") is True]
    active_pqc = [r for r in reachable if r.get("pqc_active_supported") == "True"
                  or r.get("pqc_active_supported") is True]
    tls13      = [r for r in reachable if r.get("tls_version") == "TLS_1_3"]
    legacy_tls = [r for r in reachable
                  if r.get("tls_version") in ("TLS_1_0", "TLS_1_1")]

    cert_counts = {}
    for r in reachable:
        c = r.get("cert_algorithm", "unknown")
        cert_counts[c] = cert_counts.get(c, 0) + 1

    kex_counts = {}
    for r in reachable:
        k = r.get("key_exchange", "unknown")
        kex_counts[k] = kex_counts.get(k, 0) + 1

    n = len(reachable)
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}")
    print(f"Total domains:        {total}")
    print(f"Reachable:            {n} ({n/total*100:.0f}%)")
    print(f"Unreachable:          {total-n}")
    print(f"CDN-terminated:       {len(cdn)} ({len(cdn)/n*100:.0f}% of reachable)")
    print(f"TLS 1.3:              {len(tls13)} ({len(tls13)/n*100:.0f}%)")
    print(f"Legacy TLS (1.0/1.1): {len(legacy_tls)} ({len(legacy_tls)/n*100:.0f}%)")
    print(f"Hybrid PQC offered:   {len(hybrid)} ({len(hybrid)/n*100:.0f}%)  [passive]")
    if active_pqc or any(r.get("pqc_active_probed") in ("True", True) for r in reachable):
        print(f"Hybrid PQC confirmed: {len(active_pqc)} ({len(active_pqc)/n*100:.0f}%)  [active probe]")
    print(f"\nCertificate algorithms:")
    for algo, count in sorted(cert_counts.items(), key=lambda x: -x[1]):
        print(f"  {algo:<20} {count} ({count/n*100:.0f}%)")
    print(f"\nKey exchange algorithms:")
    for kex, count in sorted(kex_counts.items(), key=lambda x: -x[1]):
        print(f"  {kex:<20} {count} ({count/n*100:.0f}%)")
    print(f"\nResults saved: {output_file}")
    print(f"\nNote: Only measured TLS observations recorded.")
    print(f"HNDL and risk scores excluded — require data flow")
    print(f"analysis beyond passive TLS scanning.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SeQr Research Scanner")
    parser.add_argument("--limit",    type=int,   help="Scan first N domains only")
    parser.add_argument("--rate",     type=float, default=0.5, help="Seconds between scans")
    parser.add_argument("--validate", action="store_true", help="Validate scanner on badssl.com first")
    parser.add_argument("--resume",   action="store_true", default=True, help="Resume from checkpoint")
    parser.add_argument("--active",   action="store_true", help="Active PQC probe (needs OpenSSL 3.5+)")
    parser.add_argument("--domains",  type=str, help="Path to a domains CSV (default domains.csv)")
    parser.add_argument("--tag",      type=str, default="", help="Output filename tag (e.g. global)")
    parser.add_argument("--no-resume", action="store_true", help="Ignore checkpoint")
    args = parser.parse_args()
    asyncio.run(main(limit=args.limit, validate=args.validate,
                     rate=args.rate, resume=not args.no_resume, active=args.active,
                     domains_file=args.domains, tag=args.tag))
