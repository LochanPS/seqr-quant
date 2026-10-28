"""
Filter domains.csv to remove likely-internal/staging/dev/private hostnames
discovered via certificate transparency logs (crt.sh).

Problem: crt.sh returns everything in CT logs — including internal corporate
infrastructure that never resolves publicly. ~60% of raw crt.sh dumps are
unreachable. This filter keeps only public-facing domains.

Run from: research/
    python filter_domains.py
"""

import csv
import re
from pathlib import Path

HERE = Path(__file__).parent

# Two-letter country-code subdomains that signal geo-routing/internal nodes.
# Requires 2+ domain segments after the 2-letter part so we don't flag
# legitimate short SLDs like fi.money or niyo.co.
# Catches: cdn.tw.razorpay.com (.tw. → razorpay.com = 2 segments)
# Skips:   api.fi.money (.fi. → money = 1 segment — "fi" is the SLD)
_COUNTRY_CODE_SUBDOMAIN = re.compile(r"\.[a-z]{2}\.[^.]+\.")

# Numbered subdomains: looker21.company.com, app02.example.com, web3.corp.com
# Does NOT match tls3.company.com (common CDN pattern) — requires 3+ alpha chars
_NUMBERED_SUBDOMAIN = re.compile(r"(?<!\d)[a-z]{3,}\d+\.")

_INTERNAL_INDICATORS = [
    # Explicit environment labels
    ".corp.", "corp.",
    ".internal.", "internal.",
    ".local.", "localhost",
    "intranet.",
    "staging.", ".staging",
    ".dev.", "dev.",
    ".test.", "test.",
    ".qa.", "qa.",
    "prod.",        # yesbank-client-cert.prod.razorpay.com
    ".prod.",
    # Identity / SSO / SCIM (always internal)
    "scim", "1p",
    # Certificate management endpoints
    "-cert.", "client-cert",
    # Analytics / BI tools (internal)
    "looker", "metabase", "grafana", "kibana", "prometheus",
]


def is_likely_internal(domain: str) -> bool:
    d = domain.lower()
    if any(ind in d for ind in _INTERNAL_INDICATORS):
        return True
    if _NUMBERED_SUBDOMAIN.search(d):
        return True
    if _COUNTRY_CODE_SUBDOMAIN.search(d):
        return True
    return False


def main() -> None:
    src = HERE / "domains.csv"
    dst = HERE / "domains_clean.csv"

    with src.open(newline="") as f:
        all_rows = list(csv.DictReader(f))

    clean = [r for r in all_rows if not is_likely_internal(r["domain"].strip())]
    dropped = [r for r in all_rows if is_likely_internal(r["domain"].strip())]

    with dst.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "entity", "entity_type"])
        writer.writeheader()
        writer.writerows(clean)

    print(f"Filtered: {len(all_rows)} -> {len(clean)} domains ({len(dropped)} dropped)")
    if dropped:
        print(f"\nDropped:")
        for r in dropped:
            print(f"  {r['domain']}  [{r['entity']}]")
    print(f"\nSaved to {dst}")


if __name__ == "__main__":
    main()
