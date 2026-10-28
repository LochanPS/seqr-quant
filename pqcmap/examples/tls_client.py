"""Show what PQC-hybrid TLS this machine can do, and (optionally) fetch a URL with it.

    python -m examples.tls_client                 # just print the capability report
    python -m examples.tls_client https://example.com   # fetch over the pqcmap context

On OpenSSL 3.5+ (or with the liboqs oqs-provider) and Python 3.13+, the client offers
X25519MLKEM768; otherwise it degrades to secure classical TLS 1.3 and the report says so.
"""
from __future__ import annotations

import sys

from pqcmap.tls import capabilities
from pqcmap.tls.http import pqc_httpx_client


def main(argv: list[str]) -> int:
    caps = capabilities()
    print(caps.summary())
    for note in caps.notes:
        print(f"  - {note}")

    if len(argv) < 2:
        print("\n(pass a URL to fetch it over the pqcmap TLS context)")
        return 0

    url = argv[1]
    try:
        with pqc_httpx_client(timeout=10.0) as client:
            resp = client.get(url)
        print(f"\nGET {url} -> {resp.status_code} ({len(resp.content)} bytes)")
        return 0
    except Exception as exc:  # network / TLS errors — this is a demo, report and exit
        print(f"\nGET {url} failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":  # pragma: no cover - manual run
    raise SystemExit(main(sys.argv))
