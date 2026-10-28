"""
Standalone public demo scanner for the SeQr landing page.

Deliberately separate from the audit backend: no auth, no Postgres, no
Celery, no org/tenant model. Just the real NetworkScanner wrapped in
rate limiting and SSRF protection, deployable as its own small service
(Render free/starter tier) so the marketing site's "try it live" claim
is backed by a real network scan.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import ipaddress
import os
import re
import socket
import time
from collections import defaultdict
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SeQr Scan Demo Service", version="1.0.0", docs_url=None, redoc_url=None)

_frontend_origins = [
    o.strip() for o in os.environ.get("FRONTEND_ORIGINS", "http://localhost:3000").split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_frontend_origins,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Rate limiting — in-memory, per IP, max 5 requests per hour
# ---------------------------------------------------------------------------

_rate_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT = 5
_RATE_WINDOW = 3600.0  # seconds


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(ip: str) -> int:
    """Consume one token. Return 0 if OK, or minutes-until-reset if limited."""
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_LIMIT:
        oldest = _rate_store[ip][0]
        reset_secs = _RATE_WINDOW - (now - oldest)
        return max(1, int(reset_secs / 60) + 1)
    _rate_store[ip].append(now)
    return 0


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)

_BLOCKED_NAMES = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
})

_BLOCKED_SUFFIXES = (
    ".local", ".internal", ".localhost", ".localdomain",
    ".test", ".example", ".invalid", ".lan",
)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _validate_domain(domain: str) -> None:
    d = domain.lower()

    if d in _BLOCKED_NAMES:
        raise HTTPException(status_code=400, detail="Cannot scan private or internal addresses")

    if any(d.endswith(s) for s in _BLOCKED_SUFFIXES):
        raise HTTPException(status_code=400, detail="Cannot scan private or internal addresses")

    if not _HOSTNAME_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # Validate EVERY resolved address (IPv4 + IPv6). gethostbyname returns only
    # one IPv4 — extra A/AAAA records could hide a private IP.
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        # DNS failure here is fine — scanner will report reachable=False
        return
    for info in infos:
        if _is_private_ip(info[4][0]):
            raise HTTPException(status_code=400, detail="Cannot scan private or internal addresses")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    domain: str


class ScanResponse(BaseModel):
    domain: str
    reachable: bool
    tls_version: Optional[str] = None
    cert_algorithm: Optional[str] = None
    cert_expiry_date: Optional[str] = None
    key_exchange: Optional[str] = None
    hybrid_status: Optional[str] = None
    pqc_offered: bool = False
    pqc_active_supported: bool = False
    pqc_active_group: Optional[str] = None
    scan_target: str = "direct"
    origin_assessed: bool = True
    deployment_level: int = 1
    deployment_level_name: str = "Modern Classical"
    crypto_agility_score: float = 0.0
    cdn_detected: bool = False
    cdn_provider: Optional[str] = None
    scan_duration_ms: int = 0
    # Mini cryptographic bill of materials synthesised from this single scan.
    # None if the CBOM layer failed (never blocks the scan itself).
    cbom: Optional[dict] = None


class ScanUnreachable(BaseModel):
    domain: str
    reachable: bool = False
    error_category: str
    message: str


# ---------------------------------------------------------------------------
# Mini-CBOM synthesis
# ---------------------------------------------------------------------------

# HNDL disclaimer — required in ALL customer-facing crypto-risk output
# (CLAUDE.md, Critical Technical Decision #2).
HNDL_DISCLAIMER = (
    "HNDL exposure scores are predictive cryptographic risk metrics based on "
    "data-type endurance, not indicators of active data interception or "
    "confirmed network breaches."
)

# Subset of CryptoComponent fields safe + useful to surface publicly.
_PUBLIC_CBOM_FIELDS = (
    "id", "location_type", "location_detail", "algorithm", "algorithm_family",
    "key_size", "quantum_status", "algorithm_risk", "final_risk_score",
    "hndl_risk", "migration_priority", "threat_timeline",
    "recommended_algorithm", "recommended_fips", "estimated_effort_hours",
    "protocol", "tls_version",
)


def _build_public_cbom(result) -> Optional[dict]:
    """
    Synthesise a mini-CBOM from a single public domain scan.

    Runs the real CBOMEngine (the exact code path the authenticated product
    uses) over one DomainScanResult, so "Try It Live" ends in a genuine,
    downloadable CycloneDX 1.6 cryptographic bill of materials — not a mock.
    Fully stateless: no DB, no auth, built from the scan already performed.

    Never raises into the scan flow — CBOM is a bonus layer on top of the scan.
    """
    try:
        from dataclasses import asdict
        from engines.cbom import CBOMEngine

        engine = CBOMEngine()
        components = engine.aggregate(
            network_results=[result],
            org_data_sensitivity="internal",
            is_public_facing=True,
        )
        if not components:
            return None

        comp_dicts = []
        for c in components:
            d = asdict(c)
            comp_dicts.append({k: d.get(k) for k in _PUBLIC_CBOM_FIELDS})

        by_timeline: dict[str, int] = {}
        by_family: dict[str, int] = {}
        for c in components:
            if c.threat_timeline:
                by_timeline[c.threat_timeline] = by_timeline.get(c.threat_timeline, 0) + 1
            by_family[c.algorithm_family] = by_family.get(c.algorithm_family, 0) + 1

        return {
            "components": comp_dicts,
            "summary": {
                "total_components": len(components),
                "vulnerable_count": sum(
                    1 for c in components
                    if c.quantum_status in ("vulnerable", "deprecated")
                ),
                "safe_count": sum(1 for c in components if c.quantum_status == "safe"),
                "by_threat_timeline": by_timeline,
                "by_algorithm_family": by_family,
            },
            "cyclonedx": engine.export_cyclonedx(components),
            "disclaimer": HNDL_DISCLAIMER,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/public/scan")
async def public_scan(body: ScanRequest, request: Request):
    domain = body.domain.strip()

    ip = _get_client_ip(request)
    wait_minutes = _check_rate_limit(ip)
    if wait_minutes:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit reached. Try again in {wait_minutes} minutes, "
                "or sign up for unlimited scans."
            ),
        )

    _validate_domain(domain)

    try:
        result = await asyncio.wait_for(_run_scanner(domain), timeout=20.0)
    except asyncio.TimeoutError:
        return {
            "error": "timeout",
            "message": (
                "This domain took too long to respond. "
                "It may be behind aggressive WAF protection."
            ),
        }

    # DNS-rebinding guard: re-validate the IP actually connected to.
    connected_ip = getattr(result, "ip_address_scanned", "") or ""
    if connected_ip and _is_private_ip(connected_ip):
        raise HTTPException(status_code=400, detail="Cannot scan private or internal addresses")

    if not result.reachable:
        category = (
            result.scan_outcome
            if result.scan_outcome not in ("success", "")
            else "connection_refused"
        )
        return ScanUnreachable(
            domain=result.domain,
            reachable=False,
            error_category=category,
            message="Could not reach this domain on port 443.",
        )

    cert_expiry: Optional[str] = None
    if result.cert and result.cert.expiry_date:
        exp = result.cert.expiry_date
        cert_expiry = exp.strftime("%Y-%m-%d") if hasattr(exp, "strftime") else str(exp)

    return ScanResponse(
        domain=result.domain,
        reachable=True,
        tls_version=result.tls_version or None,
        cert_algorithm=result.cert_algorithm or None,
        cert_expiry_date=cert_expiry,
        key_exchange=result.key_exchange_algorithm or None,
        hybrid_status=result.hybrid_status or None,
        pqc_offered=bool(result.pqc_hybrid_offered or result.pqc_only_offered),
        pqc_active_supported=bool(getattr(result, "pqc_active_supported", False)),
        pqc_active_group=getattr(result, "pqc_active_group", "") or None,
        scan_target=getattr(result, "scan_target", "direct"),
        origin_assessed=bool(getattr(result, "origin_assessed", True)),
        deployment_level=result.deployment_level,
        deployment_level_name=result.deployment_level_name,
        crypto_agility_score=result.crypto_agility_score,
        cdn_detected=result.cdn_detected,
        cdn_provider=result.cdn_provider or None,
        scan_duration_ms=result.scan_duration_ms,
        cbom=_build_public_cbom(result),
    )


async def _run_scanner(domain: str):
    """Run NetworkScanner.scan_domain in a thread pool (blocking call)."""
    from seqr_scanner import NetworkScanner

    loop = asyncio.get_event_loop()

    def _sync():
        scanner = NetworkScanner(active_pqc=True)
        raw = scanner.scan_domain(domain)
        if inspect.iscoroutine(raw):
            return asyncio.run(raw)
        return raw

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(pool, _sync)
