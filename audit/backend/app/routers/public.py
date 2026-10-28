"""
Public (unauthenticated) API for the marketing landing page demo scanner.

Intentionally minimal:
- No auth, no org, no database write
- Only returns directly-measured fields (no inferred risk scores)
- Rate limited: 5 requests per IP per hour
- SSRF-protected: rejects private/internal addresses
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import ipaddress
import re
import socket
import time
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

# ---------------------------------------------------------------------------
# Rate limiting — in-memory, per IP, max 5 requests per hour
# ---------------------------------------------------------------------------

_rate_store: dict[str, list[float]] = defaultdict(list)   # retained for tests that clear it
_RATE_LIMIT = 5
_RATE_WINDOW = 3600  # seconds


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(ip: str) -> int:
    """Consume one token. Return 0 if OK, or minutes-until-reset if limited."""
    from app.ratelimit import hit
    exceeded, retry_after = hit(f"public_scan:{ip}", _RATE_LIMIT, _RATE_WINDOW)
    return (int(retry_after / 60) + 1) if exceeded else 0


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

# Strict hostname regex — must have at least one dot and a valid TLD
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
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
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
    """Raise HTTP 400 if domain is invalid or resolves to a private address."""
    d = domain.lower()

    if d in _BLOCKED_NAMES:
        raise HTTPException(
            status_code=400,
            detail="Cannot scan private or internal addresses",
        )

    if any(d.endswith(s) for s in _BLOCKED_SUFFIXES):
        raise HTTPException(
            status_code=400,
            detail="Cannot scan private or internal addresses",
        )

    if not _HOSTNAME_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # Resolve EVERY address (IPv4 + IPv6) and reject if ANY falls in a private
    # range. gethostbyname only returns one IPv4 — an attacker can hide a private
    # IP behind extra A/AAAA records. getaddrinfo enumerates them all.
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        # DNS failure here is fine — scanner will report reachable=False
        return
    for info in infos:
        addr = info[4][0]
        if _is_private_ip(addr):
            raise HTTPException(
                status_code=400,
                detail="Cannot scan private or internal addresses",
            )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class PublicScanRequest(BaseModel):
    domain: str


class PublicScanResponse(BaseModel):
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
    scan_target: str = "direct"          # "direct" | "edge" (CDN-terminated)
    origin_assessed: bool = True
    deployment_level: int = 1
    deployment_level_name: str = "Modern Classical"
    crypto_agility_score: float = 0.0
    cdn_detected: bool = False
    cdn_provider: Optional[str] = None
    scan_duration_ms: int = 0


class PublicScanUnreachable(BaseModel):
    domain: str
    reachable: bool = False
    error_category: str
    message: str


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/scan")
async def public_scan(body: PublicScanRequest, request: Request):
    domain = body.domain.strip()

    # 1. Rate limit
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

    # 2. SSRF / format validation
    _validate_domain(domain)

    # 3. Run scanner with hard 20-second timeout
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

    # 3b. DNS-rebinding guard: the IP the scanner ACTUALLY connected to may differ
    # from what we validated (attacker flips DNS between checks). Re-validate the
    # connected IP and discard results if it turns out to be private/internal.
    connected_ip = getattr(result, "ip_address_scanned", "") or ""
    if connected_ip and _is_private_ip(connected_ip):
        raise HTTPException(
            status_code=400,
            detail="Cannot scan private or internal addresses",
        )

    # 4. Unreachable domain
    if not result.reachable:
        category = (
            result.scan_outcome
            if result.scan_outcome not in ("success", "")
            else "connection_refused"
        )
        return PublicScanUnreachable(
            domain=result.domain,
            reachable=False,
            error_category=category,
            message="Could not reach this domain on port 443.",
        )

    # 5. Format cert expiry
    cert_expiry: Optional[str] = None
    if result.cert and result.cert.expiry_date:
        exp = result.cert.expiry_date
        cert_expiry = exp.strftime("%Y-%m-%d") if hasattr(exp, "strftime") else str(exp)

    return PublicScanResponse(
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
    )


async def _run_scanner(domain: str):
    """Run NetworkScanner.scan_domain in a thread pool (blocking call)."""
    from seqr_scanner import NetworkScanner

    loop = asyncio.get_event_loop()

    def _sync() :
        scanner = NetworkScanner(active_pqc=True)
        raw = scanner.scan_domain(domain)
        if inspect.iscoroutine(raw):
            return asyncio.run(raw)
        return raw

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(pool, _sync)
