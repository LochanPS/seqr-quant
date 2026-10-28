"""
Origin discovery for CDN-fronted domains.

When a domain is CDN-fronted, a scan of the domain only sees the CDN edge — the
origin server's real crypto posture is invisible. This is the single biggest
accuracy gap for a CBOM tool, since ~65% of measured fintech is CDN-terminated.

This module finds candidate ORIGIN endpoints that are NOT behind the CDN, using
only public/passive signals:
  1. Probe common origin-leak subdomains (origin./direct./mail./ftp./cpanel./...)
     via DNS — fast, stdlib-only, catches the frequent misconfig where an
     ancillary host bypasses the web CDN and exposes origin infrastructure.
  2. Optional Certificate Transparency enrichment (crt.sh) when `use_ct=True`
     (slower / less reliable — crt.sh is frequently overloaded).
  3. Any of these resolving to a non-CDN public IP is a candidate origin —
     an endpoint the customer should assess directly for their true posture.

It does NOT scan the candidates (that is a separate, customer-authorised step).
It is discovery + honest flagging only. Never raises into the scan flow.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import socket
import urllib.request
from dataclasses import dataclass, field


@dataclass
class OriginCandidate:
    hostname: str
    ip: str
    reason: str = "resolves to a non-CDN public IP"


@dataclass
class OriginDiscoveryResult:
    queried: bool                       # CT lookup actually ran
    subdomains_seen: int                # distinct subdomains found in CT
    subdomains_checked: int             # how many we resolved
    candidates: list[OriginCandidate] = field(default_factory=list)
    note: str = ""


def _extract_subdomains(crtsh_json: list, domain: str) -> set[str]:
    """Pure: pull distinct subdomain hostnames for `domain` from crt.sh JSON."""
    out: set[str] = set()
    d = domain.lower().lstrip(".")
    for entry in crtsh_json:
        names = (entry.get("name_value") or "")
        for name in names.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name or "*" in name:
                continue
            if name == d or name.endswith("." + d):
                out.add(name)
    return out


def _fetch_crtsh(domain: str, timeout: float) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "SeQr-Scanner/0.1 security-research"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return []


def _is_cdn_or_unusable(ip: str) -> bool:
    """True if the IP is a CDN edge or otherwise not a usable origin candidate."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return True
    # Lazy import to avoid a circular import with network.py.
    try:
        from scanner.network import _cidr_cdn, _reverse_dns_cdn
        if _cidr_cdn(ip) or _reverse_dns_cdn(ip):
            return True
    except Exception:
        pass
    return False


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


# Subdomains that commonly bypass a web CDN and expose origin infrastructure.
_COMMON_ORIGIN_PREFIXES = (
    "origin", "direct", "backend", "server", "host", "cpanel", "whm", "webdisk",
    "webmail", "mail", "smtp", "imap", "pop", "mx", "ftp", "sftp", "ssh", "vpn",
    "remote", "gateway", "dev", "test", "staging", "uat", "api", "admin", "portal",
    "secure", "ww1", "www2", "old", "legacy", "internal",
)


def discover_origin_candidates(
    domain: str, timeout: float = 8.0, use_ct: bool = False, max_subdomains: int = 50
) -> OriginDiscoveryResult:
    """
    Find candidate origin endpoints for a CDN-fronted domain.
    Never raises — returns an OriginDiscoveryResult.

    Primary signal: common origin-leak subdomains resolved via DNS (fast).
    Optional: Certificate Transparency enrichment when use_ct=True (slower).
    """
    domain = domain.lower().strip()

    hosts: list[str] = [f"{p}.{domain}" for p in _COMMON_ORIGIN_PREFIXES]
    subdomains_seen = 0

    if use_ct:
        crt = _fetch_crtsh(domain, timeout)
        if crt:
            ct_subs = _extract_subdomains(crt, domain)
            subdomains_seen = len(ct_subs)
            priority = ("origin", "direct", "backend", "mail", "smtp", "ftp", "vpn", "dev")
            extra = sorted(ct_subs, key=lambda h: (not h.startswith(priority), len(h)))
            for h in extra:
                if h not in hosts:
                    hosts.append(h)

    to_check = hosts[:max_subdomains]

    # Resolve in parallel with a hard overall deadline — non-existent subdomains
    # can hang on DNS, so we cap total wall time and ignore stragglers.
    candidates: list[OriginCandidate] = []
    seen_ips: set[str] = set()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=15)
    try:
        futs = {pool.submit(_resolve, h): h for h in to_check}
        done, _pending = concurrent.futures.wait(futs, timeout=max(6.0, timeout + 2))
        for fut in done:
            host = futs[fut]
            try:
                ip = fut.result()
            except Exception:
                ip = ""
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            if not _is_cdn_or_unusable(ip):
                candidates.append(OriginCandidate(hostname=host, ip=ip))
    finally:
        pool.shutdown(wait=False)

    note = (
        f"{len(candidates)} candidate origin endpoint(s) found outside the CDN — assess directly."
        if candidates else
        "No origin endpoints discovered outside the CDN; provide the origin host to assess it."
    )
    return OriginDiscoveryResult(
        queried=True,
        subdomains_seen=subdomains_seen,
        subdomains_checked=len(to_check),
        candidates=candidates,
        note=note,
    )
