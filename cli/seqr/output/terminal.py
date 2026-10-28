"""
Rich terminal output for SeQr CLI.
"""
from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Optional

_CNSA2_DEADLINE: int = 2030          # NIST/CNSA 2.0 hard deadline

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from seqr._severity import severity_for_risk, SEVERITY_ORDER

if TYPE_CHECKING:
    from seqr._scanner import CodeFinding, DomainScanResult

__all__ = ["print_code_results", "print_domain_results", "make_console"]

_SEV_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

# CDN-specific remediation instructions
_CDN_REMEDIATION: dict[str, tuple[str, str]] = {
    "cloudflare":        ("Cloudflare Dashboard",
                          "SSL/TLS → Edge Certs → Enable Kyber / ML-KEM in TLS settings."),
    "fastly":            ("Fastly Console",
                          "TLS Configuration → Enable X25519Kyber768 cipher suite group."),
    "amazon cloudfront": ("AWS CloudFront Console",
                          "verify CDN hybrid PQC roadmap with your CDN provider."),
    "akamai":            ("Akamai Control Center",
                          "TLS Management → Cipher Suite → add ML-KEM-768 group."),
    "azure cdn":         ("Azure Front Door",
                          "Security Policy → enable TLS 1.3 with PQC cipher groups."),
    "google cloud cdn":  ("Google Cloud Load Balancer",
                          "SSL Policy → select Custom profile with ML-KEM support."),
}


# ---------------------------------------------------------------------------
# Attribute helpers — guard against MagicMock in tests
# ---------------------------------------------------------------------------

def _s(r, attr: str, default: str = "") -> str:
    val = getattr(r, attr, default)
    return val if isinstance(val, str) else default


def _b(r, attr: str, default: bool = False) -> bool:
    val = getattr(r, attr, default)
    return val if isinstance(val, bool) else default


def _i(r, attr: str, default: int = 0) -> int:
    val = getattr(r, attr, default)
    return val if isinstance(val, int) and not isinstance(val, bool) else default


def _f(r, attr: str, default: float = 0.0) -> float:
    val = getattr(r, attr, default)
    return float(val) if isinstance(val, (int, float)) and not isinstance(val, bool) else default


# ---------------------------------------------------------------------------
# Algorithm classification for display
# ---------------------------------------------------------------------------

def _cert_status(cert_algo: str) -> str:
    a = cert_algo.upper()
    if any(x in a for x in ("ML-DSA", "SLH-DSA", "ML-KEM")):
        return "safe"
    if "KYBER" in a:
        return "hybrid"
    if any(x in a for x in ("RSA", "ECDSA", "DSA", "ED25519", "ED448", "DH")):
        return "vulnerable"
    return "unknown"


def _kex_status(kex: str) -> str:
    k = kex.upper().replace("-", "").replace("_", "")
    if "X25519KYBER" in k or "X25519MLKEM" in k:
        return "hybrid"
    if "MLKEM" in k or "KYBER" in k:
        return "safe"
    if k in ("RSA", "DHE", "DH", "DHE1024", "ECDHE", "ECDH", "X25519", "X448"):
        return "vulnerable"
    if "ECDHE" in k:
        return "vulnerable"
    return "unknown"


def _classic_status(algo_name: str) -> str:
    """Returns 'WEAK' for classically broken algorithms, 'SAFE' otherwise."""
    a = algo_name.upper().replace("-", "").replace("_", "")
    if any(x in a for x in ("RC4", "MD5", "DES", "3DES", "SHA1", "NULL", "EXPORT", "ANON")):
        return "WEAK"
    if a in ("TLS10", "SSL20", "SSL30"):
        return "WEAK"
    return "SAFE"


def _dual_badge(algo_name: str, quantum_st: str) -> str:
    """Return [CLASSIC: SAFE/WEAK] [QUANTUM: SAFE/VULNERABLE/HYBRID] badge pair."""
    classic = _classic_status(algo_name)
    c_color = "green" if classic == "SAFE" else "red"
    classic_part = f"[{c_color}][CLASSIC: {classic}][/{c_color}]"
    if quantum_st == "safe":
        return f"{classic_part} [green][QUANTUM: SAFE][/green]"
    if quantum_st == "hybrid":
        return f"{classic_part} [yellow][QUANTUM: HYBRID][/yellow]"
    if quantum_st in ("vulnerable", "deprecated"):
        return f"{classic_part} [yellow][QUANTUM: VULNERABLE][/yellow]"
    return f"{classic_part} [dim][QUANTUM: UNKNOWN][/dim]"


def _exposure_label(status: str) -> str:
    if status == "safe":
        return "Quantum Safe"
    if status == "hybrid":
        return "Hybrid Protected"
    return "Quantum Exposed"


def _has_forward_secrecy(kex: str, hybrid_status: str) -> bool:
    k = kex.upper().replace("-", "").replace("_", "")
    return "X25519" in k or "ECDHE" in k or hybrid_status in ("hybrid", "full_pqc")


def _pqc_status_line(quantum_status: str, hybrid_status: str) -> str:
    if quantum_status == "safe" or hybrid_status in ("hybrid", "full_pqc"):
        return "QUANTUM READY"
    return "MIGRATION REQUIRED"


# ---------------------------------------------------------------------------
# Recommendation text (uses scanner-provided algorithm names)
# ---------------------------------------------------------------------------

def _clean_rec_algo(raw: str) -> str:
    part = raw.split("/")[0].strip()
    return part.replace(" (signing)", "").replace(" (key exchange)", "").strip()


def _cert_recommendation(r) -> Optional[str]:
    raw_algo = _s(r, "recommended_algorithm_cert", "")
    raw_fips = _s(r, "recommended_fips_cert", "")
    cert_algo = _s(r, "cert_algorithm", "")
    a = cert_algo.upper()
    if any(x in a for x in ("ML-DSA", "SLH-DSA")):
        return "Certificate is quantum-safe."
    if not raw_algo:
        return None
    # Language fix: never "adopt immediately", always "begin planning"
    return (
        "Monitor PKI ecosystem for ML-DSA certificate availability "
        "(expected 2027–2028). At next renewal, request a quantum-safe cert."
    )


def _kex_recommendation(r, kex: str, hybrid_status: str) -> Optional[str]:
    next_step = _s(r, "recommended_next_step", "")
    if next_step:
        return next_step
    if hybrid_status == "full_pqc":
        return "Fully quantum-safe key exchange. No action needed."
    if hybrid_status == "hybrid":
        raw_algo = _s(r, "recommended_algorithm_kex", "")
        algo = _clean_rec_algo(raw_algo) if raw_algo else "ML-KEM"
        return (
            f"Hybrid PQC active. Plan migration to {algo}-only "
            f"by {_CNSA2_DEADLINE} when client support is sufficient."
        )
    k = kex.upper().replace("-", "").replace("_", "")
    raw_algo = _s(r, "recommended_algorithm_kex", "")
    raw_fips = _s(r, "recommended_fips_kex", "")
    algo = _clean_rec_algo(raw_algo) if raw_algo else "ML-KEM-768"
    fips = raw_fips.split("/")[0].strip() if raw_fips else "FIPS 203"
    if "RSA" in k or k in ("DH", "DHE", "DHE1024"):
        return f"Replace RSA key exchange with {algo} ({fips})"
    if k in ("X25519", "ECDHE", "ECDH", "X448") or "ECDHE" in k:
        return "Deploy X25519Kyber768 hybrid key exchange — keep X25519 for client compatibility."
    return None


def _cdn_remediation_step(cdn_provider: str) -> Optional[tuple[str, str]]:
    p = cdn_provider.lower()
    for key, (console_name, action) in _CDN_REMEDIATION.items():
        if key in p:
            return console_name, action
    if cdn_provider:
        return (
            f"{cdn_provider} Console",
            "verify CDN hybrid PQC roadmap with your CDN provider.",
        )
    return None


def _scan_type_label(domain: str, shelf_life: str) -> str:
    d = domain.lower()
    if any(k in d for k in ("pay", "payment", "bank", "banking", "finance", "fintech", "wallet", "loan", "razorpay", "stripe", "paytm")):
        return "Financial Architecture"
    if any(k in d for k in ("health", "medical", "hospital", "pharma", "patient")):
        return "Healthcare Architecture"
    if any(k in d for k in ("gov", "mil", "government", "ministry", "federal")):
        return "Government Infrastructure"
    if any(k in d for k in ("auth", "login", "sso", "oauth")):
        return "Authentication Infrastructure"
    if shelf_life == "permanent":
        return "Critical Infrastructure"
    if shelf_life == "long":
        return "High-Value Data Architecture"
    return "domain"


# ---------------------------------------------------------------------------
# Console factory
# ---------------------------------------------------------------------------

def make_console(no_colour: bool = False) -> Console:
    import sys
    import io
    file = None
    if sys.platform == "win32":
        try:
            fd = sys.stdout.fileno()
            file = io.open(fd, "w", encoding="utf-8", closefd=False)
        except Exception:
            pass
    return Console(highlight=False, no_color=no_colour, legacy_windows=False, file=file)


def _print_upsell_footer(console: Console) -> None:
    divider = "─" * 50
    console.print()
    console.print(f"  [dim]{divider}[/dim]")
    console.print("  Full compliance report + CBOM export: [bold]seqrlabs.com[/bold]")
    console.print(
        "  Includes: PCI DSS · SEBI CSCRF · RBI Q-SAFE · DST Task Force "
        "mapping · CBOM export · PDF report"
    )
    console.print(f"  [dim]{divider}[/dim]")
    console.print()


def print_header(console: Console, target: str, scan_type: str = "code") -> None:
    from seqr import __version__
    console.print(
        Panel(
            f"[bold]SeQr PQC Scanner v{__version__}[/bold]\n"
            f"Scanning: [cyan]{target}[/cyan]  |  Type: {scan_type}",
            box=box.ROUNDED,
        )
    )


# ---------------------------------------------------------------------------
# Code results (unchanged)
# ---------------------------------------------------------------------------

def print_code_results(
    console: Console,
    findings: list,
    files_scanned: int,
    target: str,
    min_severity: str = "low",
    quiet: bool = False,
) -> None:
    from seqr import __version__

    if not quiet:
        print_header(console, target, "code")

    min_idx = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 0
    visible = [f for f in findings if SEVERITY_ORDER.index(severity_for_risk(f.algorithm_risk)) >= min_idx]

    if not visible:
        console.print(
            f"\n[green]No issues found[/green] — {files_scanned} file(s) scanned, 0 findings.\n"
        )
        return

    groups: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for f in visible:
        sev = severity_for_risk(f.algorithm_risk)
        groups[sev].append(f)

    counts = {s: len(groups[s]) for s in SEVERITY_ORDER}

    console.print()
    lines: list[str] = []
    for sev in reversed(SEVERITY_ORDER):
        items = groups[sev]
        if not items:
            continue
        color = _SEV_COLOR[sev]
        lines.append(f"  [{color}]{sev.upper()} ({len(items)})[/{color}]")
        lines.append(f"  [dim]{'─' * 73}[/dim]")
        for item in items:
            lines.append(f"  [bold]{item.file_path}:{item.line_number}[/bold]")
            lines.append(f"    [dim]{item.code_snippet}[/dim]")
            lines.append(
                f"    Algorithm: [yellow]{item.algorithm}[/yellow]  "
                f"|  Risk: [{color}]{sev.upper()}[/{color}]  "
                f"|  Confidence: {item.confidence.upper()}"
            )
            lines.append(
                f"    [green]▶ Replace with: {item.recommended_replacement}[/green]"
            )
            lines.append("")

    panel_content = "\n".join(lines)
    console.print(Panel(panel_content, title="[bold]FINDINGS[/bold]", box=box.ROUNDED))

    total = sum(counts.values())
    critical_n = counts["critical"]
    high_n = counts["high"]
    medium_n = counts["medium"]
    low_n = counts["low"]

    effort_min = sum(f.estimated_effort_hours for f in visible)
    effort_max = int(effort_min * 1.5)

    console.print()
    console.print("  [bold]SUMMARY[/bold]")
    console.print("  " + "─" * 50)
    console.print(f"  Files scanned:   {files_scanned}")
    console.print(
        f"  Findings:        {total} "
        f"([red]{critical_n} critical[/red], [red]{high_n} high[/red], "
        f"[yellow]{medium_n} medium[/yellow], [cyan]{low_n} low[/cyan])"
    )
    safe_count = max(0, files_scanned - len(set(f.file_path for f in visible)))
    console.print(f"  Quantum-safe:    {safe_count} files")
    console.print(f"  Est. fix effort: {effort_min}–{effort_max} hours total")

    _print_upsell_footer(console)


# ---------------------------------------------------------------------------
# Domain results
# ---------------------------------------------------------------------------

def print_domain_results(
    console: Console,
    results: list,
    quiet: bool = False,
    shelf_life_override: Optional[str] = None,
    verbose: bool = False,
) -> None:
    if not quiet:
        domains = ", ".join(r.domain for r in results)
        first = next((r for r in results if r.reachable), results[0] if results else None)
        shelf = shelf_life_override or (
            _s(first, "data_shelf_life", "short") if first else "short"
        )
        scan_type = _scan_type_label(first.domain if first else domains, shelf)
        print_header(console, domains, scan_type)

    console.print()
    for r in results:
        _print_single_domain(console, r, shelf_life_override, verbose=verbose)

    if len(results) > 1:
        _print_summary(console, results)


def _collect_secure_items(r, tls: str, kex: str, hybrid_status: str, cert_expired: bool) -> list[str]:
    items: list[str] = []
    if tls == "TLS_1_3":
        items.append("TLS 1.3 in use — modern protocol, forward secrecy")
    if kex in ("X25519", "ECDHE", "X25519Kyber768") or hybrid_status in ("hybrid", "full_pqc"):
        items.append("Forward secrecy enabled")
    if not cert_expired:
        cert = getattr(r, "cert", None)
        expiry = None
        if cert is not None:
            expiry = getattr(cert, "expiry_date", None)
        if expiry is not None and hasattr(expiry, "strftime"):
            items.append(f"Certificate valid (expires: {expiry.strftime('%Y-%m-%d')})")
        else:
            items.append("Certificate not expired")
    if tls not in ("TLS_1_0", "TLS_1_1", "SSL_2_0", "SSL_3_0", "unknown", ""):
        items.append("No deprecated protocols (TLS 1.0/1.1 disabled)")
    if hybrid_status in ("hybrid", "full_pqc"):
        items.append("Already using hybrid PQC")
    return items


# ---------------------------------------------------------------------------
# Single domain dispatch
# ---------------------------------------------------------------------------

def _print_single_domain(
    console: Console,
    r,
    shelf_life_override: Optional[str],
    verbose: bool = False,
) -> None:
    if verbose:
        _print_domain_verbose(console, r, shelf_life_override)
    else:
        _print_domain_default(console, r, shelf_life_override)


def _print_unreachable(console: Console, r) -> None:
    scan_outcome = getattr(r, "scan_outcome", None)
    outcome_str = scan_outcome if isinstance(scan_outcome, str) and scan_outcome else "unreachable"
    error_msg = r.error_message or "connection failed"
    console.print(
        Panel(
            f"[red]✗[/red]  Could not complete scan: {outcome_str}\n"
            f"   {_clean_sslyze_error(error_msg)}",
            title="[bold red]Scan Error[/bold red]",
            box=box.ROUNDED,
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Compact body (shared by default and verbose)
# ---------------------------------------------------------------------------

def _print_domain_compact_body(
    console: Console,
    r,
    shelf_life_override: Optional[str],
) -> None:
    """Print the LITE compact section. Called by both default and verbose paths."""
    tls = _s(r, "tls_version", "unknown")
    cert_algo = (getattr(r.cert, "algorithm", None) if r.cert else None) or _s(r, "cert_algorithm", "unknown")
    kex = _s(r, "key_exchange_algorithm", "unknown")
    hybrid_status = _s(r, "hybrid_status", "none")
    quantum_status = _s(r, "quantum_status", "unknown")
    cert_expired = _b(r, "cert_expired", False)
    cdn_detected = getattr(r, "cdn_detected", None)
    cdn_provider = _s(r, "cdn_provider", "")
    if cdn_detected is True and not cdn_provider:
        cdn_provider = "CDN"

    console.print()
    console.print(f"  [bold]{r.domain}:{r.port}[/bold]")
    console.print()

    cert_st = _cert_status(cert_algo)
    kex_st = _kex_status(kex)
    cert_lbl = _exposure_label(cert_st)
    kex_lbl = _exposure_label(kex_st)

    def _col(label: str, status: str) -> str:
        if status == "safe":
            return f"[green]{label}[/green]"
        if status == "hybrid":
            return f"[yellow]{label}[/yellow]"
        return f"[red]{label}[/red]"

    cert_algo_disp = (cert_algo or "unknown")[:14]
    kex_disp = (kex or "unknown")[:14]

    console.print(f"  TLS Version:    {tls}")
    console.print(f"  Certificate:    {cert_algo_disp:<14} {_col(cert_lbl, cert_st)}")
    if cert_expired:
        console.print("  [red]               ⚠ Certificate EXPIRED[/red]")
    console.print(f"  Key Exchange:   {kex_disp:<14} {_col(kex_lbl, kex_st)}")

    fs = _has_forward_secrecy(kex, hybrid_status)
    fs_disp = "[green]YES[/green]" if fs else "[red]NO[/red]"
    console.print(f"  Forward Secrecy: {fs_disp}")

    cdn_label = cdn_provider if cdn_detected is True and cdn_provider else "Direct"
    console.print(f"  CDN:            {cdn_label}")
    if cdn_detected is True:
        console.print(
            "  [dim]                (low confidence — origin server config unknown)[/dim]"
        )

    pqc_label = _pqc_status_line(quantum_status, hybrid_status)
    pqc_color = "red" if pqc_label == "MIGRATION REQUIRED" else "green"
    console.print(f"  PQC Status:     [{pqc_color}]{pqc_label}[/{pqc_color}]")


# ---------------------------------------------------------------------------
# Default output (compact + hint)
# ---------------------------------------------------------------------------

def _print_domain_default(
    console: Console,
    r,
    shelf_life_override: Optional[str],
) -> None:
    if not r.reachable:
        _print_unreachable(console, r)
        return

    _print_domain_compact_body(console, r, shelf_life_override)
    _print_upsell_footer(console)


# ---------------------------------------------------------------------------
# Verbose output (compact + all sections + evidence + framework)
# ---------------------------------------------------------------------------

def _print_domain_verbose(
    console: Console,
    r,
    shelf_life_override: Optional[str],
) -> None:
    if not r.reachable:
        _print_unreachable(console, r)
        return

    _print_domain_compact_body(console, r, shelf_life_override)

    # Re-extract fields needed for verbose sections
    tls = _s(r, "tls_version", "unknown")
    cert_algo = (getattr(r.cert, "algorithm", None) if r.cert else None) or _s(r, "cert_algorithm", "unknown")
    kex = _s(r, "key_exchange_algorithm", "unknown")
    hybrid_status = _s(r, "hybrid_status", "none")
    quantum_status = _s(r, "quantum_status", "unknown")
    cert_expired = _b(r, "cert_expired", False)
    cdn_detected = getattr(r, "cdn_detected", None)
    cdn_provider = _s(r, "cdn_provider", "")

    raw_ms = getattr(r, "scan_duration_ms", None)
    if isinstance(raw_ms, (int, float)) and not isinstance(raw_ms, bool):
        duration_ms = int(raw_ms)
    else:
        duration_ms = int(_f(r, "scan_duration_seconds", 0.0) * 1000)

    # ── WHAT IS SECURE ───────────────────────────────────
    tls_deprecated = tls in ("TLS_1_0", "TLS_1_1", "SSL_2_0", "SSL_3_0")
    secure_items = _collect_secure_items(r, tls, kex, hybrid_status, cert_expired)
    if secure_items and not tls_deprecated:
        console.print()
        console.print("  [bold]WHAT IS SECURE[/bold]")
        console.print("  [dim]──────────────[/dim]")
        for item in secure_items:
            console.print(f"  [green]✓[/green] {item}")

    # ── CRYPTOGRAPHIC ALGORITHM STATUS ───────────────────
    console.print()
    console.print("  [bold]CRYPTOGRAPHIC ALGORITHM STATUS[/bold]")
    console.print("  [dim]──────────────────────────────[/dim]")

    cert_q_status = _cert_status(cert_algo)
    cert_badge = _dual_badge(cert_algo, cert_q_status)
    console.print(f"  Certificate:      {cert_algo:<14} {cert_badge}")
    if cert_expired:
        console.print("  [bold red]  ⚠ Certificate is EXPIRED[/bold red]")

    kex_q_status = _kex_status(kex)
    kex_badge = _dual_badge(kex, kex_q_status)
    console.print(f"  Key Exchange:     {kex:<14} {kex_badge}")

    if hybrid_status == "hybrid":
        console.print("  Hybrid PQC KEM:   [yellow]ACTIVE[/yellow]  ↳ X25519Kyber768 detected")
    elif hybrid_status == "full_pqc":
        console.print("  Hybrid PQC KEM:   [green]ACTIVE (Full PQC)[/green]  ↳ ML-KEM detected")
    else:
        console.print("  Hybrid PQC KEM:   UNSUPPORTED")
        console.print("  [dim]               ↳ Passive scan only — active ML-KEM handshake[/dim]")
        console.print("  [dim]                 not attempted without hybrid ClientHello.[/dim]")

    # ── REMEDIATION ACTIONS ───────────────────────────────
    if quantum_status == "safe":
        console.print()
        console.print("  [green]✓ This domain appears quantum-safe.[/green]")
    else:
        action_items: list[tuple[str, str]] = []

        if cdn_detected is True:
            cdn_step = _cdn_remediation_step(cdn_provider)
            if cdn_step:
                action_items.append(("Edge/CDN Layer", f"{cdn_step[0]} → {cdn_step[1]}"))

        cert_rec = _cert_recommendation(r)
        if cert_rec and "quantum-safe" not in cert_rec:
            action_items.append(("Certificate", cert_rec))

        kex_rec = _kex_recommendation(r, kex, hybrid_status)
        if kex_rec and "No action" not in kex_rec:
            action_items.append(("Key Exchange", kex_rec))

        if action_items:
            console.print()
            console.print("  [bold]REMEDIATION ACTIONS[/bold]")
            console.print("  [dim]──────────────────[/dim]")
            for idx, (label, action) in enumerate(action_items, 1):
                console.print(f"  {idx}. {label:<14} → {action}")
        elif hybrid_status == "hybrid":
            console.print()
            console.print(
                f"  [yellow]Hybrid PQC active. Monitor client support and "
                f"begin migration planning for full ML-KEM by {_CNSA2_DEADLINE}.[/yellow]"
            )

    # ── EVIDENCE OBSERVED ─────────────────────────────────
    _print_evidence_section(console, r, tls, kex, duration_ms)

    _print_upsell_footer(console)


def _print_evidence_section(
    console: Console,
    r,
    tls: str,
    kex: str,
    duration_ms: int,
) -> None:
    cert = getattr(r, "cert", None)

    def _cert_field(name: str, default: str = "") -> str:
        val = getattr(cert, name, None) if cert is not None else None
        if val is None or not isinstance(val, (str, datetime.datetime, datetime.date)):
            return default
        if hasattr(val, "strftime"):
            return val.strftime("%Y-%m-%d")
        return str(val)

    ip_str = _s(r, "ip_address_scanned", "")
    cipher = _s(r, "cipher_suite", "")
    cert_subject = _cert_field("subject")
    cert_expiry = _cert_field("expiry_date")
    cert_issuer = _cert_field("issuer")

    console.print()
    console.print("  [bold]EVIDENCE OBSERVED[/bold]")
    console.print("  [dim]─────────────────[/dim]")
    if ip_str:
        console.print(f"  IP Connected:     {ip_str}")
    if duration_ms:
        console.print(f"  Scan Duration:    {duration_ms}ms")
    if cert_subject:
        console.print(f"  Cert Subject:     {cert_subject}")
    if cert_expiry:
        console.print(f"  Cert Expiry:      {cert_expiry}")
    if cert_issuer:
        console.print(f"  Cert Issuer:      {cert_issuer}")
    console.print(f"  TLS Version:      {tls}")
    if cipher:
        console.print(f"  Cipher Suite:     {cipher}")
    console.print(f"  Key Exchange:     {kex}")


# ---------------------------------------------------------------------------
# Summary (multi-domain)
# ---------------------------------------------------------------------------

def _print_summary(console: Console, results: list) -> None:
    reachable = [r for r in results if r.reachable]
    errors    = [r for r in results if not r.reachable]
    cdn_list  = [r for r in reachable if getattr(r, "cdn_detected", None) is True]

    success = [
        r for r in reachable
        if _s(r, "scan_outcome", "success") in ("success", "")
    ]

    rsa_count   = sum(1 for r in reachable if "RSA"   in _s(r, "cert_algorithm", "").upper())
    ecdsa_count = sum(1 for r in reachable if "ECDSA" in _s(r, "cert_algorithm", "").upper())
    other_cert  = len(reachable) - rsa_count - ecdsa_count

    x25519_count  = 0
    rsa_kex_count = 0
    kyber_count   = 0
    ecdhe_count   = 0
    for r in reachable:
        kex = _s(r, "key_exchange_algorithm", "")
        k = kex.upper().replace("-", "").replace("_", "")
        if "X25519KYBER" in k:
            kyber_count += 1
        elif kex == "X25519":
            x25519_count += 1
        elif kex == "RSA":
            rsa_kex_count += 1
        elif "ECDHE" in k:
            ecdhe_count += 1

    console.print("  " + "━" * 51)
    console.print("  [bold]SCAN SUMMARY[/bold]")
    console.print("  " + "━" * 51)
    console.print(f"  Domains scanned:       {len(results)}")
    console.print(f"  [dim]{'─' * 50}[/dim]")
    console.print(f"  Successful scans:      {len(success)}")
    console.print(f"  Errors / unreachable:  {len(errors)}")
    console.print(f"  CDN-terminated:        {len(cdn_list)}")
    if cdn_list:
        console.print("    [dim](low confidence — origin server config unknown)[/dim]")
    console.print(f"  [dim]{'─' * 50}[/dim]")
    console.print("  Certificate algorithms found:")
    console.print(f"    RSA:   {rsa_count} domains")
    console.print(f"    ECDSA: {ecdsa_count} domains")
    if other_cert > 0:
        console.print(f"    Other: {other_cert} domains")
    console.print("  Key exchange algorithms found:")
    for label, count in [
        ("X25519", x25519_count),
        ("ECDHE", ecdhe_count),
        ("RSA (static)", rsa_kex_count),
        ("X25519Kyber768", kyber_count),
    ]:
        if count:
            console.print(f"    {label:<18}  {count} domains")
    console.print("  " + "━" * 51)
    console.print()


def _clean_sslyze_error(msg: str) -> str:
    import re
    m = re.search(r'"([^"]+)"', msg)
    if m:
        return f"[red]{m.group(1)}[/red]"
    return f"[red]{msg[:120]}[/red]"
