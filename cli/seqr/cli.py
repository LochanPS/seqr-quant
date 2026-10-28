"""
SeQr CLI entry point.
All commands defined here.
"""
from __future__ import annotations

import json
import os
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="sslyze")
warnings.filterwarnings("ignore", message=".*negative serial number.*")
from pathlib import Path

import click

from seqr import __version__
from seqr._severity import severity_for_risk, SEVERITY_ORDER

# ---------------------------------------------------------------------------
# Shared option factories
# ---------------------------------------------------------------------------

_OUTPUT_CHOICES = click.Choice(["terminal", "json", "sarif"])


def _output_opt(choices=None):
    return click.option(
        "--output",
        default="terminal",
        type=choices or _OUTPUT_CHOICES,
        help="Output format",
        show_default=True,
    )


def _save_opt():
    return click.option("--save", default=None, metavar="PATH", help="Save results to file")


def _fail_on_opt():
    return click.option(
        "--fail-on",
        "fail_on",
        default=None,
        type=click.Choice(SEVERITY_ORDER),
        help="Exit 1 if findings at this severity exist (for CI)",
    )


def _policy_opt():
    return click.option(
        "--policy",
        default=None,
        type=click.Choice(["strict", "lax"]),
        help=(
            "CI policy shorthand: strict=fail on URGENT+ findings, "
            "lax=fail on IMMEDIATE only. "
            "Default: exit 0 always (never breaks builds unless --policy or --fail-on set)."
        ),
    )


def _severity_opt():
    return click.option(
        "--severity",
        default="low",
        type=click.Choice(SEVERITY_ORDER),
        help="Only show findings at this level or above",
        show_default=True,
    )


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--api-key", envvar="SEQR_API_KEY", default=None, hidden=True)
@click.option("--no-colour", "--no-color", is_flag=True, default=False, help="Disable colour")
@click.option("--quiet", is_flag=True, default=False, help="Only print findings, no progress")
@click.version_option(__version__, prog_name="seqr")
@click.pass_context
def main(ctx, api_key, no_colour, quiet):
    """SeQr PQC Scanner — find quantum-vulnerable cryptography."""
    ctx.ensure_object(dict)
    ctx.obj["api_key"] = api_key
    ctx.obj["no_colour"] = no_colour
    ctx.obj["quiet"] = quiet


# ---------------------------------------------------------------------------
# scan group
# ---------------------------------------------------------------------------

@main.group()
def scan():
    """Run a scan."""


# ── scan code ──────────────────────────────────────────────────────────────

@scan.command("code")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--language", default=None, help="Only scan this language (python|javascript|java|go|all)")
@click.option("--exclude", multiple=True, metavar="GLOB", help="Glob pattern to exclude (repeatable)")
@click.option("--include", default=None, metavar="GLOB", help="Only scan files matching this glob")
@_severity_opt()
@_fail_on_opt()
@_policy_opt()
@_output_opt()
@_save_opt()
@click.option("--quiet", is_flag=True, default=False, help="Only print findings")
@click.option("--ranked", is_flag=True, default=False,
              help="Rank findings by context-aware risk (exposure, crypto role, data, blast radius)")
@click.option("--context", "context_file", default=None, type=click.Path(exists=True, dir_okay=False),
              help="JSON/YAML file of per-path context overrides for --ranked (implies --ranked)")
@click.pass_context
def scan_code(ctx, path, language, exclude, include, severity, fail_on, policy, output, save, quiet,
              ranked, context_file):
    """Scan a local code directory for quantum-vulnerable cryptography."""
    no_colour = ctx.obj.get("no_colour", False)
    quiet = quiet or ctx.obj.get("quiet", False)

    from seqr._scanner import CodeScanner

    scanner = CodeScanner()

    exclude_dirs: set[str] = set()
    for pat in exclude:
        exclude_dirs.add(pat.rstrip("/"))

    if not quiet and output == "terminal":
        from seqr.output.terminal import make_console
        console = make_console(no_colour)
        console.print(f"[dim]Scanning {path}...[/dim]")

    all_findings = scanner.scan_directory(path, exclude_dirs=exclude_dirs if exclude_dirs else None)

    # Filter by language
    if language and language != "all":
        ext_map = {"python": (".py", ".pyw"), "javascript": (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"),
                   "java": (".java",), "go": (".go",)}
        exts = ext_map.get(language, ())
        all_findings = [f for f in all_findings if Path(f.file_path).suffix.lower() in exts]

    # Count files scanned (rough: unique file paths)
    files_scanned = len(set(f.file_path for f in all_findings)) or _count_files(path, language)

    # Apply severity filter for display
    min_idx = SEVERITY_ORDER.index(severity)
    display_findings = [
        f for f in all_findings
        if SEVERITY_ORDER.index(severity_for_risk(f.algorithm_risk)) >= min_idx
    ]

    # Output
    if ranked or context_file:
        rendered = _render_ranked(display_findings, files_scanned, path, output, no_colour, context_file)
    else:
        rendered = _render_code(display_findings, files_scanned, path, output, no_colour, quiet)

    if save:
        Path(save).write_text(rendered, encoding="utf-8")
    elif output != "terminal":
        click.echo(rendered)

    # Exit code
    if fail_on:
        fail_idx = SEVERITY_ORDER.index(fail_on)
        has_fail = any(
            SEVERITY_ORDER.index(severity_for_risk(f.algorithm_risk)) >= fail_idx
            for f in all_findings
        )
        if has_fail:
            sys.exit(1)

    if policy:
        # strict = URGENT+ ≈ severity high+; lax = IMMEDIATE only ≈ severity critical
        policy_sev = "high" if policy == "strict" else "critical"
        policy_idx = SEVERITY_ORDER.index(policy_sev)
        if any(
            SEVERITY_ORDER.index(severity_for_risk(f.algorithm_risk)) >= policy_idx
            for f in all_findings
        ):
            sys.exit(1)


def _render_code(findings, files_scanned, target, output, no_colour, quiet):
    if output == "json":
        from seqr.output.json_export import build_code_report
        return json.dumps(build_code_report(findings, files_scanned, target), indent=2)
    if output == "sarif":
        from seqr.output.sarif import build_sarif
        root = os.path.abspath(target) if os.path.isdir(target) else None
        return json.dumps(build_sarif(findings, root=root), indent=2)
    # terminal
    from seqr.output.terminal import make_console, print_code_results
    import io
    buf = io.StringIO()
    console = make_console(no_colour)
    print_code_results(console, findings, files_scanned, target, quiet=quiet)
    return ""


_TIER_STYLE = {"IMMEDIATE": "bold red", "URGENT": "bold yellow", "PLANNED": "cyan", "MONITOR": "dim"}


def _render_ranked(findings, files_scanned, target, output, no_colour, context_file):
    """Context-aware ranking (risk v2): every finding scored 0-100 with the reasons behind it."""
    from seqr._scanner.engines.risk_v2 import RiskContext, assess_findings, summarize

    try:
        context = RiskContext.load(context_file)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--context")
    results = assess_findings(findings, target, context)
    summary = summarize(results)

    if output == "json":
        return json.dumps({"target": target, "files_scanned": files_scanned,
                           "summary": summary, "findings": [a.to_dict() for a in results]}, indent=2)

    from rich.table import Table
    from seqr.output.terminal import make_console
    console = make_console(no_colour)
    table = Table(title=f"Risk-ranked findings — {target}", show_lines=False, expand=True)
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Tier", no_wrap=True)
    table.add_column("Where")
    table.add_column("Role / exposure")
    table.add_column("Why")
    for i, a in enumerate(results, 1):
        style = _TIER_STYLE.get(a.tier, "")
        where = f"{a.rel_path}:{a.line_number}\n[dim]{a.algorithm}[/dim]"
        guess = " [dim](inferred)[/dim]" if "exposure" in a.inferred else ""
        role = f"{a.role.replace('_', ' ')}\n{a.exposure}{guess}" + ("\n[red]HNDL[/red]" if a.hndl else "")
        table.add_row(str(i), f"[{style}]{a.score:.0f}[/{style}]", f"[{style}]{a.tier}[/{style}]",
                      where, role, "; ".join(a.reasons(2)))
    console.print(table)
    t = summary["tiers"]
    console.print(f"  {summary['findings']} findings · IMMEDIATE {t['IMMEDIATE']} · URGENT {t['URGENT']} · "
                  f"PLANNED {t['PLANNED']} · MONITOR {t['MONITOR']}")
    if summary["inferred_exposure"]:
        console.print(f"  [dim]{summary['inferred_exposure']} findings have exposure inferred from file paths; "
                      "pass --context <file> to supply exposure, data and controls.[/dim]")
    if summary["hndl"]:
        console.print(f"  [dim]{summary['hndl_disclaimer']}[/dim]")
    return ""


def _count_files(path: str, language) -> int:
    root = Path(path)
    exts = {".py", ".pyw", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".java", ".go"}
    if language and language != "all":
        ext_map = {"python": {".py", ".pyw"}, "javascript": {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"},
                   "java": {".java"}, "go": {".go"}}
        exts = ext_map.get(language, exts)
    return sum(1 for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts)


# ── scan domain ────────────────────────────────────────────────────────────

@scan.command("domain")
@click.argument("domains", nargs=-1, required=False)
@click.option("--file", "domains_file", default=None, type=click.Path(exists=True),
              help="File with one domain per line (# = comment, blank lines ignored)")
@click.option("--port", default=443, show_default=True, help="Port to scan")
@click.option("--timeout", default=10, show_default=True, help="Connection timeout (seconds)")
@click.option("--shelf-life", "shelf_life", default=None,
              type=click.Choice(["ephemeral", "short", "medium", "long", "permanent"]),
              help="Override data shelf life for HNDL risk assessment "
                   "(default: inferred from domain name)")
@click.option("--verbose", is_flag=True, default=False,
              help="Show full evidence and framework reference sections")
@_output_opt(click.Choice(["terminal", "json"]))
@_save_opt()
@_fail_on_opt()
@_policy_opt()
@click.pass_context
def scan_domain(ctx, domains, domains_file, port, timeout, shelf_life, verbose, output, save, fail_on, policy):
    """Scan domain TLS configuration. Accepts positional domains and/or --file."""
    no_colour = ctx.obj.get("no_colour", False)
    quiet = ctx.obj.get("quiet", False)

    all_domains: list[str] = list(domains)
    if domains_file:
        lines = Path(domains_file).read_text(encoding="utf-8").splitlines()
        all_domains += [
            ln.strip() for ln in lines
            if ln.strip() and not ln.strip().startswith("#")
        ]

    if not all_domains:
        raise click.UsageError("Provide at least one domain as argument or via --file.")

    from seqr._scanner import NetworkScanner
    scanner = NetworkScanner(timeout=timeout)

    use_progress = (
        len(all_domains) > 1
        and not quiet
        and output == "terminal"
    )

    if use_progress:
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
        from seqr.output.terminal import make_console
        console = make_console(no_colour)
        results: list = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning domains", total=len(all_domains))
            for i, d in enumerate(all_domains, 1):
                progress.update(task, description=f"Scanning domain {i}/{len(all_domains)}: {d}")
                results.append(scanner.scan_domain(d, port=port))
                progress.advance(task)
    else:
        if not quiet and output == "terminal":
            from seqr.output.terminal import make_console
            console = make_console(no_colour)
            console.print(f"[dim]Scanning {', '.join(all_domains)}...[/dim]")
        results = scanner.scan_domains(all_domains, port=port)

    # Apply explicit shelf-life override: set field + recompute hndl_risk
    if shelf_life:
        for r in results:
            if not r.reachable:
                continue
            try:
                r.data_shelf_life = shelf_life
                kex_class = getattr(r, "key_exchange_classification", None)
                is_hndl_kex = (
                    kex_class is not None
                    and getattr(kex_class, "hndl_candidate", False)
                    and getattr(kex_class, "quantum_status", "") == "vulnerable"
                )
                r.hndl_risk = is_hndl_kex and shelf_life in ("long", "permanent")
            except Exception:
                pass

    if output == "json":
        from seqr.output.json_export import build_domain_report
        out = json.dumps(build_domain_report(results), indent=2)
    else:
        from seqr.output.terminal import make_console, print_domain_results
        console = make_console(no_colour)
        print_domain_results(console, results, quiet=quiet, shelf_life_override=shelf_life, verbose=verbose)
        out = ""

    if save and out:
        Path(save).write_text(out, encoding="utf-8")
    elif out:
        click.echo(out)

    if fail_on:
        from seqr._severity import severity_for_risk
        fail_idx = SEVERITY_ORDER.index(fail_on)
        if any(
            SEVERITY_ORDER.index(severity_for_risk(r.final_algorithm_risk)) >= fail_idx
            for r in results if r.reachable
        ):
            sys.exit(1)

    if policy:
        # strict = fail on URGENT+; lax = fail on IMMEDIATE only
        timelines_to_fail = (
            ("URGENT", "IMMEDIATE") if policy == "strict" else ("IMMEDIATE",)
        )
        if any(
            (getattr(r, "threat_timeline", "") or "").upper() in timelines_to_fail
            for r in results if r.reachable
        ):
            sys.exit(1)


# ── scan certs ─────────────────────────────────────────────────────────────

@scan.command("certs")
@click.argument("path", type=click.Path(exists=True))
@click.option("--recursive/--no-recursive", default=True, show_default=True)
@click.option("--types", default="pem,crt,cer,key,pub", show_default=True, help="File extensions to scan")
@click.pass_context
def scan_certs(ctx, path, recursive, types):
    """Scan local certificate files and SSH keys."""
    no_colour = ctx.obj.get("no_colour", False)
    from seqr.output.terminal import make_console
    console = make_console(no_colour)

    extensions = {f".{t.strip().lstrip('.')}" for t in types.split(",")}
    root = Path(path)
    pattern = "**/*" if recursive else "*"

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from seqr._severity import severity_for_risk

    found = 0
    for cert_file in root.glob(pattern):
        if not cert_file.is_file():
            continue
        if cert_file.suffix.lower() not in extensions:
            continue
        found += 1
        try:
            data = cert_file.read_bytes()
            cert = x509.load_pem_x509_certificate(data)
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                algo = f"RSA-{pub.key_size}"
                risk = 8
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                algo = f"ECDSA-{pub.curve.name}"
                risk = 7
            else:
                algo = type(pub).__name__
                risk = 3
            sev = severity_for_risk(risk)
            console.print(f"  [bold]{cert_file}[/bold]  [{sev}]{algo}[/{sev}]  Risk: {sev.upper()}")
        except Exception:
            console.print(f"  [dim]{cert_file}[/dim]  (could not parse)")

    if found == 0:
        console.print(f"No certificate files found in {path}")


# ── scan ssh ───────────────────────────────────────────────────────────────

@scan.command("ssh")
@click.argument("hosts", nargs=-1, required=True)
@click.option("--port", default=22, show_default=True, help="SSH port")
@click.option("--timeout", default=10, show_default=True, help="Connection timeout (seconds)")
@click.pass_context
def scan_ssh_cmd(ctx, hosts, port, timeout):
    """Scan SSH servers for post-quantum key exchange + host-key posture."""
    no_colour = ctx.obj.get("no_colour", False)
    from seqr._scanner import scan_ssh
    from seqr.output.terminal import make_console, _print_upsell_footer
    console = make_console(no_colour)

    for host in hosts:
        r = scan_ssh(host, port=port, timeout=timeout)
        console.print()
        if not r.reachable:
            console.print(f"  [red]✗[/red] {host}:{port} — {r.error_message or 'unreachable'}")
            continue
        console.print(f"  [bold]{host}:{port}[/bold]  [dim]{r.server_banner}[/dim]")
        pqc = "[green]YES[/green]" if r.pqc_kex_supported else "[red]NO[/red]"
        methods = f"  ([green]{', '.join(r.pqc_kex_methods)}[/green])" if r.pqc_kex_methods else ""
        console.print(f"  PQC key exchange: {pqc}{methods}")
        hk_color = "red" if r.host_key_quantum_status == "vulnerable" else "yellow"
        console.print(
            f"  Host keys:        [{hk_color}]{', '.join(r.host_key_algorithms[:4])}[/{hk_color}]"
            f"  (quantum: {r.host_key_quantum_status})"
        )
        if not r.pqc_kex_supported:
            console.print(
                "  [dim]→ Enable a PQC KEX (OpenSSH 9.x: "
                "mlkem768x25519-sha256 / sntrup761x25519-sha512)[/dim]"
            )
    _print_upsell_footer(console)


# ── scan mail ──────────────────────────────────────────────────────────────

@scan.command("mail")
@click.argument("hosts", nargs=-1, required=True)
@click.option("--protocol", type=click.Choice(["smtp", "imap", "pop3"]), default="smtp",
              show_default=True, help="Mail protocol (STARTTLS)")
@click.option("--port", default=None, type=int, help="Override default port (smtp 587, imap 143, pop3 110)")
@click.option("--timeout", default=15, show_default=True, help="Connection timeout (seconds)")
@click.pass_context
def scan_mail_cmd(ctx, hosts, protocol, port, timeout):
    """Scan mail servers (SMTP/IMAP/POP3 STARTTLS) for TLS + quantum posture."""
    no_colour = ctx.obj.get("no_colour", False)
    quiet = ctx.obj.get("quiet", False)
    from seqr._scanner import NetworkScanner
    from seqr.output.terminal import make_console, print_domain_results
    scanner = NetworkScanner(timeout=timeout)

    results = [scanner.scan_domain(h, port=(port or 443), protocol=protocol) for h in hosts]
    console = make_console(no_colour)
    print_domain_results(console, results, quiet=quiet)


# ── scan all ───────────────────────────────────────────────────────────────

@scan.command("all")
@click.option("--domain", "domains", multiple=True, metavar="DOMAIN", help="Domain(s) to include")
@click.option("--path", "code_path", default=".", show_default=True, type=click.Path(exists=True, file_okay=False))
@click.option("--cert-path", default=None, metavar="PATH", help="Certificate directory")
@_output_opt(click.Choice(["terminal", "json"]))
@_save_opt()
@click.pass_context
def scan_all(ctx, domains, code_path, cert_path, output, save):
    """Run all scanners: code + certs + optional domains."""
    ctx.invoke(scan_code, path=code_path, language=None, exclude=(), include=None,
               severity="low", fail_on=None, output=output, save=None)
    if domains:
        ctx.invoke(scan_domain, domains=domains, port=443, timeout=10, output=output, save=None)
    if cert_path:
        ctx.invoke(scan_certs, path=cert_path, recursive=True, types="pem,crt,cer,key,pub")


# ---------------------------------------------------------------------------
# config group
# ---------------------------------------------------------------------------

@main.group()
def config():
    """Manage configuration."""


@config.command("init")
def config_init():
    """Create ~/.seqr/config.toml with defaults."""
    from seqr import config as cfg_mod
    p = cfg_mod.init_config()
    click.echo(f"Config initialised at {p}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a config value (e.g. auth.api_key YOUR_KEY)."""
    from seqr import config as cfg_mod
    try:
        cfg_mod.set_value(key, value)
        click.echo(f"Set {key} = {value}")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@config.command("show")
def config_show():
    """Show current config."""
    from seqr import config as cfg_mod
    click.echo(cfg_mod.show())


@config.command("patterns")
def config_patterns():
    """Show pattern library version."""
    from seqr._scanner import CodeScanner
    scanner = CodeScanner()
    versions = scanner.get_pattern_versions()
    for lang, ver in versions.items():
        click.echo(f"  {lang}: v{ver}")


# ---------------------------------------------------------------------------
# verify-attestation — fully offline, self-contained (air-gap auditor tool)
# ---------------------------------------------------------------------------

# Must match the backend signer exactly (app/spine/attest.py CANON_FIELDS). The signature
# covers these fields, serialized sorted + compact, so signer and verifier hash identical bytes.
_ATT_CANON_FIELDS = [
    "org_id", "policy_id", "policy_version", "policy_content_hash",
    "evaluation_id", "evaluation_result_hash", "covered_asset_set",
    "scanner_version", "migration_engine_version", "graph_schema_version",
    "key_id", "created_at",
]


def _att_canonical_payload(d: dict) -> bytes:
    return json.dumps(
        {k: d[k] for k in _ATT_CANON_FIELDS}, sort_keys=True, separators=(",", ":")
    ).encode()


def _att_key_id(public_raw: bytes) -> str:
    import hashlib
    return "att_" + hashlib.sha256(public_raw).hexdigest()[:16]


def _verify_attestation_artifact(artifact: dict) -> bool:
    """Offline verify: recompute canonical bytes, check Ed25519 sig against the embedded
    public key, and confirm key_id is consistent with that key. No db, no network."""
    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        public_raw = base64.b64decode(artifact["public_key"])
        if artifact.get("key_id") != _att_key_id(public_raw):
            return False
        signature = base64.b64decode(artifact["signature"])
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, _att_canonical_payload(artifact)
        )
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


@main.command("verify-attestation")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@_output_opt(click.Choice(["terminal", "json"]))
@click.pass_context
def verify_attestation(ctx, path, output):
    """Verify a signed SeQr attestation certificate — fully offline.

    Recomputes the signature over the certificate's own fields against its embedded public
    key. No network call, no SeQr account: works air-gapped. Exit 0 if VALID, 1 if INVALID.

    Trust: match the certificate's key_id to SeQr's PUBLISHED attestation public key
    out-of-band — this command proves the certificate is internally authentic and untampered.
    """
    with open(path) as fh:
        artifact = json.load(fh)
    ok = _verify_attestation_artifact(artifact)

    if output == "json":
        click.echo(json.dumps({
            "valid": ok,
            "key_id": artifact.get("key_id"),
            "org_id": artifact.get("org_id"),
            "policy_version": artifact.get("policy_version"),
            "created_at": artifact.get("created_at"),
        }, indent=2))
        ctx.exit(0 if ok else 1)

    no_colour = ctx.obj.get("no_colour", False) if ctx.obj else False

    def _c(text, colour):
        return text if no_colour else click.style(text, fg=colour)

    covered = artifact.get("covered_asset_set") or []
    click.echo(f"  policy version : {artifact.get('policy_version', '?')}")
    click.echo(f"  evaluated at   : {artifact.get('created_at', '?')}")
    click.echo(f"  covered assets : {len(covered)}")
    click.echo(f"  signing key    : {artifact.get('key_id', '?')}")
    click.echo(f"  scanner        : {artifact.get('scanner_version') or 'n/a'}")
    click.echo("")
    if ok:
        click.echo("  " + _c("VALID", "green") + " — signature authentic, certificate untampered.")
        click.echo("  Confirm the signing key matches SeQr's published attestation key.")
    else:
        click.echo("  " + _c("INVALID", "red") + " — signature does not verify. Do not trust this certificate.")
    ctx.exit(0 if ok else 1)


# ---------------------------------------------------------------------------
# ci — diff-aware PQC gate for pull requests (the CI / regression-guard arm)
# ---------------------------------------------------------------------------

_CI_LANG_EXTS = {
    "python": (".py", ".pyw"),
    "javascript": (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"),
    "java": (".java",),
    "go": (".go",),
}


def _safe_echo(text: str) -> None:
    """Echo text that may contain emoji without crashing on a legacy console codepage.

    The Markdown report uses emoji (🔐, 🔴 …); a Windows cp1252 stdout would otherwise
    raise UnicodeEncodeError. Falls back to replacing un-encodable characters.
    """
    try:
        click.echo(text)
    except UnicodeEncodeError:
        enc = (getattr(sys.stdout, "encoding", None) or "utf-8")
        click.echo(text.encode(enc, errors="replace").decode(enc))


@main.command("ci")
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--base", default=None,
              help="Base git ref to diff against (default: auto — origin/main, main, "
                   "then HEAD~1). Ignored with --diff or --all.")
@click.option("--diff", "diff_file", default=None, type=click.Path(exists=True),
              help="Read a unified diff from this file instead of invoking git.")
@click.option("--all", "scan_all", is_flag=True, default=False,
              help="Gate on every finding, not just PR-added lines.")
@click.option("--language", default=None,
              help="Only scan this language (python|javascript|java|go|all)")
@click.option("--exclude", multiple=True, metavar="GLOB",
              help="Directory to exclude (repeatable)")
@_fail_on_opt()
@_policy_opt()
@click.option("--policy-file", "policy_file", default=None, metavar="PATH",
              help="Declarative crypto policy (spine {\"rules\":[...]} shape). "
                   "Default: auto-discover seqr-policy.json, else the built-in baseline.")
@click.option("--fail-on-drift/--no-fail-on-drift", "fail_on_drift", default=None,
              help="Fail the build on NEW findings that drift from the crypto policy.")
@click.option("--baseline", "baseline_file", default=None, metavar="PATH",
              help="Baseline of accepted findings (default: auto-discover "
                   "seqr-baseline.json). Only findings absent from it can fail the gate.")
@click.option("--no-baseline", "no_baseline", is_flag=True, default=False,
              help="Ignore any baseline file; treat every finding as new.")
@click.option("--update-baseline", "update_baseline", is_flag=True, default=False,
              help="Rewrite the baseline to accept all current findings, then exit 0.")
@click.option("--config", "config_file", default=None, metavar="PATH",
              help="seqr-ci.yml defaults (default: auto-discover).")
@click.option("--snapshot", "snapshot", is_flag=True, default=False,
              help="Scheduled (non-PR) mode: scan the WHOLE tree against policy, record a "
                   "dated snapshot, and report drift trend (new vs resolved) since the "
                   "previous snapshot. Ignores --base/--diff and PR-added-line narrowing.")
@click.option("--snapshot-dir", "snapshot_dir", default=None, metavar="PATH",
              help="Directory for dated trend snapshots (default: .seqr/snapshots).")
@click.option("--fail-budget", "fail_budget", type=int, default=None, metavar="N",
              help="With --snapshot: fail the build if MORE than N new drift findings "
                   "appeared since the prior snapshot (default: advisory, exit 0).")
@click.option("--output", default="markdown",
              type=click.Choice(["markdown", "json", "sarif"]), show_default=True)
@click.option("--comment-file", "comment_file", default=None, metavar="PATH",
              help="Also write the Markdown report to this file (for a bot to post).")
@click.option("--sarif-file", "sarif_file", default=None, metavar="PATH",
              help="Also write SARIF 2.1.0 to this file (for GitHub code-scanning upload).")
@click.pass_context
def ci(ctx, path, base, diff_file, scan_all, language, exclude, fail_on, policy,
       policy_file, fail_on_drift, baseline_file, no_baseline, update_baseline,
       config_file, snapshot, snapshot_dir, fail_budget, output, comment_file, sarif_file):
    """Scan the crypto a change introduces and gate the build against policy.

    Designed for pull-request CI: it flags quantum-vulnerable patterns on the lines a
    change ADDS (pre-existing issues never fail an unrelated build), subtracts accepted
    findings (baseline + inline ``# seqr:ignore`` + ``.seqrignore``), evaluates the rest
    against the org crypto policy, renders a PR-style review, and exits non-zero only when
    a gate is armed (``--fail-on`` / ``--policy`` on severity, ``--fail-on-drift`` on NEW
    policy drift). Exit 0 by default — it never breaks a build on its own.
    """
    from seqr._scanner import CodeScanner
    from seqr.ci import (
        CIConfigError, GitDiffError, apply_inline_suppressions, apply_path_ignores,
        auto_base, build_markdown, decide, evaluate_findings, filter_new,
        filter_to_added, find_baseline_file, git_diff, load_baseline, load_config,
        load_policy, load_seqrignore, parse_unified_diff, save_baseline,
    )
    from seqr.ci import (
        DEFAULT_SNAPSHOT_DIR, budget_decision, build_snapshot, build_trend_json,
        build_trend_markdown, diff_snapshots, git_commit, load_snapshots,
        prior_snapshot, save_snapshot,
    )

    quiet = ctx.obj.get("quiet", False) if ctx.obj else False
    root = os.path.abspath(path)

    # -- config: CLI flag > seqr-ci.yml > built-in default --------------------
    try:
        cfg = load_config(config_file, root=root)
    except CIConfigError as exc:
        raise click.ClickException(str(exc))
    if fail_on is None:
        fail_on = cfg.get("fail_on")
    if policy is None:
        policy = cfg.get("policy")
    if policy_file is None:
        policy_file = cfg.get("policy_file")
    if baseline_file is None:
        baseline_file = cfg.get("baseline")
    if fail_on_drift is None:
        fail_on_drift = bool(cfg.get("fail_on_drift", False))
    if language is None:
        language = cfg.get("language")
    if not exclude and cfg.get("exclude"):
        exclude = tuple(cfg["exclude"])

    # -- scan -----------------------------------------------------------------
    scanner = CodeScanner()
    exclude_dirs = {p.rstrip("/") for p in exclude} or None
    all_findings = scanner.scan_directory(path, exclude_dirs=exclude_dirs)

    if language and language != "all":
        exts = _CI_LANG_EXTS.get(language, ())
        all_findings = [f for f in all_findings if Path(f.file_path).suffix.lower() in exts]

    # -- suppressions (apply before diff/baseline so they silence everywhere) --
    ignore_patterns = load_seqrignore(root)
    all_findings, _path_ignored = apply_path_ignores(all_findings, ignore_patterns, root=root)
    all_findings, suppressed = apply_inline_suppressions(all_findings)

    # -- update-baseline: accept the full current tree, then exit 0 -----------
    if update_baseline:
        target = baseline_file or (find_baseline_file(root) or (Path(root) / "seqr-baseline.json"))
        count = save_baseline(target, all_findings, root=root)
        if not quiet:
            click.echo(f"Wrote baseline with {count} accepted finding(s) → {target}")
        ctx.exit(0)

    # -- scheduled trend mode: whole-tree drift over time + fail-budget -------
    if snapshot:
        crypto_policy = load_policy(policy_file, root=root)
        snap_dir = snapshot_dir or (Path(root) / DEFAULT_SNAPSHOT_DIR)
        current = build_snapshot(
            all_findings, crypto_policy, root=root, commit=git_commit(root)
        )
        # Compare against prior snapshots BEFORE writing today's, so a same-day re-run
        # still diffs against the previous day rather than itself.
        history = load_snapshots(snap_dir)
        prior = prior_snapshot(history, current)
        save_snapshot(snap_dir, current)

        tdiff = diff_snapshots(prior, current)
        decision = budget_decision(len(tdiff.new), fail_budget)

        if output == "json":
            rendered = json.dumps(
                build_trend_json(current, prior, tdiff, decision), indent=2
            )
        else:  # markdown (sarif is not meaningful for a trend summary)
            rendered = build_trend_markdown(current, prior, tdiff, decision)

        if comment_file:
            Path(comment_file).write_text(
                build_trend_markdown(current, prior, tdiff, decision), encoding="utf-8"
            )
        _safe_echo(rendered)
        ctx.exit(1 if decision.should_fail else 0)

    # -- diff-narrowing to PR-added lines -------------------------------------
    resolved_base = None
    advisory_note = None
    if scan_all:
        findings = all_findings
    else:
        try:
            if diff_file:
                diff_text = Path(diff_file).read_text(encoding="utf-8")
            else:
                resolved_base = base or auto_base()
                diff_text = git_diff(resolved_base)
            added = parse_unified_diff(diff_text)
            findings = filter_to_added(all_findings, added, root=root)
        except GitDiffError as exc:
            # Cannot determine the diff → never break the build on a guess. Report all
            # findings as advisory and force exit 0.
            advisory_note = str(exc)
            findings = all_findings
            fail_on = policy = None
            fail_on_drift = False

    # -- baseline: keep only findings not already accepted --------------------
    baselined_count = 0
    if not no_baseline:
        bl_path = baseline_file or find_baseline_file(root)
        if bl_path is not None:
            baseline = load_baseline(bl_path)
            findings, baselined = filter_new(findings, baseline, root=root)
            baselined_count = len(baselined)

    # -- policy evaluation → drift on the surviving (new) findings ------------
    crypto_policy = load_policy(policy_file, root=root)
    drift_map = evaluate_findings(crypto_policy, findings)
    drift_ids = set(drift_map)
    drift_findings = [f for f in findings if id(f) in drift_ids]

    decision = decide(
        findings, fail_on, policy, drift=drift_findings, fail_on_drift=bool(fail_on_drift)
    )

    def _markdown() -> str:
        return build_markdown(
            findings, base=resolved_base, gate=decision,
            suppressed=len(suppressed), baselined=baselined_count, drift_ids=drift_ids,
        )

    if output == "json":
        from seqr.output.json_export import build_code_report
        report = build_code_report(findings, len(findings), path)
        report["gate"] = {
            "should_fail": decision.should_fail,
            "reason": decision.reason,
            "base": resolved_base,
            "advisory": advisory_note,
            "policy": crypto_policy.name,
            "drift_count": len(drift_findings),
            "baselined_count": baselined_count,
            "suppressed_count": len(suppressed),
        }
        rendered = json.dumps(report, indent=2)
    elif output == "sarif":
        from seqr.output.sarif import build_sarif
        rendered = json.dumps(build_sarif(findings, root=root), indent=2)
    else:  # markdown
        rendered = _markdown()

    if comment_file:
        Path(comment_file).write_text(_markdown(), encoding="utf-8")

    if sarif_file:
        from seqr.output.sarif import build_sarif
        Path(sarif_file).write_text(
            json.dumps(build_sarif(findings, root=root), indent=2), encoding="utf-8"
        )

    if not quiet or output != "markdown":
        _safe_echo(rendered)

    if advisory_note and not quiet:
        click.echo(f"::warning:: PQC gate ran in advisory mode: {advisory_note}", err=True)

    ctx.exit(1 if decision.should_fail else 0)
