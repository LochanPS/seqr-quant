#!/usr/bin/env python3
"""End-to-end worked example: find with `seqr`, fix with `pqcmap`, re-scan clean.

Runs the real SeQr scanner over a small vulnerable auth service, shows the findings,
then runs the pqcmap-migrated version and shows the scan comes back clean — and that
the migrated code still issues and verifies a token. No mocks: the scanner and the
crypto both run for real.

    python examples/worked_migration/run_migration.py

Requires the SeQr CLI (`pip install seqr`). If `seqr` isn't on PATH, the script falls
back to the CLI package in a sibling `cli/` directory (monorepo layout).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEFORE = HERE / "before"
AFTER = HERE / "after"
PQCMAP_ROOT = HERE.parent.parent  # the pqcmap package root


def _seqr_command() -> list[str]:
    """Locate the SeQr CLI: prefer the installed `seqr`, else the monorepo cli/ package."""
    exe = shutil.which("seqr")
    if exe:
        return [exe]
    cli_dir = PQCMAP_ROOT.parent / "cli"
    if (cli_dir / "seqr" / "cli.py").exists():
        env_path = os.environ.get("PYTHONPATH", "")
        os.environ["PYTHONPATH"] = os.pathsep.join([str(cli_dir), env_path]) if env_path else str(cli_dir)
        return [sys.executable, "-c", "from seqr.cli import main; main()"]
    raise SystemExit(
        "SeQr CLI not found. Install it with `pip install seqr`, then re-run this example."
    )


SEQR = _seqr_command()


def scan(path: Path) -> dict:
    """Run `seqr scan code <path> --output json` and return the parsed report."""
    proc = subprocess.run(
        [*SEQR, "scan", "code", str(path), "--output", "json"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise SystemExit(f"seqr scan failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def scan_fails_the_build(path: Path) -> bool:
    """Would `seqr scan code --fail-on high` break a CI build here? (exit != 0)."""
    proc = subprocess.run(
        [*SEQR, "scan", "code", str(path), "--fail-on", "high", "--output", "json"],
        capture_output=True, text=True,
    )
    return proc.returncode != 0


def _print_findings(report: dict) -> None:
    for f in report["findings"]:
        loc = f"{Path(f['file']).name}:{f['line']}"
        print(f"    - [{f['severity'].upper():<8}] {f['id']:<14} {loc:<20} {f['algorithm_family']}")
        repl = f.get("recommended_replacement")
        if repl:
            print(f"          -> {repl}")


def prove_migrated_code_works() -> None:
    """Import the AFTER service and actually issue + verify a token."""
    sys.path.insert(0, str(AFTER))
    sys.path.insert(0, str(PQCMAP_ROOT))
    import auth_service  # noqa: E402  (the AFTER version)

    import tempfile
    store = os.path.join(tempfile.gettempdir(), "worked_migration_proof.enc")
    for p in (store, store + ".audit.log"):
        if os.path.exists(p):
            os.unlink(p)
    ks = auth_service.open_keystore(passphrase="demo", path=store)
    kid = ks.generate_and_store(auth_service.ALGORITHM, metadata={"purpose": "session-jwt"})
    token = auth_service.issue_token({"sub": "user-123", "role": "admin"}, ks.get_private_key(kid))
    claims = auth_service.verify_token(token, ks.get_public_key(kid))
    assert claims["sub"] == "user-123" and claims["role"] == "admin"
    for p in (store, store + ".audit.log"):
        if os.path.exists(p):
            os.unlink(p)
    print(f"    issued + verified an {auth_service.ALGORITHM} token; claims = {claims}")


def main() -> int:
    print("=" * 74)
    print("SeQr + pqcmap - find it, fix it, prove it clean")
    print("=" * 74)

    print("\n[1/4] Scan the ORIGINAL service with `seqr scan code`:")
    print(f"      $ seqr scan code {BEFORE.relative_to(PQCMAP_ROOT)}")
    before = scan(BEFORE)
    n_before = before["summary"]["components_found"]
    print(f"\n      {n_before} quantum-vulnerable component(s) found:")
    _print_findings(before)
    fails = scan_fails_the_build(BEFORE)
    print(f"\n      `--fail-on high` would {'FAIL' if fails else 'pass'} the build "
          f"(exit {'!= 0' if fails else '0'}).")
    if n_before == 0:
        raise SystemExit("expected findings in the BEFORE service but got none")

    print("\n[2/4] Apply the pqcmap migration (docs/COOKBOOK.md recipes 1 + 7):")
    print("      import jwt                    ->  import pqcmap.jwt as jwt")
    print("      rsa.generate_private_key(...) ->  LocalKeyStore.generate_and_store('ML-DSA-65')")
    print("      algorithm='RS256'            ->  algorithm='ML-DSA-65'")

    print("\n[3/4] Prove the MIGRATED service still works:")
    prove_migrated_code_works()

    print("\n[4/4] Re-scan the MIGRATED service:")
    print(f"      $ seqr scan code {AFTER.relative_to(PQCMAP_ROOT)}")
    after = scan(AFTER)
    n_after = after["summary"]["components_found"]
    print(f"\n      {n_after} quantum-vulnerable component(s) found.")
    after_fails = scan_fails_the_build(AFTER)
    print(f"      `--fail-on high` now {'FAILS' if after_fails else 'passes'} the build "
          f"(exit {'!= 0' if after_fails else '0'}).")
    if n_after != 0:
        raise SystemExit(f"expected a clean scan after migration but got {n_after} findings")

    print("\n" + "=" * 74)
    print(f"RESULT: {n_before} findings -> {n_after}. Migration verified end-to-end.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
