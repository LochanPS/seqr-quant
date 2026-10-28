# Worked example: find it with `seqr`, fix it with `pqcmap`, prove it clean

This is the full loop the SeQr lifecycle promises — **the scanner finds quantum-vulnerable
crypto, pqcmap fixes it, and a re-scan confirms it's gone** — on a small but real auth service.
Nothing is mocked: the SeQr scanner runs for real and the migrated code performs genuine
ML-DSA-65 signing.

## Files

| File | What |
|---|---|
| [`before/auth_service.py`](before/auth_service.py) | The original service: RSA-2048 key + **RS256** JWTs. Quantum-vulnerable. |
| [`after/auth_service.py`](after/auth_service.py) | The same service migrated to **ML-DSA-65** JWTs via `pqcmap.jwt` + `LocalKeyStore`. |
| [`run_migration.py`](run_migration.py) | The driver: scans BEFORE, proves AFTER works, re-scans AFTER clean. |

## Run it

```bash
pip install seqr pqcmap
python examples/worked_migration/run_migration.py
```

## What it does, and the real output

1. Runs `seqr scan code before/` and prints every finding.
2. Shows the exact 3-line migration (recipes 1 + 7 in [`../../docs/COOKBOOK.md`](../../docs/COOKBOOK.md)).
3. Imports the migrated service and actually issues + verifies a token.
4. Re-scans `after/` and confirms **0 findings** — and that `--fail-on high` flips from
   failing the build to passing it.

```text
==========================================================================
SeQr + pqcmap - find it, fix it, prove it clean
==========================================================================

[1/4] Scan the ORIGINAL service with `seqr scan code`:
      $ seqr scan code examples\worked_migration\before

      5 quantum-vulnerable component(s) found:
    - [HIGH    ] PY-RSA-001     auth_service.py:14   RSA
          -> ML-DSA-65 (FIPS 204) for signatures, ML-KEM-768 (FIPS 203) for key exchange
    - [HIGH    ] PY-JWT-RS256   auth_service.py:19   RSA
          -> ML-DSA-65 via seqr-scanner SDK
    - [HIGH    ] PY-JWT-RS256   auth_service.py:23   RSA
          -> ML-DSA-65 via seqr-scanner SDK
    - [HIGH    ] PY-ECC-001     auth_service.py:14   ECC
          -> ML-DSA-65 (FIPS 204)
    - [HIGH    ] PY-DH-001      auth_service.py:14   DH
          -> ML-KEM-768 (FIPS 203)

      `--fail-on high` would FAIL the build (exit != 0).

[2/4] Apply the pqcmap migration (docs/COOKBOOK.md recipes 1 + 7):
      import jwt                    ->  import pqcmap.jwt as jwt
      rsa.generate_private_key(...) ->  LocalKeyStore.generate_and_store('ML-DSA-65')
      algorithm='RS256'            ->  algorithm='ML-DSA-65'

[3/4] Prove the MIGRATED service still works:
    issued + verified an ML-DSA-65 token; claims = {'role': 'admin', 'sub': 'user-123'}

[4/4] Re-scan the MIGRATED service:
      $ seqr scan code examples\worked_migration\after

      0 quantum-vulnerable component(s) found.
      `--fail-on high` now passes the build (exit 0).

==========================================================================
RESULT: 5 findings -> 0. Migration verified end-to-end.
==========================================================================
```

> The `before/` file trips several patterns on one line (`rsa.generate_private_key` reads as
> RSA **and** the generic key-generation patterns for ECC/DH), which is why one line yields
> multiple findings — the scanner is deliberately eager here. After migration, every one is
> resolved.

The loop is guarded in CI by [`../../tests/test_worked_migration.py`](../../tests/test_worked_migration.py),
so this example can't silently rot.
