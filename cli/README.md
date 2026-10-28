# seqr

PQC readiness scanner for Indian financial infrastructure.

`seqr` scans your code and live domains for quantum-vulnerable cryptography (RSA, ECDSA, DH)
and reports TLS configuration, certificate algorithm, key exchange, forward secrecy, CDN
detection, and PQC offering status — entirely from the command line, no account required.

## Install

```bash
pip install seqr
```

## Usage

```bash
seqr scan domain example.com
seqr scan code ./src
seqr scan certs ./certs
seqr scan all --domain example.com --path .
```

Add `--output json` or `--output sarif` (code scans) for machine-readable output, or
`--fail-on`/`--policy` for CI/CD gating.

For crypto agility scoring, HNDL risk assessment, migration priority, regulatory
compliance mapping (RBI / CERT-In / DST Task Force / DPDP), CBOM export, and PDF
reports, see [seqrlabs.com](https://seqrlabs.com).

## License

MIT
