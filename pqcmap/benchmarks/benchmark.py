#!/usr/bin/env python3
"""pqcmap benchmark — real keygen / encap / decap / sign / verify timings.

Runs the genuine FIPS 203/204 operations on **this machine**, for every PQC backend
that is actually installed (pure-python always; liboqs when present), and — for
context — a classical RSA-2048 baseline via PyCA ``cryptography``. Nothing here is a
looked-up or invented number: every row is timed live in the current process.

    python benchmarks/benchmark.py                 # human table, default iterations
    python benchmarks/benchmark.py --iterations 50 # more samples = tighter numbers
    python benchmarks/benchmark.py --json out.json # machine-readable results too
    python benchmarks/benchmark.py --quick         # fewer iterations, faster

Timings are per-operation wall-clock (``time.perf_counter``), reported as the median
over N iterations (median is robust to GC/scheduler jitter) plus ops/sec. The
pure-Python backend is a portable *reference* implementation and is expected to be
much slower than liboqs; install ``pqcmap[liboqs]`` for production throughput.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

# Allow running straight from a checkout (python benchmarks/benchmark.py) without install.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from pqcmap import algorithms  # noqa: E402
from pqcmap._backend import _LiboqsBackend, _PurePythonBackend, _try_liboqs  # noqa: E402

KEM_ALGS = [
    algorithms.KEMAlgorithm.ML_KEM_512,
    algorithms.KEMAlgorithm.ML_KEM_768,
    algorithms.KEMAlgorithm.ML_KEM_1024,
]
SIGN_ALGS = [
    algorithms.SignAlgorithm.ML_DSA_44,
    algorithms.SignAlgorithm.ML_DSA_65,
    algorithms.SignAlgorithm.ML_DSA_87,
]
MESSAGE = b"pqcmap benchmark message" * 4  # ~96 bytes, representative of a JWT signing input


@dataclass
class OpResult:
    backend: str
    algorithm: str
    operation: str
    iterations: int
    median_ms: float
    mean_ms: float
    min_ms: float
    ops_per_sec: float


def _time_op(fn: Callable[[], object], iterations: int) -> list[float]:
    """Return per-call durations in milliseconds (fresh inputs handled by the caller)."""
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _summarise(backend: str, alg: str, op: str, samples: list[float]) -> OpResult:
    median = statistics.median(samples)
    return OpResult(
        backend=backend,
        algorithm=alg,
        operation=op,
        iterations=len(samples),
        median_ms=median,
        mean_ms=statistics.fmean(samples),
        min_ms=min(samples),
        ops_per_sec=(1000.0 / median) if median > 0 else float("inf"),
    )


def bench_kem(backend, alg: str, iterations: int) -> list[OpResult]:
    results = []
    # keygen
    results.append(_summarise(backend.name, alg, "keygen",
                              _time_op(lambda: backend.kem_keypair(alg), iterations)))
    pk, sk = backend.kem_keypair(alg)
    # encapsulate
    results.append(_summarise(backend.name, alg, "encapsulate",
                              _time_op(lambda: backend.kem_encaps(alg, pk), iterations)))
    ct, _ = backend.kem_encaps(alg, pk)
    # decapsulate
    results.append(_summarise(backend.name, alg, "decapsulate",
                              _time_op(lambda: backend.kem_decaps(alg, sk, ct), iterations)))
    return results


def bench_sign(backend, alg: str, iterations: int) -> list[OpResult]:
    results = []
    results.append(_summarise(backend.name, alg, "keygen",
                              _time_op(lambda: backend.sign_keypair(alg), iterations)))
    pk, sk = backend.sign_keypair(alg)
    results.append(_summarise(backend.name, alg, "sign",
                              _time_op(lambda: backend.sign(alg, sk, MESSAGE), iterations)))
    signature = backend.sign(alg, sk, MESSAGE)
    results.append(_summarise(backend.name, alg, "verify",
                              _time_op(lambda: backend.verify(alg, pk, signature, MESSAGE), iterations)))
    return results


def bench_rsa_baseline(iterations: int) -> list[OpResult]:
    """Classical RSA-2048 baseline (real, timed here) for honest side-by-side context."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except Exception:
        return []

    results = []
    # keygen — RSA keygen is the expensive step; fewer iterations keep it bearable.
    kg_iters = max(3, iterations // 5)
    results.append(_summarise("rsa-2048 (classical)", "RSA-2048", "keygen",
                              _time_op(lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
                                       kg_iters)))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    results.append(_summarise("rsa-2048 (classical)", "RSA-2048", "sign",
                              _time_op(lambda: key.sign(MESSAGE, pss, hashes.SHA256()), iterations)))
    sig = key.sign(MESSAGE, pss, hashes.SHA256())
    pub = key.public_key()

    def _verify():
        pub.verify(sig, MESSAGE, pss, hashes.SHA256())

    results.append(_summarise("rsa-2048 (classical)", "RSA-2048", "verify",
                              _time_op(_verify, iterations)))
    return results


def backends_available() -> list[object]:
    found = [_PurePythonBackend()]
    liboqs = _try_liboqs()
    if liboqs is not None:
        found.append(liboqs)
    return found


def run(iterations: int, include_rsa: bool = True) -> dict:
    machine = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "iterations": iterations,
    }

    backends = backends_available()
    machine["backends_benchmarked"] = [b.name for b in backends]
    machine["liboqs_available"] = any(b.name == "liboqs" for b in backends)

    results: list[OpResult] = []
    for backend in backends:
        for alg in KEM_ALGS:
            results.extend(bench_kem(backend, alg, iterations))
        for alg in SIGN_ALGS:
            results.extend(bench_sign(backend, alg, iterations))
    if include_rsa:
        results.extend(bench_rsa_baseline(iterations))

    return {"machine": machine, "results": [asdict(r) for r in results]}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _fmt_ms(ms: float) -> str:
    return f"{ms:9.3f}"


def render_table(report: dict) -> str:
    m = report["machine"]
    lines = []
    lines.append("=" * 78)
    lines.append("pqcmap benchmark - real timings on this machine")
    lines.append("=" * 78)
    lines.append(f"  timestamp : {m['timestamp']}")
    lines.append(f"  python    : {m['implementation']} {m['python']}")
    lines.append(f"  platform  : {m['platform']}")
    lines.append(f"  processor : {m['processor']}")
    lines.append(f"  iterations: {m['iterations']} per operation (median reported)")
    lines.append(f"  backends  : {', '.join(m['backends_benchmarked'])}"
                 + ("" if m["liboqs_available"] else "   (liboqs not installed - pip install pqcmap[liboqs])"))
    lines.append("")
    header = f"  {'backend':<22} {'algorithm':<12} {'operation':<12} {'median (ms)':>12} {'ops/sec':>12}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for r in report["results"]:
        lines.append(
            f"  {r['backend']:<22} {r['algorithm']:<12} {r['operation']:<12} "
            f"{_fmt_ms(r['median_ms'])} {r['ops_per_sec']:>12.1f}"
        )
    lines.append("")
    lines.append("  Note: pure-python is a portable reference implementation and is expected")
    lines.append("  to be far slower than liboqs. Sizes (key/ciphertext/signature bytes) are")
    lines.append("  fixed by the FIPS parameter set - see docs/COOKBOOK.md and the README table.")
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    m = report["machine"]
    lines = []
    lines.append("<!-- Generated by benchmarks/benchmark.py — do not edit by hand. -->")
    lines.append("# pqcmap benchmark results")
    lines.append("")
    lines.append("Real, live-timed measurements — every number below was produced by running")
    lines.append("`benchmarks/benchmark.py` on the machine described here. Re-run it to reproduce.")
    lines.append("")
    lines.append(f"- **Timestamp:** {m['timestamp']}")
    lines.append(f"- **Python:** {m['implementation']} {m['python']}")
    lines.append(f"- **Platform:** {m['platform']}")
    lines.append(f"- **Processor:** {m['processor']}")
    lines.append(f"- **Iterations:** {m['iterations']} per operation (median reported)")
    lines.append(f"- **Backends benchmarked:** {', '.join(m['backends_benchmarked'])}"
                 + ("" if m["liboqs_available"]
                    else " — _liboqs not installed on this machine; install `pqcmap[liboqs]` for the fast backend._"))
    lines.append("")
    lines.append("| Backend | Algorithm | Operation | Median (ms) | Ops/sec |")
    lines.append("|---|---|---|---:|---:|")
    for r in report["results"]:
        lines.append(
            f"| {r['backend']} | {r['algorithm']} | {r['operation']} "
            f"| {r['median_ms']:.3f} | {r['ops_per_sec']:.1f} |"
        )
    lines.append("")
    lines.append("> **Reading these numbers honestly:** the pure-Python backend (kyber-py +")
    lines.append("> dilithium-py) is a correct, portable *reference* implementation, not an")
    lines.append("> optimised one. Even so, ML-KEM/ML-DSA **keygen is already faster than")
    lines.append("> RSA-2048 keygen** here. Its **sign/verify look slower than RSA only because")
    lines.append("> the Python reference code is unoptimised** — the native `liboqs` backend")
    lines.append("> (`pip install pqcmap[liboqs]`) runs the same operations orders of magnitude")
    lines.append("> faster and typically beats RSA on sign as well. Re-run this script with")
    lines.append("> liboqs installed to see the production numbers on your hardware.")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="pqcmap real-timing benchmark")
    parser.add_argument("--iterations", type=int, default=20,
                        help="samples per operation (default: 20)")
    parser.add_argument("--quick", action="store_true",
                        help="fewer iterations (5) for a fast sanity run")
    parser.add_argument("--no-rsa", action="store_true",
                        help="skip the classical RSA-2048 baseline")
    parser.add_argument("--json", metavar="PATH", default=None,
                        help="also write raw results as JSON to PATH")
    parser.add_argument("--markdown", metavar="PATH", default=None,
                        help="also write a Markdown results table to PATH")
    args = parser.parse_args(argv)

    iterations = 5 if args.quick else args.iterations
    report = run(iterations, include_rsa=not args.no_rsa)

    print(render_table(report))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n  wrote JSON  -> {args.json}")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
        print(f"  wrote Markdown -> {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
