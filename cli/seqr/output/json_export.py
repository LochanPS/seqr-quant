"""
JSON output for SeQr CLI.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from seqr._severity import severity_for_risk

__all__ = ["build_code_report", "build_domain_report"]


def _has_forward_secrecy(kex: str, hybrid_status: str) -> bool:
    k = (kex or "").upper().replace("-", "").replace("_", "")
    return "X25519" in k or "ECDHE" in k or hybrid_status in ("hybrid", "full_pqc")


def _pqc_offered(hybrid_status: str) -> bool:
    return hybrid_status in ("hybrid", "full_pqc")


def build_code_report(
    findings: list,
    files_scanned: int,
    target: str,
    pattern_library_version: str = "1.4.0",
) -> dict[str, Any]:
    from seqr import __version__

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    effort_min_total = 0

    serialized = []
    for f in findings:
        sev = severity_for_risk(f.algorithm_risk)
        counts[sev] += 1
        effort_min_total += f.estimated_effort_hours

        serialized.append({
            "id": f.pattern_id,
            "file": f.file_path,
            "line": f.line_number,
            "snippet": f.code_snippet,
            "algorithm": f.algorithm,
            "algorithm_family": f.algorithm_family,
            "quantum_status": f.quantum_status,
            "severity": sev,
            "confidence": f.confidence,
            "recommended_replacement": f.recommended_replacement,
            "estimated_effort_hours": {
                "min": f.estimated_effort_hours,
                "max": int(f.estimated_effort_hours * 1.5),
            },
        })

    return {
        "seqr_version": __version__,
        "scan_timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_type": "code",
        "target": target,
        "pattern_library_version": pattern_library_version,
        "summary": {
            "files_scanned": files_scanned,
            "components_found": len(findings),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "quantum_safe_count": max(0, files_scanned - len(set(f.file_path for f in findings))),
            "estimated_effort_hours": {
                "min": effort_min_total,
                "max": int(effort_min_total * 1.5),
            },
        },
        "findings": serialized,
        "upsell": "Full compliance report + CBOM export: seqrlabs.com",
    }


def build_domain_report(results: list) -> dict[str, Any]:
    from seqr import __version__

    serialized = []
    for r in results:
        entry: dict[str, Any] = {
            "domain": r.domain,
            "reachable": r.reachable,
        }
        if not r.reachable:
            entry["error"] = r.error_message
        else:
            hybrid_status = getattr(r, "hybrid_status", "none")
            entry["tls_version"] = r.tls_version
            entry["cert_algorithm"] = r.cert.algorithm if r.cert else None
            entry["key_exchange"] = r.key_exchange_algorithm
            entry["forward_secrecy"] = _has_forward_secrecy(r.key_exchange_algorithm, hybrid_status)
            entry["cdn_detected"] = bool(getattr(r, "cdn_detected", False))
            entry["cdn_provider"] = getattr(r, "cdn_provider", "") or ""
            entry["pqc_offered"] = _pqc_offered(hybrid_status)
            entry["scan_confidence"] = getattr(r, "scan_confidence", "high")
        serialized.append(entry)

    return {
        "seqr_version": __version__,
        "scan_timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_type": "domain",
        "results": serialized,
        "upsell": "Full compliance report + CBOM export: seqrlabs.com",
    }
