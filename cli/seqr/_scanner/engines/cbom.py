"""
CBOM (Cryptographic Bill of Materials) aggregation engine.

Converts raw scanner output (DomainScanResult, CodeFinding) into canonical
CryptoComponent records, deduplicates, and exports in multiple formats.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib.metadata import version as _pkg_version
from typing import Any, Optional

try:
    _SCANNER_VERSION = _pkg_version("seqr")
except Exception:
    _SCANNER_VERSION = "unknown"

from .classifier import AlgorithmClassification, classify_algorithm, recommended_algorithm
from .risk import (
    ComponentRiskScore,
    OrgRiskScore,
    score_component,
    score_org,
    check_compliance,
    ComplianceResult,
    DATA_SENSITIVITY_SCORES,
)


# ---------------------------------------------------------------------------
# Threat timeline constants
# ---------------------------------------------------------------------------

THREAT_TIMELINE_IMMEDIATE = "immediate"  # < 1 year: deprecated algos, active HNDL risk
THREAT_TIMELINE_URGENT = "urgent"        # 1–2 years: vulnerable, high risk score
THREAT_TIMELINE_PLANNED = "planned"      # 2–3 years: vulnerable, medium risk
THREAT_TIMELINE_ROADMAP = "roadmap"      # 3+ years: compliant now, plan for future


# ---------------------------------------------------------------------------
# Canonical component
# ---------------------------------------------------------------------------

@dataclass
class CryptoComponent:
    id: str
    location_type: str            # tls_cert | code | kms_key | ssh_key | config | jwt
    location_detail: str          # "api.company.com" | "src/auth/jwt.py:42"
    location_file: str            # file path (code scans) or empty
    location_line: Optional[int]  # line number (code scans) or None

    algorithm: str
    algorithm_family: str
    key_size: Optional[int]
    quantum_status: str
    algorithm_risk: int
    confidence: str               # high | medium | low

    data_sensitivity: str         # public | internal | confidential | highly_confidential
    data_sensitivity_score: int
    final_risk_score: float
    hndl_risk: bool

    recommended_algorithm: str
    recommended_fips: str
    estimated_effort_hours: int
    migration_priority: str

    nist_compliant: bool
    pci_compliant: bool
    dst_compliant: bool
    cnsa_compliant: bool

    library_name: str = ""
    protocol: str = ""            # TLS | SSH | JWT | PGP
    tls_version: str = ""

    # Certificate fields (TLS scans)
    cert_expiry_date: Optional[str] = None
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_serial: str = ""

    first_seen_at: str = field(default_factory=lambda: _now_iso())
    last_seen_at: str = field(default_factory=lambda: _now_iso())

    # Threat timeline (added v1.1)
    threat_timeline: str = ""  # immediate | urgent | planned | roadmap


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# CBOM summary
# ---------------------------------------------------------------------------

@dataclass
class CBOMSummary:
    total_components: int
    vulnerable_count: int
    safe_count: int
    deprecated_count: int
    hndl_critical_count: int
    by_algorithm_family: dict[str, int]
    by_quantum_status: dict[str, int]
    by_migration_priority: dict[str, int]
    org_risk_score: int
    org_risk_detail: OrgRiskScore
    compliance: dict[str, ComplianceResult]  # framework → result


# ---------------------------------------------------------------------------
# CBOMEngine
# ---------------------------------------------------------------------------

class CBOMEngine:
    """
    Aggregate scanner results into a CBOM.

    Usage:
        engine = CBOMEngine()
        components = engine.aggregate(
            network_results=[...],
            code_findings=[...],
            org_data_sensitivity="confidential",
        )
        summary = engine.summarise(components)
        json_str = engine.export_json(components)
    """

    def aggregate(
        self,
        network_results: Optional[list] = None,
        code_findings: Optional[list] = None,
        org_data_sensitivity: str = "internal",
        is_public_facing: bool = True,
    ) -> list[CryptoComponent]:
        """
        Convert raw scanner results to CryptoComponent records.

        Args:
            network_results:     list of DomainScanResult from scanner.network
            code_findings:       list of CodeFinding from scanner.code
            org_data_sensitivity: default asset sensitivity if not specified per-asset
            is_public_facing:    whether assets are publicly accessible
        """
        components: list[CryptoComponent] = []

        for result in (network_results or []):
            components.extend(
                self._from_network_result(result, org_data_sensitivity, is_public_facing)
            )

        for finding in (code_findings or []):
            components.append(
                self._from_code_finding(finding, org_data_sensitivity)
            )

        return self._deduplicate(components)

    # ------------------------------------------------------------------
    # Conversion from network scanner
    # ------------------------------------------------------------------

    def _from_network_result(
        self,
        result,
        data_sensitivity: str,
        is_public_facing: bool,
    ) -> list[CryptoComponent]:
        """Convert a DomainScanResult to 1–3 CryptoComponent records."""
        components: list[CryptoComponent] = []

        if not result.reachable:
            return components

        domain = result.domain
        port = getattr(result, "port", 443)

        # --- TLS version component ---
        if result.tls_version:
            tls_cls = next(
                (c for c in (result.classifications or []) if c.algorithm_family == "TLS"),
                None,
            )
            if tls_cls:
                components.append(
                    self._make_component(
                        location_type="tls_cert",
                        location_detail=f"{domain}:{port}",
                        algorithm=result.tls_version,
                        algorithm_family="TLS",
                        classification=tls_cls,
                        data_sensitivity=data_sensitivity,
                        is_public_facing=is_public_facing,
                        protocol="TLS",
                        tls_version=result.tls_version,
                    )
                )

        # --- Certificate algorithm component ---
        cert = result.cert
        if cert and cert.algorithm:
            key_size = cert.key_size
            cls = classify_algorithm(cert.algorithm, key_size)
            expiry = cert.expiry_date.isoformat() if cert.expiry_date else None
            components.append(
                self._make_component(
                    location_type="tls_cert",
                    location_detail=f"{domain}:{port} (cert)",
                    algorithm=f"{cert.algorithm.upper()}-{key_size}" if key_size else cert.algorithm.upper(),
                    algorithm_family=cls.algorithm_family,
                    classification=cls,
                    key_size=key_size,
                    data_sensitivity=data_sensitivity,
                    is_public_facing=is_public_facing,
                    protocol="TLS",
                    tls_version=result.tls_version or "",
                    cert_expiry_date=expiry,
                    cert_issuer=cert.issuer or "",
                    cert_subject=cert.subject or "",
                    cert_serial=str(cert.serial) if cert.serial else "",
                )
            )

        # --- Key exchange algorithm component ---
        kex = result.key_exchange_algorithm
        if kex:
            kex_cls = classify_algorithm(kex)
            if kex_cls.algorithm_family not in ("TLS",):
                components.append(
                    self._make_component(
                        location_type="tls_cert",
                        location_detail=f"{domain}:{port} (key exchange)",
                        algorithm=kex.upper(),
                        algorithm_family=kex_cls.algorithm_family,
                        classification=kex_cls,
                        data_sensitivity=data_sensitivity,
                        is_public_facing=is_public_facing,
                        protocol="TLS",
                        tls_version=result.tls_version or "",
                    )
                )

        return components

    # ------------------------------------------------------------------
    # Conversion from code scanner
    # ------------------------------------------------------------------

    def _from_code_finding(
        self,
        finding,
        data_sensitivity: str,
    ) -> CryptoComponent:
        """Convert a CodeFinding to a CryptoComponent."""
        cls = classify_algorithm(finding.algorithm)
        rec_algo, rec_fips = recommended_algorithm(finding.algorithm)

        risk = score_component(
            component_id="tmp",
            algorithm=finding.algorithm,
            algorithm_family=finding.algorithm_family,
            algorithm_risk=finding.algorithm_risk,
            quantum_status=finding.quantum_status,
            data_sensitivity=data_sensitivity,
            location_type="code",
            is_public_facing=False,
        )

        timeline = _classify_threat_timeline(
            finding.quantum_status,
            finding.algorithm_risk,
            finding.hndl_risk,
            risk.migration_priority,
        )

        return CryptoComponent(
            id=str(uuid.uuid4()),
            location_type="code",
            location_detail=f"{finding.file_path}:{finding.line_number}",
            location_file=finding.file_path,
            location_line=finding.line_number,
            algorithm=finding.algorithm,
            algorithm_family=finding.algorithm_family,
            key_size=None,
            quantum_status=finding.quantum_status,
            algorithm_risk=finding.algorithm_risk,
            confidence=finding.confidence,
            data_sensitivity=data_sensitivity,
            data_sensitivity_score=risk.data_sensitivity_score,
            final_risk_score=risk.final_risk_score,
            hndl_risk=finding.hndl_risk,
            recommended_algorithm=finding.recommended_replacement or rec_algo,
            recommended_fips=rec_fips,
            estimated_effort_hours=finding.estimated_effort_hours,
            migration_priority=risk.migration_priority,
            nist_compliant=risk.nist_compliant,
            pci_compliant=risk.pci_compliant,
            dst_compliant=risk.dst_compliant,
            cnsa_compliant=risk.cnsa_compliant,
            library_name=finding.library_name,
            protocol="",
            threat_timeline=timeline,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_component(
        self,
        *,
        location_type: str,
        location_detail: str,
        algorithm: str,
        algorithm_family: str,
        classification: AlgorithmClassification,
        key_size: Optional[int] = None,
        data_sensitivity: str = "internal",
        is_public_facing: bool = True,
        protocol: str = "",
        tls_version: str = "",
        cert_expiry_date: Optional[str] = None,
        cert_issuer: str = "",
        cert_subject: str = "",
        cert_serial: str = "",
    ) -> CryptoComponent:
        rec_algo, rec_fips = recommended_algorithm(algorithm)

        risk = score_component(
            component_id="tmp",
            algorithm=algorithm,
            algorithm_family=algorithm_family,
            algorithm_risk=classification.algorithm_risk,
            quantum_status=classification.quantum_status,
            data_sensitivity=data_sensitivity,
            location_type=location_type,
            is_public_facing=is_public_facing,
            key_size=key_size,
        )

        timeline = _classify_threat_timeline(
            classification.quantum_status,
            classification.algorithm_risk,
            risk.hndl_risk,
            risk.migration_priority,
        )

        return CryptoComponent(
            id=str(uuid.uuid4()),
            location_type=location_type,
            location_detail=location_detail,
            location_file="",
            location_line=None,
            algorithm=algorithm,
            algorithm_family=algorithm_family,
            key_size=key_size,
            quantum_status=classification.quantum_status,
            algorithm_risk=classification.algorithm_risk,
            confidence="high",
            data_sensitivity=data_sensitivity,
            data_sensitivity_score=risk.data_sensitivity_score,
            final_risk_score=risk.final_risk_score,
            hndl_risk=risk.hndl_risk,
            recommended_algorithm=rec_algo,
            recommended_fips=rec_fips,
            estimated_effort_hours=_effort_hours(algorithm_family),
            migration_priority=risk.migration_priority,
            nist_compliant=risk.nist_compliant,
            pci_compliant=risk.pci_compliant,
            dst_compliant=risk.dst_compliant,
            cnsa_compliant=risk.cnsa_compliant,
            protocol=protocol,
            tls_version=tls_version,
            cert_expiry_date=cert_expiry_date,
            cert_issuer=cert_issuer,
            cert_subject=cert_subject,
            cert_serial=cert_serial,
            threat_timeline=timeline,
        )

    def _deduplicate(self, components: list[CryptoComponent]) -> list[CryptoComponent]:
        """
        Deduplicate by (location_detail, algorithm).
        Keep the highest-risk occurrence; update last_seen_at.
        """
        seen: dict[tuple[str, str], CryptoComponent] = {}
        for comp in components:
            key = (comp.location_detail, comp.algorithm.lower())
            if key not in seen or comp.final_risk_score > seen[key].final_risk_score:
                seen[key] = comp
            else:
                seen[key].last_seen_at = comp.last_seen_at
        return list(seen.values())

    # ------------------------------------------------------------------
    # Summary & analytics
    # ------------------------------------------------------------------

    def summarise(
        self,
        components: list[CryptoComponent],
        frameworks: Optional[list[str]] = None,
    ) -> CBOMSummary:
        """Compute summary statistics and compliance across all components."""
        if frameworks is None:
            frameworks = ["nist_800_131a", "pci_dss_12_3_3", "dst_2026", "cnsa_2"]

        scored = [
            score_component(
                component_id=c.id,
                algorithm=c.algorithm,
                algorithm_family=c.algorithm_family,
                algorithm_risk=c.algorithm_risk,
                quantum_status=c.quantum_status,
                data_sensitivity=c.data_sensitivity,
                location_type=c.location_type,
                is_public_facing=True,
                key_size=c.key_size,
            )
            for c in components
        ]

        org = score_org(scored)

        by_family: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}

        for comp in components:
            by_family[comp.algorithm_family] = by_family.get(comp.algorithm_family, 0) + 1
            by_status[comp.quantum_status] = by_status.get(comp.quantum_status, 0) + 1
            by_priority[comp.migration_priority] = by_priority.get(comp.migration_priority, 0) + 1

        compliance: dict[str, ComplianceResult] = {}
        for fw in frameworks:
            try:
                compliance[fw] = check_compliance(scored, fw)
            except ValueError:
                pass

        return CBOMSummary(
            total_components=len(components),
            vulnerable_count=sum(1 for c in components if c.quantum_status in ("vulnerable", "deprecated")),
            safe_count=sum(1 for c in components if c.quantum_status == "safe"),
            deprecated_count=sum(1 for c in components if c.quantum_status == "deprecated"),
            hndl_critical_count=org.hndl_critical_count,
            by_algorithm_family=by_family,
            by_quantum_status=by_status,
            by_migration_priority=by_priority,
            org_risk_score=org.score,
            org_risk_detail=org,
            compliance=compliance,
        )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, components: list[CryptoComponent], indent: int = 2) -> str:
        """Export CBOM as JSON."""
        data = {
            "schema_version": "1.0",
            "generated_at": _now_iso(),
            "component_count": len(components),
            "components": [_component_to_dict(c) for c in components],
        }
        return json.dumps(data, indent=indent, default=str)

    def export_csv(self, components: list[CryptoComponent]) -> str:
        """Export CBOM as CSV."""
        if not components:
            return ""
        buf = io.StringIO()
        fieldnames = [
            "id", "location_type", "location_detail", "algorithm",
            "algorithm_family", "quantum_status", "algorithm_risk",
            "data_sensitivity", "final_risk_score", "hndl_risk",
            "migration_priority", "recommended_algorithm", "recommended_fips",
            "estimated_effort_hours", "nist_compliant", "pci_compliant",
            "dst_compliant", "cnsa_compliant", "confidence",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for comp in components:
            writer.writerow(_component_to_dict(comp))
        return buf.getvalue()

    def export_cyclonedx(self, components: list[CryptoComponent]) -> dict[str, Any]:
        """
        Export CBOM in CycloneDX 1.6 format. The cryptographic-asset component
        type and cryptoProperties were introduced in CycloneDX 1.6 (Apr 2024) —
        declaring 1.5 here while using those fields produces a BOM that fails
        validation against its own declared schema version.
        Ref: https://cyclonedx.org/docs/1.6/json/
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": _now_iso(),
                "tools": [{"vendor": "SeQr Labs", "name": "seqr-scanner", "version": _SCANNER_VERSION}],
            },
            "components": [
                {
                    "type": "cryptographic-asset",
                    "bom-ref": comp.id,
                    "name": comp.algorithm,
                    "cryptoProperties": {
                        "assetType": _cdx_asset_type(comp.location_type),
                        "algorithmProperties": {
                            "primitive": _cdx_primitive(comp.algorithm_family),
                            "parameterSetIdentifier": comp.algorithm,
                            "classical": comp.quantum_status in ("vulnerable", "deprecated"),
                        },
                        "relatedCryptoMaterialProperties": {
                            "type": comp.location_type,
                            "size": comp.key_size,
                        },
                    },
                    "evidence": {
                        "occurrences": [
                            {
                                "location": comp.location_detail,
                                "line": comp.location_line,
                            }
                        ]
                    },
                    "properties": [
                        {"name": "seqr:quantum_status", "value": comp.quantum_status},
                        {"name": "seqr:algorithm_risk", "value": str(comp.algorithm_risk)},
                        {"name": "seqr:final_risk_score", "value": str(comp.final_risk_score)},
                        {"name": "seqr:hndl_risk", "value": str(comp.hndl_risk)},
                        {"name": "seqr:migration_priority", "value": comp.migration_priority},
                        {"name": "seqr:threat_timeline", "value": comp.threat_timeline},
                        {"name": "seqr:recommended_algorithm", "value": comp.recommended_algorithm},
                        {"name": "seqr:recommended_fips", "value": comp.recommended_fips},
                    ],
                }
                for comp in components
            ],
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _component_to_dict(comp: CryptoComponent) -> dict:
    d = asdict(comp)
    return d


def _classify_threat_timeline(
    quantum_status: str,
    algorithm_risk: int,
    hndl_risk: bool,
    migration_priority: str,
) -> str:
    """Map component properties to a threat timeline category."""
    if quantum_status == "deprecated" or hndl_risk:
        return THREAT_TIMELINE_IMMEDIATE
    if quantum_status == "vulnerable":
        if migration_priority == "critical" or algorithm_risk >= 7:
            return THREAT_TIMELINE_URGENT
        return THREAT_TIMELINE_PLANNED
    return THREAT_TIMELINE_ROADMAP


def _effort_hours(family: str) -> int:
    return {
        "RSA": 8,
        "ECC": 8,
        "DH": 12,
        "AES": 2,
        "SHA": 2,
        "TLS": 4,
        "ML-KEM": 0,
        "ML-DSA": 0,
        "SLH-DSA": 0,
    }.get(family.upper(), 8)


def _cdx_asset_type(location_type: str) -> str:
    return {
        "tls_cert": "certificate",
        "code": "library",
        "kms_key": "related-crypto-material",
        "ssh_key": "related-crypto-material",
        "jwt": "protocol",
    }.get(location_type, "unknown")


def _cdx_primitive(family: str) -> str:
    return {
        "RSA": "public-key-encryption",
        "ECC": "signature",
        "DH": "key-agreement",
        "AES": "block-cipher",
        "SHA": "hash",
        "TLS": "protocol",
        "ML-KEM": "kem",
        "ML-DSA": "signature",
        "SLH-DSA": "signature",
    }.get(family.upper(), "other")


def build_cbom(
    network_results=None,
    code_findings=None,
    org_data_sensitivity: str = "internal",
    is_public_facing: bool = True,
) -> list[CryptoComponent]:
    """Convenience wrapper — equivalent to CBOMEngine().aggregate(...)."""
    return CBOMEngine().aggregate(
        network_results=network_results,
        code_findings=code_findings,
        org_data_sensitivity=org_data_sensitivity,
        is_public_facing=is_public_facing,
    )
