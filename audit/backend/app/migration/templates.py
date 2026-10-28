"""Enterprise validation templates (Phase 2 checkpoint).

No public dataset exists for internal cryptographic inventories (they are confidential), so we
validate on multiple realistic *sector* templates instead. Each template is a data spec of
assets + observations + graph edges with a realistic weak/hybrid/compliant crypto mix and at
least one exposed origin. `build(spec)` materializes a template and runs the whole pipeline.

The external-surface data we DO have for real (the 118-domain research corpus) can be adapted
into a template later via the same spec shape.
"""

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.asset_identity import AssetIdentity
from app.models.asset_type import AssetType
from app.spine.sources import precedence_for

_T0 = datetime(2026, 6, 1)

_TYPES = [
    ("tls_endpoint", "TLS Endpoint", "network"), ("origin", "Origin Server", "network"),
    ("reverse_proxy", "Reverse Proxy", "network"), ("load_balancer", "Load Balancer", "network"),
    ("host", "Internal Host", "host"), ("hsm", "HSM", "key-store"),
    ("certificate", "Certificate", "pki"), ("mail_server", "Mail Server", "network"),
]

# obs tuple: (location_type, algorithm, family, quantum_status, source, key_size|None)
# asset tuple: (type, identifier, provenance, sensitivity, [obs...])
TEMPLATES: dict[str, dict] = {
    "banking": {
        "name": "Meridian Financial",
        "assets": [
            ("tls_endpoint", "api.meridian.example", "user_declared", "confidential",
             [("tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", "active_probe", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("tls_endpoint", "auth.meridian.example", "user_declared", "confidential",
             [("tls_kex", "RSA", "RSA", "vulnerable", "external_scanner", None),
              ("tls_cert", "ECDSA-P256", "ECC", "vulnerable", "external_scanner", 256)]),
            ("tls_endpoint", "secure.meridian.example", "user_declared", "internal",
             [("tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", "active_probe", None),
              ("tls_cert", "RSA-3072", "RSA", "vulnerable", "external_scanner", 3072)]),
            ("origin", "origin-api.meridian.example", "discovered", "confidential",
             [("tls_kex", "X25519", "ECC", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("load_balancer", "lb01.meridian.example", "discovered", "internal",
             [("tls_kex", "ECDHE", "ECC", "vulnerable", "discovery_agent", None)]),
            ("host", "app01.meridian.example", "discovered", "internal",
             [("ssh_key", "ssh-rsa", "RSA", "vulnerable", "discovery_agent", 2048)]),
            ("hsm", "hsm-luna-01", "discovered", "confidential",
             [("ssh_key", "RSA-4096 (slot 3)", "RSA", "vulnerable", "discovery_agent", 4096)]),
        ],
        "edges": [("api.meridian.example", "origin-api.meridian.example", "origin_of"),
                  ("lb01.meridian.example", "app01.meridian.example", "upstream_of"),
                  ("app01.meridian.example", "hsm-luna-01", "hosted_on_hsm")],
    },
    "healthcare": {
        "name": "Aster Health Systems",
        "assets": [
            ("tls_endpoint", "portal.aster.example", "user_declared", "confidential",
             [("tls_kex", "X25519", "ECC", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("tls_endpoint", "records.aster.example", "user_declared", "confidential",
             [("tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", "active_probe", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("origin", "origin-records.aster.example", "discovered", "confidential",
             [("tls_kex", "RSA", "RSA", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("mail_server", "mx.aster.example", "discovered", "confidential",
             [("tls_kex", "ECDHE", "ECC", "vulnerable", "external_scanner", None)]),
            ("hsm", "hsm-aster-01", "discovered", "confidential",
             [("ssh_key", "RSA-3072 (slot 1)", "RSA", "vulnerable", "discovery_agent", 3072)]),
        ],
        "edges": [("records.aster.example", "origin-records.aster.example", "origin_of")],
    },
    "telecom": {
        "name": "Nimbus Telecom",
        "assets": [
            ("tls_endpoint", "selfcare.nimbus.example", "user_declared", "internal",
             [("tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", "active_probe", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("reverse_proxy", "rp-edge.nimbus.example", "discovered", "internal",
             [("tls_kex", "ECDHE", "ECC", "vulnerable", "discovery_agent", None)]),
            ("origin", "origin-selfcare.nimbus.example", "discovered", "confidential",
             [("tls_kex", "X25519", "ECC", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("host", "core01.nimbus.example", "discovered", "internal",
             [("ssh_key", "ecdsa-sha2-nistp256", "ECC", "vulnerable", "discovery_agent", 256)]),
        ],
        "edges": [("selfcare.nimbus.example", "origin-selfcare.nimbus.example", "origin_of"),
                  ("rp-edge.nimbus.example", "origin-selfcare.nimbus.example", "fronts")],
    },
    "government": {
        "name": "State Digital Services",
        "assets": [
            ("tls_endpoint", "eportal.sds.example", "user_declared", "confidential",
             [("tls_kex", "X25519", "ECC", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("origin", "origin-eportal.sds.example", "discovered", "confidential",
             [("tls_kex", "RSA", "RSA", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("hsm", "hsm-sds-airgap", "discovered", "confidential",
             [("ssh_key", "RSA-4096 (air-gapped)", "RSA", "vulnerable", "discovery_agent", 4096)]),
            ("host", "gw01.sds.example", "discovered", "internal",
             [("ssh_key", "ssh-rsa", "RSA", "vulnerable", "discovery_agent", 2048)]),
        ],
        "edges": [("eportal.sds.example", "origin-eportal.sds.example", "origin_of"),
                  ("gw01.sds.example", "hsm-sds-airgap", "hosted_on_hsm")],
    },
    "saas": {
        "name": "Cloudline SaaS",
        "assets": [
            ("tls_endpoint", "app.cloudline.example", "user_declared", "internal",
             [("tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", "active_probe", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("tls_endpoint", "api.cloudline.example", "user_declared", "confidential",
             [("tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", "active_probe", None),
              ("tls_cert", "RSA-3072", "RSA", "vulnerable", "external_scanner", 3072)]),
            ("origin", "origin-api.cloudline.example", "discovered", "confidential",
             [("tls_kex", "X25519", "ECC", "vulnerable", "external_scanner", None),
              ("tls_cert", "RSA-2048", "RSA", "vulnerable", "external_scanner", 2048)]),
            ("load_balancer", "alb.cloudline.example", "discovered", "internal",
             [("tls_kex", "ECDHE", "ECC", "vulnerable", "discovery_agent", None)]),
        ],
        "edges": [("api.cloudline.example", "origin-api.cloudline.example", "origin_of"),
                  ("alb.cloudline.example", "origin-api.cloudline.example", "upstream_of")],
    },
}


def _asset(s, org, type_, ident, prov, sens):
    a = Asset(org_id=org, type=type_, identifier=ident, name=ident, provenance=prov,
              data_sensitivity=sens, first_seen_at=_T0)
    s.add(a); s.flush()
    s.add(AssetIdentity(org_id=org, asset_id=a.id,
                        key_type="domain" if type_ in ("tls_endpoint", "origin", "mail_server") else type_,
                        key_value=ident, resolver="exact", confidence=1.0, resolved_at=_T0))
    return a


def _obs(s, org, scan_id, asset_id, loc, algo, fam, status, source, key_size):
    from app.models.crypto_component import CryptoComponent
    s.add(CryptoComponent(
        org_id=org, scan_id=scan_id, asset_id=asset_id, location_type=loc, location_detail=loc,
        algorithm=algo, algorithm_family=fam, quantum_status=status, key_size=key_size,
        source=source, precedence=precedence_for(source), observed_at=_T0))


def build(s: Session, spec: dict, org=None) -> dict:
    """Materialize a template + run the full pipeline. Returns pipeline artifacts.

    Pass `org` to seed into an existing organisation (e.g. the DB seeder); default = a fresh
    ephemeral org id for in-memory validation.
    """
    from app.migration.bundle import MigrationSigner, build_bundle, verify_bundle
    from app.migration.planner import build_plan
    from app.spine.attest import AttestationSigner, create_attestation
    from app.spine.ingest import project_component_state, record_event
    from app.spine.policy import evaluate_policy
    from app.spine.verify import verify_artifact

    org = org or uuid.uuid4()
    for key, label, cat in _TYPES:
        if not s.query(AssetType).filter(AssetType.key == key, AssetType.org_id.is_(None)).first():
            s.add(AssetType(org_id=None, key=key, label=label, category=cat, created_at=_T0))

    from app.models.scan import Scan

    idx: dict[str, Asset] = {}
    for (type_, ident, prov, sens, obs) in spec["assets"]:
        a = _asset(s, org, type_, ident, prov, sens)
        idx[ident] = a
        # crypto_components.scan_id is a NOT-NULL FK to scans; create a placeholder completed
        # scan per asset so the observations reference a real row (Postgres enforces the FK;
        # SQLite silently tolerated the previous dangling scan_id).
        scan = Scan(org_id=org, asset_id=a.id, type="seed", status="complete",
                    started_at=_T0, completed_at=_T0)
        s.add(scan); s.flush()
        for (loc, algo, fam, status, src, ks) in obs:
            _obs(s, org, scan.id, a.id, loc, algo, fam, status, src, ks)
    for (src_i, dst_i, rel) in spec["edges"]:
        s.add(AssetEdge(org_id=org, src_asset_id=idx[src_i].id, dst_asset_id=idx[dst_i].id,
                        relation=rel, discovered_by="external_scanner", confidence=0.9, valid_from=_T0))
    record_event(s, org, "measured", "seed", None, {"template": spec["name"], "assets": len(idx)})
    s.commit()

    for a in idx.values():
        project_component_state(s, org, a.id)
    s.commit()

    ev = evaluate_policy(s, org); s.commit()
    plan = build_plan(s, org, ev); s.commit()
    bundle_row, tar_bytes, manifest = build_bundle(s, plan, MigrationSigner.generate()); s.commit()
    att_row, artifact = create_attestation(s, org, ev, AttestationSigner.generate()); s.commit()

    return {
        "org_id": org, "template": spec["name"], "evaluation_id": ev.id, "plan_id": plan.id,
        "bundle_id": bundle_row.id, "bundle_tar": tar_bytes, "bundle_manifest": manifest,
        "bundle_offline_verify": verify_bundle(tar_bytes),
        "attestation_id": att_row.id, "attestation_artifact": artifact,
        "attestation_offline_verify": verify_artifact(artifact),
    }
