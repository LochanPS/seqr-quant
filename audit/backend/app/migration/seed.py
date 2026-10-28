"""Realistic enterprise seed + full-pipeline run (Phase 2 internal-validation checkpoint).

Builds a fictional enterprise ("Meridian Financial") with the shape of a real environment —
CDN-fronted edges, exposed origins, a reverse proxy, a load balancer, internal hosts, an HSM
reference, certificate chains, and a mix of weak / hybrid / compliant crypto — then runs the
entire lifecycle (project -> evaluate -> plan -> bundle -> attest) and returns every artifact
so a harness can inspect each stage.

NOTE: the discovery agent is not built yet, so internal/origin/HSM assets are seeded directly
as the *data* such an agent would produce. This validates the pipeline, not the agent.
"""

import uuid
from datetime import date, datetime

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_edge import AssetEdge
from app.models.asset_identity import AssetIdentity
from app.models.asset_type import AssetType
from app.models.crypto_component import CryptoComponent
from app.spine.ingest import project_component_state
from app.spine.policy import evaluate_policy
from app.spine.sources import DiscoverySource, precedence_for

_T0 = datetime(2026, 6, 1)

_ASSET_TYPES = [
    ("tls_endpoint", "TLS Endpoint", "network"),
    ("origin", "Origin Server", "network"),
    ("reverse_proxy", "Reverse Proxy", "network"),
    ("load_balancer", "Load Balancer", "network"),
    ("host", "Internal Host", "host"),
    ("hsm", "HSM", "key-store"),
    ("certificate", "Certificate", "pki"),
]


def _asset(s, org, type_, ident, provenance, sensitivity="internal"):
    a = Asset(org_id=org, type=type_, identifier=ident, name=ident, provenance=provenance,
              data_sensitivity=sensitivity, first_seen_at=_T0)
    s.add(a); s.flush()
    s.add(AssetIdentity(org_id=org, asset_id=a.id,
                        key_type="domain" if type_ in ("tls_endpoint", "origin") else type_,
                        key_value=ident, resolver="exact", confidence=1.0, resolved_at=_T0))
    return a


def _obs(s, org, asset_id, loc, algo, fam, status, source, key_size=None, issuer=None, expiry=None):
    s.add(CryptoComponent(
        org_id=org, scan_id=uuid.uuid4(), asset_id=asset_id, location_type=loc, location_detail=loc,
        algorithm=algo, algorithm_family=fam, quantum_status=status, key_size=key_size,
        cert_issuer=issuer, cert_expiry_date=expiry,
        source=source, precedence=precedence_for(source), observed_at=_T0,
    ))


def _edge(s, org, src, dst, relation, by=DiscoverySource.EXTERNAL_SCANNER, conf=0.9):
    s.add(AssetEdge(org_id=org, src_asset_id=src, dst_asset_id=dst, relation=relation,
                    discovered_by=by, confidence=conf, valid_from=_T0))


EXT = DiscoverySource.EXTERNAL_SCANNER
PROBE = DiscoverySource.ACTIVE_PROBE
AGENT = DiscoverySource.DISCOVERY_AGENT


def build_enterprise(s: Session) -> dict:
    org = uuid.uuid4()
    for key, label, cat in _ASSET_TYPES:
        s.add(AssetType(org_id=None, key=key, label=label, category=cat, created_at=_T0))

    # --- assets ---------------------------------------------------------------------------
    api = _asset(s, org, "tls_endpoint", "api.meridian.example", "user_declared", "confidential")
    auth = _asset(s, org, "tls_endpoint", "auth.meridian.example", "user_declared", "confidential")
    secure = _asset(s, org, "tls_endpoint", "secure.meridian.example", "user_declared")  # already compliant
    origin = _asset(s, org, "origin", "origin-api.meridian.example", "discovered", "confidential")
    rp = _asset(s, org, "reverse_proxy", "rp01.meridian.example", "discovered")
    lb = _asset(s, org, "load_balancer", "lb01.meridian.example", "discovered")
    host = _asset(s, org, "host", "app01.meridian.example", "discovered")
    hsm = _asset(s, org, "hsm", "hsm-luna-01", "discovered", "confidential")
    leaf = _asset(s, org, "certificate", "CN=api.meridian.example", "discovered")
    inter = _asset(s, org, "certificate", "CN=Meridian Issuing CA", "discovered")

    # --- observations (mix of weak / hybrid / compliant) ----------------------------------
    # api: hybrid at the CDN edge, but a classical certificate (the mirage)
    _obs(s, org, api.id, "tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", PROBE)
    _obs(s, org, api.id, "tls_cert", "RSA-2048", "RSA", "vulnerable", EXT, key_size=2048,
         issuer="Meridian Issuing CA", expiry=date(2026, 11, 1))
    # origin behind the edge: fully classical + exposed
    _obs(s, org, origin.id, "tls_kex", "X25519", "ECC", "vulnerable", EXT)
    _obs(s, org, origin.id, "tls_cert", "RSA-2048", "RSA", "vulnerable", EXT, key_size=2048)
    # auth: static RSA key exchange (no forward secrecy) + classical
    _obs(s, org, auth.id, "tls_kex", "RSA", "RSA", "vulnerable", EXT)
    _obs(s, org, auth.id, "tls_cert", "ECDSA-P256", "ECC", "vulnerable", EXT, key_size=256)
    # secure: already compliant — hybrid KEX + strong cert (proves clean assets produce no noise)
    _obs(s, org, secure.id, "tls_kex", "X25519MLKEM768", "ML-KEM", "hybrid", PROBE)
    _obs(s, org, secure.id, "tls_cert", "RSA-3072", "RSA", "vulnerable", EXT, key_size=3072)
    # reverse proxy / load balancer: classical transport (internal, agent-discovered)
    _obs(s, org, rp.id, "tls_kex", "ECDHE", "ECC", "vulnerable", AGENT)
    _obs(s, org, lb.id, "tls_kex", "ECDHE", "ECC", "vulnerable", AGENT)
    # internal host: SSH classical host key + kex (inventory beyond current policy rules)
    _obs(s, org, host.id, "ssh_key", "ssh-rsa", "RSA", "vulnerable", AGENT, key_size=2048)
    _obs(s, org, host.id, "ssh_kex", "curve25519-sha256", "ECC", "vulnerable", AGENT)
    # HSM: stored key material reference
    _obs(s, org, hsm.id, "ssh_key", "RSA-4096 (HSM slot 3)", "RSA", "vulnerable", AGENT, key_size=4096)
    # certificate-chain assets
    _obs(s, org, leaf.id, "tls_cert", "RSA-2048", "RSA", "vulnerable", EXT, key_size=2048,
         issuer="Meridian Issuing CA")
    _obs(s, org, inter.id, "tls_cert", "RSA-4096", "RSA", "vulnerable", EXT, key_size=4096,
         issuer="Meridian Root CA")

    # --- graph edges ----------------------------------------------------------------------
    _edge(s, org, api.id, origin.id, "origin_of")          # exposed origin behind the edge
    _edge(s, org, rp.id, origin.id, "fronts")
    _edge(s, org, lb.id, host.id, "upstream_of")
    _edge(s, org, host.id, hsm.id, "hosted_on_hsm")
    _edge(s, org, api.id, leaf.id, "serves_cert")
    _edge(s, org, leaf.id, inter.id, "issued_by")
    s.commit()

    # --- run the full pipeline ------------------------------------------------------------
    from app.spine.ingest import record_event
    record_event(s, org, "measured", "seed", None, {"assets": 10, "observations": 15})
    for a in (api, auth, secure, origin, rp, lb, host, hsm, leaf, inter):
        project_component_state(s, org, a.id)
    s.commit()

    ev = evaluate_policy(s, org); s.commit()

    from app.migration.planner import build_plan
    from app.migration.bundle import MigrationSigner, build_bundle, verify_bundle
    from app.spine.attest import AttestationSigner, create_attestation
    from app.spine.verify import verify_artifact

    plan = build_plan(s, org, ev); s.commit()
    bundle_row, tar_bytes, manifest = build_bundle(s, plan, MigrationSigner.generate()); s.commit()
    att_row, artifact = create_attestation(s, org, ev, AttestationSigner.generate()); s.commit()

    return {
        "org_id": org,
        "evaluation_id": ev.id,
        "plan_id": plan.id,
        "bundle_id": bundle_row.id,
        "bundle_tar": tar_bytes,
        "bundle_manifest": manifest,
        "bundle_offline_verify": verify_bundle(tar_bytes),
        "attestation_id": att_row.id,
        "attestation_artifact": artifact,
        "attestation_offline_verify": verify_artifact(artifact),
    }
