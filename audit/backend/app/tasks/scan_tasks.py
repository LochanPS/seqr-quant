import asyncio
import concurrent.futures
import json
import random
import uuid as _uuid
from datetime import datetime, timezone

from seqr_scanner import NetworkScanner, scan_ssh

from app.tasks import celery_app
from app.tasks import throttle
from app.spine.ingest import confidence_score
from app.spine.sources import DiscoverySource, precedence_for

# Asset types whose scan goes through the TLS pipeline (DomainScanResult).
# STARTTLS-upgraded (smtp/imap/pop3/postgres) + direct-TLS (mongodb/amqp/grpc)
# + mysql (its own mid-handshake TLS-upgrade probe).
_TLS_PROTOCOLS = {"smtp", "imap", "pop3", "postgres", "mongodb", "amqp", "grpc", "mysql"}


# --- Live progress over the WS pub/sub channel (scan:{scan_id}) -------------
# The frontend scan page subscribes to /ws/scans/{scan_id} (main.py), which relays
# whatever the worker publishes to the Redis channel scan:{scan_id}. We emit:
#   {"type":"step","step": "..."}                       — phase text
#   {"type":"finding","algorithm","location_detail",...} — each component as found
#   {"type":"complete","components": n} / {"type":"failed","error": "..."}
# Publishing is a no-op with fakeredis (dev/tests) — there is no real subscriber.

def _real_broker() -> bool:
    from app.config import settings
    return not settings.USE_FAKE_REDIS


def _publish(scan_id: str, payload: dict) -> None:
    if not _real_broker():
        return
    try:
        celery_app.backend.client.publish(f"scan:{scan_id}", json.dumps(payload))
    except Exception:
        # Progress is best-effort telemetry; never fail a scan because the WS
        # channel is unavailable.
        pass


def _step(scan_id: str, text: str) -> None:
    _publish(scan_id, {"type": "step", "step": text})


def _publish_findings(scan_id: str, components: list) -> None:
    for c in components:
        _publish(scan_id, {
            "type": "finding",
            "algorithm": c.algorithm,
            "algorithm_family": c.algorithm_family,
            "location_detail": c.location_detail,
            "quantum_status": c.quantum_status,
        })


# --- Per-org fairness throttle ----------------------------------------------

def _throttle_enabled() -> bool:
    """Enforce per-org caps only with a real broker + queue. Eager/fakeredis runs
    inline (dev/tests), where retry would recurse and there is no contention."""
    from app.config import settings
    return (
        _real_broker()
        and not settings.CELERY_ALWAYS_EAGER
        and settings.MAX_CONCURRENT_SCANS_PER_ORG > 0
    )


def _acquire_org_slot(org_id: str) -> bool:
    from app.config import settings
    return throttle.acquire_org_slot(
        celery_app.backend.client,
        org_id,
        settings.MAX_CONCURRENT_SCANS_PER_ORG,
        settings.SCAN_ORG_INFLIGHT_TTL,
    )


def _release_org_slot(org_id: str) -> None:
    throttle.release_org_slot(celery_app.backend.client, org_id)


def _retry_countdown() -> int:
    from app.config import settings
    base = settings.SCAN_RETRY_COUNTDOWN
    return base + random.randint(0, base)  # jitter so re-queues don't thundering-herd


def _stamp_observations(components, result=None):
    """Set structured source/precedence/confidence/observed_at on each observation (PRD 13)."""
    now = datetime.utcnow()
    for c in components:
        hybrid_kex = c.location_type == "tls_kex" and result is not None and (
            getattr(result, "pqc_active_supported", False) or getattr(result, "hybrid_status", "") == "hybrid"
        )
        c.source = DiscoverySource.ACTIVE_PROBE if hybrid_kex else DiscoverySource.EXTERNAL_SCANNER
        c.precedence = precedence_for(c.source)
        c.confidence_score = confidence_score(c.confidence)
        c.observed_at = now
    return components


@celery_app.task(bind=True, max_retries=None)
def run_network_scan(self, scan_id: str, asset_id: str, org_id: str, domain: str, asset_type: str = "domain"):
    from app.database import SyncSessionLocal
    from app.models.scan import Scan
    from app.models.crypto_component import CryptoComponent

    # Fairness: claim a per-org slot before doing any work. If the org is already at
    # its cap, re-queue (freeing this worker slot for another tenant) — the scan row
    # stays "queued" and the WS shows queued until a slot frees.
    throttled = _throttle_enabled()
    if throttled and not _acquire_org_slot(org_id):
        raise self.retry(countdown=_retry_countdown())

    db = SyncSessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == _uuid.UUID(scan_id)).first()
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        scan.celery_task_id = self.request.id
        db.commit()
        _step(scan_id, "Resolving DNS and TLS endpoints…")

        if asset_type == "ssh":
            ssh_result = scan_ssh(domain)
            components = _ssh_result_to_components(ssh_result, scan_id, asset_id, org_id)
            transport = _ssh_transport_summary(ssh_result)
        else:
            protocol = asset_type if asset_type in _TLS_PROTOCOLS else "https"
            _step(scan_id, "Probing TLS configuration…")
            # Authenticated scan of the customer's OWN asset → safe to discover
            # the origin behind a CDN (the public demo never does recon).
            scanner = NetworkScanner(active_pqc=True, discover_origin=(protocol == "https"))
            import inspect
            raw = scanner.scan_domain(domain, protocol=protocol)
            if inspect.iscoroutine(raw):
                try:
                    asyncio.get_running_loop()
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        result = pool.submit(asyncio.run, raw).result()
                except RuntimeError:
                    result = asyncio.run(raw)
            else:
                result = raw
            _step(scan_id, "Classifying quantum exposure…")
            components = _result_to_components(result, scan_id, asset_id, org_id)
            transport = _tls_transport_summary(result, protocol)
        for c in components:
            db.add(c)
        scan.transport_summary = transport

        scan.status = "complete"
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        scan.components_found = len(components)
        scan.vulnerable_found = sum(
            1 for c in components if c.quantum_status == "vulnerable"
        )
        db.commit()
        # Stream each discovered component to the live findings panel.
        _publish_findings(scan_id, components)

        # Platform spine (PRD 13): resolve the asset, record origin edges, and project the
        # append-only observations into current state. Never fails the scan.
        try:
            from app.spine.ingest import ingest_scan_graph
            from app.spine.policy import evaluate_policy
            ingest_scan_graph(db, org_id, asset_id, scan_id, transport)
            db.commit()
            # Judge the fresh state against the org's policy (default baseline for now).
            evaluate_policy(db, org_id)
            db.commit()
        except Exception:
            db.rollback()

        from app.routers.risk import _compute_score
        vuln = [c for c in components if c.quantum_status == "vulnerable"]
        new_score = _compute_score(vuln)
        from app.models.organisation import Organisation
        org_obj = db.query(Organisation).filter(
            Organisation.id == _uuid.UUID(org_id)
        ).first()
        if org_obj:
            org_obj.quantum_risk_score = new_score
            db.commit()

        _publish(scan_id, {"type": "complete", "components": len(components)})

    except Exception as e:
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            db.commit()
        _publish(scan_id, {"type": "failed", "error": str(e)})
    finally:
        db.close()
        if throttled:
            _release_org_slot(org_id)


def _tls_transport_summary(result, protocol: str) -> dict:
    """Scan-level transport posture for the scan-detail header + edge/origin card."""
    active_group = getattr(result, "pqc_active_group", "") or None
    return {
        "protocol": protocol,
        "tls_version": result.tls_version or None,
        "cert_algorithm": result.cert_algorithm or None,
        "key_exchange": active_group or (result.key_exchange_algorithm or None),
        "hybrid_status": result.hybrid_status or None,
        "pqc_active_supported": bool(getattr(result, "pqc_active_supported", False)),
        "pqc_active_group": active_group,
        "deployment_level": result.deployment_level,
        "deployment_level_name": result.deployment_level_name,
        "crypto_agility_score": result.crypto_agility_score,
        "cdn_detected": bool(result.cdn_detected),
        "cdn_provider": result.cdn_provider or None,
        "scan_target": getattr(result, "scan_target", "direct"),
        "origin_assessed": bool(getattr(result, "origin_assessed", False)),
        "origin_note": getattr(result, "origin_note", "") or None,
        "origin_candidates": list(getattr(result, "origin_candidates", []) or []),
    }


def _ssh_transport_summary(result) -> dict:
    if not getattr(result, "reachable", False):
        return {"protocol": "ssh", "reachable": False}
    kex = None
    if getattr(result, "pqc_kex_supported", False) and getattr(result, "pqc_kex_methods", None):
        kex = result.pqc_kex_methods[0]
    elif getattr(result, "kex_algorithms", None):
        kex = result.kex_algorithms[0]
    return {
        "protocol": "ssh",
        "reachable": True,
        "host_key": result.host_key_algorithms[0] if getattr(result, "host_key_algorithms", None) else None,
        "key_exchange": kex,
        "pqc_kex_supported": bool(getattr(result, "pqc_kex_supported", False)),
    }


def _result_to_components(result, scan_id: str, asset_id: str, org_id: str) -> list:
    from app.models.crypto_component import CryptoComponent

    components = []
    domain = result.domain
    port = getattr(result, "port", 443)

    # --- Certificate (authentication) ---
    if result.cert_algorithm:
        expiry = None
        issuer = None
        if result.cert:
            raw = result.cert.expiry_date
            if raw:
                expiry = raw.date() if hasattr(raw, "date") else raw
            issuer = result.cert.issuer

        cert_family = _get_family(result.cert_algorithm)
        # Status of the CERTIFICATE itself — not the domain-level status. A domain can
        # negotiate hybrid PQC key exchange while its certificate stays classical (the
        # common CDN case); the cert must not inherit the domain's "hybrid" label.
        cert_status = "safe" if cert_family in ("ML-DSA", "ML-KEM") else "vulnerable"

        components.append(CryptoComponent(
            org_id=_uuid.UUID(org_id),
            scan_id=_uuid.UUID(scan_id),
            asset_id=_uuid.UUID(asset_id),
            location_type="tls_cert",
            location_detail=f"{domain}:{port} (certificate)",
            algorithm=result.cert_algorithm,
            algorithm_family=cert_family,
            quantum_status=cert_status,
            pqc_migration_priority=result.pqc_migration_priority,
            estimated_hndl_exposure=result.estimated_hndl_exposure,
            deployment_level=result.deployment_level,
            crypto_agility_score=result.crypto_agility_score,
            threat_timeline=result.threat_timeline,
            confidence=result.scan_confidence,
            cert_expiry_date=expiry,
            cert_issuer=issuer,
        ))

    # --- Key exchange (confidentiality) ---
    # Surfaces the active ML-KEM probe result. Previously dropped entirely, so the
    # dashboard never showed the hybrid PQC group the scanner actually negotiated.
    kex_hybrid = bool(getattr(result, "pqc_active_supported", False)) or result.hybrid_status == "hybrid"
    kex_algo = (getattr(result, "pqc_active_group", "") or result.key_exchange_algorithm) if kex_hybrid \
        else result.key_exchange_algorithm
    if kex_algo:
        if kex_hybrid:
            kex_family, kex_status = "ML-KEM", "hybrid"
        elif (kex_algo or "").upper().startswith("RSA"):
            kex_family, kex_status = "RSA", "vulnerable"   # static RSA: also no forward secrecy
        else:
            kex_family, kex_status = "ECC", "vulnerable"   # X25519 / ECDHE: classical, quantum-vulnerable

        components.append(CryptoComponent(
            org_id=_uuid.UUID(org_id),
            scan_id=_uuid.UUID(scan_id),
            asset_id=_uuid.UUID(asset_id),
            location_type="tls_kex",
            location_detail=f"{domain}:{port} (key exchange)",
            algorithm=kex_algo,
            algorithm_family=kex_family,
            quantum_status=kex_status,
            deployment_level=result.deployment_level,
            crypto_agility_score=result.crypto_agility_score,
            threat_timeline=result.threat_timeline,
            confidence=result.scan_confidence,
        ))

    return _stamp_observations(components, result)


def _ssh_result_to_components(result, scan_id: str, asset_id: str, org_id: str) -> list:
    """Map an SshScanResult to CryptoComponents: host-key signature + key exchange."""
    from app.models.crypto_component import CryptoComponent

    if not getattr(result, "reachable", False):
        return []

    components = []
    host = f"{result.host}:{result.port}"

    # Host-key signature (authentication) — all current SSH host keys are classical.
    if result.host_key_algorithms:
        hk = result.host_key_algorithms[0]
        components.append(CryptoComponent(
            org_id=_uuid.UUID(org_id),
            scan_id=_uuid.UUID(scan_id),
            asset_id=_uuid.UUID(asset_id),
            location_type="ssh_key",
            location_detail=f"{host} (host key)",
            algorithm=hk,
            algorithm_family=_ssh_hostkey_family(hk),
            quantum_status=result.host_key_quantum_status or "vulnerable",
            confidence="high",
        ))

    # Key exchange — quantum-safe if the server offers a hybrid PQC KEX.
    kex_algo = (result.pqc_kex_methods[0] if result.pqc_kex_supported
                else (result.kex_algorithms[0] if result.kex_algorithms else "unknown"))
    components.append(CryptoComponent(
        org_id=_uuid.UUID(org_id),
        scan_id=_uuid.UUID(scan_id),
        asset_id=_uuid.UUID(asset_id),
        location_type="ssh_kex",
        location_detail=f"{host} (key exchange)",
        algorithm=kex_algo,
        algorithm_family="ML-KEM" if result.pqc_kex_supported else "ECC",
        quantum_status="safe" if result.pqc_kex_supported else "vulnerable",
        confidence="high",
    ))
    return _stamp_observations(components)


def _ssh_hostkey_family(algo: str) -> str:
    a = (algo or "").lower()
    if "rsa" in a:
        return "RSA"
    if "ed25519" in a or "ed448" in a or "ecdsa" in a:
        return "ECC"
    if "dss" in a or "dsa" in a:
        return "DSA"
    return "other"


def _get_family(algorithm: str) -> str:
    if not algorithm:
        return "unknown"
    a = algorithm.upper()
    if "RSA" in a:
        return "RSA"
    if "ECDSA" in a or "ECC" in a:
        return "ECC"
    if "ML-KEM" in a or "KYBER" in a:
        return "ML-KEM"
    if "ML-DSA" in a:
        return "ML-DSA"
    if "AES" in a:
        return "AES"
    return "other"
