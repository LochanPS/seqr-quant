"""Policy engine (PRD 13, §4) — the single home of *desired* state.

A policy is immutable and content-hashed. Evaluation runs it over an org's current
component_state projection (+ the graph, for the origin-bypass rule) and produces a
reproducible PolicyEvaluation with ranked Violations. component_state stores only a
reference (latest_policy_evaluation_id); compliance is never cached on state.

Rule severities are declared on the rule for v1; wiring engines/risk.py for a calibrated
severity/priority is a later refinement.
"""

import hashlib
import json
import re
import uuid

from sqlalchemy.orm import Session

from app.models.asset_edge import AssetEdge
from app.models.component_state import ComponentState
from app.models.crypto_component import CryptoComponent
from app.models.policy import Policy, PolicyEvaluation, Violation
from app.spine.ingest import record_event

# System baseline derived from PCI DSS 12.3.3 + SEBI CSCRF intent (inventory + prioritise
# PQC migration). ML-DSA certs are a future module, so the cert rule only enforces a
# classical minimum, not PQC signatures.
DEFAULT_POLICY_BODY = {
    "rules": [
        {"key": "kex_must_be_hybrid", "slot": "tls:kex", "type": "family_in",
         "allowed": ["ML-KEM"], "severity": "urgent", "target": "X25519MLKEM768"},
        {"key": "no_static_rsa_kex", "slot": "tls:kex", "type": "family_not_in",
         "forbidden": ["RSA"], "severity": "immediate", "target": "ephemeral or hybrid KEX"},
        {"key": "cert_min_rsa", "slot": "tls:cert", "type": "min_key_size",
         "family": "RSA", "min": 3072, "severity": "planned", "target": "RSA-3072+ (ML-DSA later)"},
        {"key": "no_exposed_classical_origin", "type": "graph_no_origin_edge",
         "severity": "urgent", "target": "close origin / enforce mTLS edge->origin"},
    ]
}


def content_hash(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _u(v) -> uuid.UUID:
    return v if isinstance(v, uuid.UUID) else uuid.UUID(str(v))


def _parse_key_size(algorithm: str | None) -> int | None:
    m = re.search(r"(\d{3,5})", algorithm or "")
    return int(m.group(1)) if m else None


def ensure_default_policy(db: Session) -> Policy:
    """The system default policy (org_id NULL, is_default). Created once, immutable."""
    ch = content_hash(DEFAULT_POLICY_BODY)
    existing = (
        db.query(Policy)
        .filter(Policy.org_id.is_(None), Policy.is_default.is_(True), Policy.content_hash == ch)
        .first()
    )
    if existing:
        return existing
    pol = Policy(org_id=None, name="SeQr baseline (PCI DSS + SEBI CSCRF)", version="1",
                 content_hash=ch, body=DEFAULT_POLICY_BODY, is_default=True)
    db.add(pol)
    db.flush()
    return pol


def _eval_slot_rule(rule: dict, obs: CryptoComponent | None) -> str | None:
    """Return the offending 'actual' string if the rule fails on this observation, else None."""
    if obs is None:
        return None
    fam = obs.algorithm_family or ""
    t = rule["type"]
    if t == "family_in" and fam not in rule["allowed"]:
        return f"{obs.algorithm} ({fam})"
    if t == "family_not_in" and fam in rule["forbidden"]:
        return f"{obs.algorithm} ({fam})"
    if t == "min_key_size" and fam == rule["family"]:
        ks = obs.key_size or _parse_key_size(obs.algorithm)
        if ks is not None and ks < rule["min"]:
            return f"{obs.algorithm} ({ks}-bit)"
    return None


def evaluate_policy(db: Session, org_id, policy: Policy | None = None, actor: str = "system") -> PolicyEvaluation:
    """Run a policy over an org's current state + graph → PolicyEvaluation + Violations."""
    org_id = _u(org_id)
    if policy is None:
        policy = ensure_default_policy(db)

    states = db.query(ComponentState).filter(ComponentState.org_id == org_id).all()
    # (asset_id, observation_id | None, rule, actual)
    found: list[tuple] = []
    covered: set = set()

    slot_rules = [r for r in policy.body["rules"] if r.get("slot")]
    for st in states:
        covered.add(st.asset_id)
        obs = db.get(CryptoComponent, st.winning_observation_id)
        for rule in slot_rules:
            if rule["slot"] != st.slot_key:
                continue
            actual = _eval_slot_rule(rule, obs)
            if actual:
                found.append((st.asset_id, obs.id if obs else None, rule, actual))

    # Graph rule: an open origin_of edge = an exposed origin outside the protected edge.
    for rule in policy.body["rules"]:
        if rule.get("type") == "graph_no_origin_edge":
            edges = (
                db.query(AssetEdge)
                .filter(AssetEdge.org_id == org_id, AssetEdge.relation == "origin_of",
                        AssetEdge.valid_to.is_(None))
                .all()
            )
            for e in edges:
                covered.add(e.src_asset_id)
                found.append((e.src_asset_id, None, rule, "reachable classical origin behind edge"))

    # Deterministic result hash (reproducible attestation input).
    canonical = sorted(f"{a}|{rule['key']}|{actual}" for (a, _o, rule, actual) in found)
    result_hash = hashlib.sha256(
        (policy.content_hash + "\n" + "\n".join(canonical)).encode()
    ).hexdigest()

    ev = PolicyEvaluation(
        org_id=org_id, policy_id=policy.id, policy_content_hash=policy.content_hash,
        covered_asset_set=sorted(str(a) for a in covered), result_hash=result_hash,
        violations_count=len(found),
    )
    db.add(ev)
    db.flush()

    for (asset_id, obs_id, rule, actual) in found:
        db.add(Violation(
            org_id=org_id, evaluation_id=ev.id, asset_id=asset_id, observation_id=obs_id,
            rule_key=rule["key"], severity=rule.get("severity", "planned"),
            actual=actual, target_state=rule.get("target"),
        ))

    # Point evaluated state rows at this evaluation (compliance computed from it, not stored).
    for st in states:
        st.latest_policy_evaluation_id = ev.id

    record_event(db, org_id, "policy_evaluated", actor, None,
                 {"evaluation_id": str(ev.id), "violations": len(found)})
    return ev
