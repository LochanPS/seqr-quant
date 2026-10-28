"""Migration bundle engine (PRD 14, Slice 3).

Assembles a plan's synthesized artifacts into a portable, deterministic, offline-verifiable
tar bundle with a signed manifest. Uses a DEDICATED migration signing key (separate from the
attestation and licensing keys). No execution — the engine's job ends at a verified bundle.

Bundle layout:
    manifest.json          signed metadata + per-file SHA-256 (the trust anchor)
    runbook.md             human-readable ordered steps
    compatibility.md       per-change compatibility notes
    artifacts/<id>.json    one ChangeArtifact per ChangeItem (snippets + rollback + checklist)
"""

import base64
import hashlib
import io
import json
import os
import tarfile
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.orm import Session

from app.graph_schema import GRAPH_SCHEMA_VERSION
from app.migration.synthesis import synthesize_plan
from app.migration_version import MIGRATION_ENGINE_VERSION
from app.models.migration import ChangeItem, MigrationBundle, RollbackPlan
from app.spine.ingest import record_event


def _mig_key_id(public_raw: bytes) -> str:
    return "mig_" + hashlib.sha256(public_raw).hexdigest()[:16]


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class MigrationSigner:
    """Dedicated Ed25519 migration signer. key_id prefix 'mig_' (distinct from attestation 'att_')."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self.public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = _mig_key_id(self.public_raw)

    @classmethod
    def generate(cls) -> "MigrationSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes) -> "MigrationSigner":
        return cls(serialization.load_pem_private_key(pem, password=None))

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._sk.sign(payload)).decode()

    def public_b64(self) -> str:
        return base64.b64encode(self.public_raw).decode()

    def private_pem(self) -> bytes:
        return self._sk.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def get_migration_signer() -> MigrationSigner:
    pem = os.environ.get("MIGRATION_PRIVATE_KEY_PEM")
    if pem:
        return MigrationSigner.from_pem(pem.encode())
    path = os.environ.get("MIGRATION_KEY_PATH")
    if path and os.path.exists(path):
        with open(path, "rb") as fh:
            return MigrationSigner.from_pem(fh.read())
    signer = MigrationSigner.generate()
    if path:
        with open(path, "wb") as fh:
            fh.write(signer.private_pem())
    return signer


def _render_runbook(artifacts) -> str:
    lines = ["# SeQr migration runbook", "",
             "Apply these changes in order. Each is additive; rollback steps are included.", ""]
    for i, a in enumerate(artifacts, 1):
        lines.append(f"## Step {i}: {a.action} on {a.target_platform} ({a.target_component or '-'})")
        if a.prerequisites:
            lines.append("Prerequisites: " + "; ".join(a.prerequisites))
        if a.required_inputs:
            lines.append("Required inputs: " + "; ".join(a.required_inputs))
        for sn in a.snippets:
            lines.append(f"Insert in {sn.insertion_point}:")
            lines.append("```" + sn.language)
            lines.append(sn.content)
            lines.append("```")
        if a.expected_outcome:
            lines.append("Expected: " + a.expected_outcome)
        if a.validation_checklist:
            lines.append("Validate: " + "; ".join(a.validation_checklist))
        if a.rollback:
            lines.append("Rollback: " + "; ".join(a.rollback))
        lines.append("")
    return "\n".join(lines)


def _render_compatibility(artifacts) -> str:
    out = ["# Compatibility report", ""]
    for a in artifacts:
        out.append(f"- {a.action} / {a.target_platform}: {a.compatibility or 'n/a'}")
    return "\n".join(out) + "\n"


def _deterministic_tar(files: dict[str, bytes]) -> bytes:
    """Build a byte-stable tar: sorted names, zeroed mtime/uid/gid."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_bundle(db: Session, plan, signer: MigrationSigner | None = None, actor: str = "system"):
    """Synthesize + assemble + sign a bundle for a plan. Returns (MigrationBundle row, tar_bytes, manifest)."""
    signer = signer or get_migration_signer()
    artifacts = synthesize_plan(db, plan)

    # Capture a rollback per change item: pre-change state + the inverse steps (Slice 4).
    items = {str(ci.id): ci for ci in db.query(ChangeItem).filter(ChangeItem.plan_id == plan.id).all()}
    for a in artifacts:
        ci = items.get(a.change_item_id)
        if ci is None:
            continue
        exists = db.query(RollbackPlan).filter(RollbackPlan.change_item_id == ci.id).first()
        if not exists:
            db.add(RollbackPlan(
                org_id=plan.org_id, change_item_id=ci.id,
                pre_state={"slot_key": ci.slot_key, "actual": ci.from_state},
                inverse_artifact="\n".join(a.rollback),
            ))

    files: dict[str, bytes] = {}
    entries = []
    for a in artifacts:
        path = f"artifacts/{a.change_item_id or uuid.uuid4()}.json"
        data = a.model_dump_json(indent=2).encode()
        files[path] = data
        entries.append({"path": path, "sha256": _sha256(data), "change_item_id": a.change_item_id,
                        "action": a.action, "target_platform": a.target_platform})

    runbook = _render_runbook(artifacts)
    compat = _render_compatibility(artifacts)
    files["runbook.md"] = runbook.encode()
    files["compatibility.md"] = compat.encode()
    entries.append({"path": "runbook.md", "sha256": _sha256(files["runbook.md"]), "change_item_id": None,
                    "action": "runbook", "target_platform": "-"})
    entries.append({"path": "compatibility.md", "sha256": _sha256(files["compatibility.md"]), "change_item_id": None,
                    "action": "compatibility", "target_platform": "-"})

    # Signed portion — deterministic (no timestamp): a pure function of the plan + synthesis.
    signed = {
        "plan_id": str(plan.id),
        "org_id": str(plan.org_id),
        "migration_engine_version": MIGRATION_ENGINE_VERSION,
        "graph_schema_version": GRAPH_SCHEMA_VERSION,
        "artifacts": sorted(entries, key=lambda e: e["path"]),
        "key_id": signer.key_id,
    }
    signature = signer.sign(_canonical(signed))
    manifest = {
        "bundle": signed,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),  # informational, unsigned
        "signature": signature,
        "public_key": signer.public_b64(),
        "algorithm": "ed25519",
    }
    files["manifest.json"] = json.dumps(manifest, indent=2).encode()

    tar_bytes = _deterministic_tar(files)

    row = MigrationBundle(
        org_id=plan.org_id, plan_id=plan.id, manifest=signed, runbook=runbook,
        migration_engine_version=MIGRATION_ENGINE_VERSION, graph_schema_version=GRAPH_SCHEMA_VERSION,
        key_id=signer.key_id, signature=signature,
    )
    db.add(row)
    plan.status = "bundled"
    db.flush()
    record_event(db, plan.org_id, "migration_bundled", actor, None,
                 {"plan_id": str(plan.id), "bundle_id": str(row.id), "artifacts": len(entries)})
    return row, tar_bytes, manifest


def verify_bundle(tar_bytes: bytes) -> bool:
    """Offline: verify the signature over the manifest and every artifact's SHA-256. No network."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            files = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
        manifest = json.loads(files["manifest.json"])
        signed = manifest["bundle"]
        public_raw = base64.b64decode(manifest["public_key"])
        if signed.get("key_id") != _mig_key_id(public_raw):
            return False
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            base64.b64decode(manifest["signature"]), _canonical(signed))
        for entry in signed["artifacts"]:
            if _sha256(files[entry["path"]]) != entry["sha256"]:
                return False
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError, tarfile.TarError):
        return False
