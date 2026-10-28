"""Encrypted local key store — AES-256-GCM at rest, key derived from a passphrase.

    ks = LocalKeyStore(passphrase="my-secret")
    key_id = ks.generate_and_store("ML-DSA-65", metadata={"purpose": "jwt"})
    pub = ks.get_public_key(key_id)
    priv = ks.get_private_key(key_id)                 # counts as one "use"
    new_id = ks.rotate(key_id)                        # new keypair; old marked "rotated"

On-disk layout (single file, default ``~/.seqr/keys.enc``):
    salt(16) || nonce(12) || AES-256-GCM(ciphertext+tag)
The plaintext is a JSON document. The master key is
PBKDF2-HMAC-SHA256(passphrase, salt, 100_000 iterations, 32 bytes). A wrong passphrase
surfaces as :class:`KMSAuthError` (GCM tag mismatch).

Hardening (SDK-4):

* **Rotation policy** — a :class:`RotationPolicy` (max age / max uses). ``get_private_key``
  counts a use; :meth:`needs_rotation` / :meth:`rotate_if_needed` act on the policy.
* **Export / import** — :meth:`export_key` emits a single key as a portable,
  passphrase-encrypted blob; :meth:`import_key` reads it back into another store.
* **Append-only audit log** — every key operation is appended (hash-chained, tamper-
  evident) to ``<store>.audit.log``. It holds *operational metadata only* (op, key id,
  algorithm, timestamps) — never key material — so it is deliberately not encrypted.

``store`` / ``get_*`` / ``rotate`` bookkeeping is backend-free; only key *generation*
(``generate_and_store`` / ``rotate``) needs the PQC backend.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pqcmap import algorithms
from pqcmap.core.exceptions import (
    KMSAuthError,
    KMSError,
    KMSKeyNotFoundError,
    UnsupportedAlgorithmError,
)
from pqcmap.utils import encoding

_SALT_LEN = 16
_NONCE_LEN = 12
_PBKDF2_ITERATIONS = 100_000
_MASTER_KEY_LEN = 32  # AES-256
_SCHEMA_VERSION = 2
_EXPORT_MAGIC = b"PQCKEXP1"
_AUDIT_GENESIS = "0" * 64

DEFAULT_STORE_PATH = Path.home() / ".seqr" / "keys.enc"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class RotationPolicy:
    """When a key should be rotated. ``None`` disables that dimension."""

    max_age_days: Optional[float] = None
    max_uses: Optional[int] = None

    def to_dict(self) -> dict:
        return {"max_age_days": self.max_age_days, "max_uses": self.max_uses}

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "RotationPolicy":
        d = d or {}
        return cls(max_age_days=d.get("max_age_days"), max_uses=d.get("max_uses"))


class LocalKeyStore:
    def __init__(
        self,
        passphrase: str,
        path: Optional[os.PathLike | str] = None,
        *,
        rotation_policy: Optional[RotationPolicy] = None,
        audit: bool = True,
    ):
        if not passphrase:
            raise KMSAuthError("A non-empty passphrase is required.")
        self._passphrase = passphrase.encode("utf-8")
        self.path = Path(path) if path is not None else DEFAULT_STORE_PATH
        self.audit_path = self.path.with_name(self.path.name + ".audit.log")
        self._audit_enabled = audit
        self._records: dict[str, dict[str, Any]] = {}
        self._policy = rotation_policy or RotationPolicy()
        self._salt: bytes
        if self.path.exists():
            self._load()
            if rotation_policy is not None:  # explicit policy overrides the stored one
                self._policy = rotation_policy
                self._save()
        else:
            self._salt = secrets.token_bytes(_SALT_LEN)
            if rotation_policy is not None:  # persist the policy even before any key
                self._save()
        self._last_audit_hash = self._read_last_audit_hash()

    # -- public API ---------------------------------------------------------------

    @property
    def rotation_policy(self) -> RotationPolicy:
        return self._policy

    def set_rotation_policy(self, policy: RotationPolicy) -> None:
        self._policy = policy
        self._save()

    def store(
        self,
        algorithm: str,
        public_key: bytes,
        secret_key: bytes,
        metadata: Optional[dict] = None,
    ) -> str:
        """Store an existing keypair; return its generated key id."""
        if algorithm not in algorithms.ALGORITHM_META:
            raise UnsupportedAlgorithmError(f"Unknown algorithm {algorithm!r}.")
        key_id = "key_" + secrets.token_hex(8)
        self._records[key_id] = {
            "algorithm": algorithm,
            "public_key": encoding.b64u_encode(public_key),
            "secret_key": encoding.b64u_encode(secret_key),
            "metadata": metadata or {},
            "created_at": _now(),
            "status": "active",
            "rotated_to": None,
            "uses": 0,
            "last_used_at": None,
        }
        self._save()
        self._audit("store", key_id, algorithm)
        return key_id

    def generate_and_store(self, algorithm: str, metadata: Optional[dict] = None) -> str:
        """Generate a fresh keypair for ``algorithm`` and store it. Needs the backend."""
        keypair = self._generate(algorithm)
        key_id = self.store(algorithm, keypair.public_key, keypair.secret_key, metadata)
        self._audit("generate", key_id, algorithm)
        return key_id

    def get_public_key(self, key_id: str) -> bytes:
        return encoding.b64u_decode(self._record(key_id)["public_key"])

    def get_private_key(self, key_id: str, *, record_use: bool = True) -> bytes:
        """Return the secret key. Counts as one "use" unless ``record_use=False``.

        Usage tracking feeds the rotation policy; pass ``record_use=False`` to peek
        (e.g. for an export) without advancing the counter or writing an audit entry.
        """
        rec = self._record(key_id)
        if record_use:
            rec["uses"] = int(rec.get("uses", 0)) + 1
            rec["last_used_at"] = _now()
            self._save()
            self._audit("access", key_id, rec["algorithm"], {"uses": rec["uses"]})
        return encoding.b64u_decode(rec["secret_key"])

    def get_metadata(self, key_id: str) -> dict:
        rec = self._record(key_id)
        return {
            "algorithm": rec["algorithm"],
            "metadata": rec["metadata"],
            "created_at": rec["created_at"],
            "status": rec["status"],
            "rotated_to": rec["rotated_to"],
            "uses": int(rec.get("uses", 0)),
            "last_used_at": rec.get("last_used_at"),
        }

    def rotate(self, key_id: str) -> str:
        """Generate a new keypair (same algorithm), mark the old one rotated.

        The old record is retained (status ``rotated``, ``rotated_to`` → new id) so
        previously issued artifacts can still be verified. Needs the backend.
        """
        rec = self._record(key_id)
        new_id = self.generate_and_store(rec["algorithm"], rec["metadata"])
        rec["status"] = "rotated"
        rec["rotated_to"] = new_id
        self._save()
        self._audit("rotate", key_id, rec["algorithm"], {"rotated_to": new_id})
        return new_id

    def needs_rotation(self, key_id: str, policy: Optional[RotationPolicy] = None) -> bool:
        """True if ``key_id`` has exceeded the age or usage limit of the policy."""
        rec = self._record(key_id)
        if rec["status"] != "active":
            return False
        pol = policy or self._policy
        if pol.max_uses is not None and int(rec.get("uses", 0)) >= pol.max_uses:
            return True
        if pol.max_age_days is not None:
            age_days = (
                datetime.now(timezone.utc) - _parse_ts(rec["created_at"])
            ).total_seconds() / 86400.0
            if age_days >= pol.max_age_days:
                return True
        return False

    def rotate_if_needed(
        self, key_id: str, policy: Optional[RotationPolicy] = None
    ) -> Optional[str]:
        """Rotate ``key_id`` if the policy says so; return the new id or ``None``."""
        if self.needs_rotation(key_id, policy):
            return self.rotate(key_id)
        return None

    def list_keys(self) -> list[dict]:
        return [{"key_id": kid, **self.get_metadata(kid)} for kid in self._records]

    # -- export / import ----------------------------------------------------------

    def export_key(self, key_id: str, passphrase: str) -> bytes:
        """Export a single key as a portable, passphrase-encrypted blob.

        Independent of the store's own passphrase, so a key can be handed to another
        store or environment. AES-256-GCM under PBKDF2-HMAC-SHA256(passphrase).
        """
        if not passphrase:
            raise KMSAuthError("A non-empty export passphrase is required.")
        rec = self._record(key_id)
        doc = json.dumps({"key_id": key_id, "record": rec}).encode("utf-8")
        salt = secrets.token_bytes(_SALT_LEN)
        nonce = secrets.token_bytes(_NONCE_LEN)
        key = _derive(passphrase.encode("utf-8"), salt)
        ciphertext = AESGCM(key).encrypt(nonce, doc, None)
        self._audit("export", key_id, rec["algorithm"])
        return _EXPORT_MAGIC + salt + nonce + ciphertext

    def import_key(self, blob: bytes, passphrase: str) -> str:
        """Import a key produced by :meth:`export_key`; return its id in this store.

        Reuses the original key id when free, otherwise assigns a fresh one. Raises
        :class:`KMSAuthError` on a wrong passphrase or corrupt blob.
        """
        if blob[: len(_EXPORT_MAGIC)] != _EXPORT_MAGIC:
            raise KMSError("Not a pqcmap key export (bad magic).")
        body = blob[len(_EXPORT_MAGIC) :]
        if len(body) < _SALT_LEN + _NONCE_LEN:
            raise KMSError("Truncated key export.")
        salt = body[:_SALT_LEN]
        nonce = body[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
        ciphertext = body[_SALT_LEN + _NONCE_LEN :]
        key = _derive(passphrase.encode("utf-8"), salt)
        try:
            doc = json.loads(AESGCM(key).decrypt(nonce, ciphertext, None))
        except InvalidTag as exc:
            raise KMSAuthError("Wrong export passphrase or corrupt export blob.") from exc
        record = doc["record"]
        key_id = doc.get("key_id", "")
        if not key_id or key_id in self._records:
            key_id = "key_" + secrets.token_hex(8)
        self._records[key_id] = record
        self._save()
        self._audit("import", key_id, record.get("algorithm", "?"))
        return key_id

    # -- audit log ----------------------------------------------------------------

    def read_audit_log(self) -> list[dict]:
        """Return the parsed append-only audit entries (oldest first)."""
        if not self.audit_path.exists():
            return []
        entries = []
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    def verify_audit_log(self) -> bool:
        """Re-walk the hash chain; return True, or raise :class:`KMSError` on tamper."""
        prev = _AUDIT_GENESIS
        for entry in self.read_audit_log():
            expected = _audit_hash(prev, entry)
            if entry.get("hash") != expected or entry.get("prev") != prev:
                raise KMSError(
                    f"Audit log tamper detected at seq {entry.get('seq')!r}."
                )
            prev = entry["hash"]
        return True

    # -- internals ----------------------------------------------------------------

    def _record(self, key_id: str) -> dict[str, Any]:
        try:
            return self._records[key_id]
        except KeyError as exc:
            raise KMSKeyNotFoundError(f"No key with id {key_id!r}.") from exc

    def _generate(self, algorithm: str):
        if algorithm in algorithms.KEM_ALGORITHMS:
            from pqcmap.core.kem import KeyEncapsulation

            return KeyEncapsulation(algorithm).generate_keypair()
        if algorithm in algorithms.SIGN_ALGORITHMS:
            from pqcmap.core.sign import Signature

            return Signature(algorithm).generate_keypair()
        raise UnsupportedAlgorithmError(f"Cannot generate for {algorithm!r}.")

    def _derive_key(self, salt: bytes) -> bytes:
        return _derive(self._passphrase, salt)

    def _load(self) -> None:
        raw = self.path.read_bytes()
        if len(raw) < _SALT_LEN + _NONCE_LEN:
            raise KMSAuthError("Key store file is truncated or corrupt.")
        self._salt = raw[:_SALT_LEN]
        nonce = raw[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
        ciphertext = raw[_SALT_LEN + _NONCE_LEN :]
        key = self._derive_key(self._salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise KMSAuthError(
                "Could not decrypt key store — wrong passphrase or corrupt file."
            ) from exc
        doc = json.loads(plaintext.decode("utf-8"))
        # Schema v2 wraps keys + policy; a legacy v1 file is a flat {key_id: record} map.
        if isinstance(doc, dict) and doc.get("version") == _SCHEMA_VERSION:
            self._records = doc.get("keys", {})
            self._policy = RotationPolicy.from_dict(doc.get("policy"))
        else:
            self._records = doc
            self._policy = RotationPolicy()

    def _save(self) -> None:
        doc = {
            "version": _SCHEMA_VERSION,
            "keys": self._records,
            "policy": self._policy.to_dict(),
        }
        key = self._derive_key(self._salt)
        nonce = secrets.token_bytes(_NONCE_LEN)
        plaintext = json.dumps(doc).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically, then tighten permissions (best effort on POSIX).
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(self._salt + nonce + ciphertext)
        try:
            os.chmod(tmp, 0o600)
        except (OSError, NotImplementedError):
            pass  # Windows / restricted FS — encryption still protects the contents
        os.replace(tmp, self.path)

    def _read_last_audit_hash(self) -> str:
        if not self._audit_enabled or not self.audit_path.exists():
            return _AUDIT_GENESIS
        last = _AUDIT_GENESIS
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)["hash"]
                except (ValueError, KeyError):
                    continue
        return last

    def _audit(
        self, op: str, key_id: str, algorithm: str, detail: Optional[dict] = None
    ) -> None:
        if not self._audit_enabled:
            return
        entry = {
            "seq": len(self.read_audit_log()),
            "ts": _now(),
            "op": op,
            "key_id": key_id,
            "algorithm": algorithm,
            "detail": detail or {},
            "prev": self._last_audit_hash,
        }
        entry["hash"] = _audit_hash(self._last_audit_hash, entry)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            raise KMSError(f"Could not append to audit log: {exc}") from exc
        self._last_audit_hash = entry["hash"]


def _derive(passphrase: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_MASTER_KEY_LEN,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    ).derive(passphrase)


def _audit_hash(prev: str, entry: dict) -> str:
    """Hash of an entry chained to ``prev`` — excludes the ``hash`` field itself."""
    material = {k: entry[k] for k in ("seq", "ts", "op", "key_id", "algorithm", "detail")}
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
