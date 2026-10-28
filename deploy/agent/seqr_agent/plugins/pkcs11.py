"""HSM / PKCS#11 slot-inventory collector (stub, key-safe).

Enumerates the slots, token labels, and *public* key objects an HSM exposes over PKCS#11 —
key type and size only. It NEVER extracts private key material (PRD 15 §8: inventory, not
export); it reads object attributes (CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS_BITS / EC params)
and enumerates supported mechanisms. Emits `hsm_key` observations.

Real backends use PyKCS11 against the configured module (e.g. SoftHSM, a network HSM's
client lib). When PyKCS11 or the module is absent, ``available()`` is False and the runtime
skips it — the stub degrades cleanly rather than failing the run.

Config:
    module: /usr/lib/softhsm/libsofthsm2.so   # PKCS#11 .so/.dll
    pin: null                                  # optional; public objects need no login
    label: null                                # restrict to one token label
"""

from __future__ import annotations

import os

from ..observation import AssetObservation
from .base import SourcePlugin

# CKK_* key type -> (algorithm, family). Public-object key types only.
_KEY_TYPES = {
    "CKK_RSA": ("RSA", "RSA"),
    "CKK_EC": ("ECDSA", "ECC"),
    "CKK_ECDSA": ("ECDSA", "ECC"),
    "CKK_EC_EDWARDS": ("Ed25519", "ECC"),
    "CKK_ML_KEM": ("ML-KEM", "ML-KEM"),
    "CKK_ML_DSA": ("ML-DSA", "ML-DSA"),
}


class PKCS11Plugin(SourcePlugin):
    key = "pkcs11"

    def available(self) -> bool:
        # A test/simulation enumerator, or a real module path with PyKCS11 installed.
        if callable(self.config.get("_enumerator")):
            return True
        module = self.config.get("module")
        if not module or not os.path.isfile(module):
            return False
        try:
            import PyKCS11  # noqa: F401
        except Exception:
            return False
        return True

    def collect(self) -> list[AssetObservation]:
        slots = self._enumerate()
        obs: list[AssetObservation] = []
        for slot in slots:
            token = slot.get("token") or f"slot-{slot.get('slot_id')}"
            mechanisms = slot.get("mechanisms") or []
            for key in slot.get("public_keys") or []:
                alg, fam = _KEY_TYPES.get(key.get("key_type", ""), (key.get("key_type", "unknown"), None))
                obs.append(AssetObservation(
                    asset_key=f"hsm:{token}:{key.get('label') or key.get('id') or 'key'}",
                    asset_key_type="hsm_object", asset_type="hsm_key",
                    asset_name=f"{token} · {key.get('label') or key.get('id') or 'key'}",
                    location_type="hsm_key",
                    location_detail=f"PKCS#11 token '{token}', slot {slot.get('slot_id')}",
                    algorithm=alg, algorithm_family=fam, key_size=key.get("bits"),
                    confidence="high", plugin=self.key,
                ))
            if not slot.get("public_keys") and mechanisms:
                # No public objects visible (login-gated) — still record the token + its mechs.
                obs.append(AssetObservation(
                    asset_key=f"hsm:{token}", asset_key_type="hsm_object", asset_type="hsm_token",
                    asset_name=f"{token} (mechanisms only)",
                    location_type="hsm_token",
                    location_detail=f"slot {slot.get('slot_id')} · mechanisms: {', '.join(mechanisms[:12])}",
                    algorithm=_dominant_mech(mechanisms), confidence="low", plugin=self.key,
                ))
        return obs

    # ---------------------------------------------------------------- enumeration
    def _enumerate(self) -> list[dict]:
        """Return a list of slot dicts. A `_enumerator` callable in config overrides the real
        PyKCS11 path (used by tests + air-gap simulation). Never raises."""
        enum = self.config.get("_enumerator")
        if callable(enum):
            try:
                return list(enum(self.config) or [])
            except Exception:
                return []
        try:
            return self._enumerate_pykcs11()
        except Exception:
            return []

    def _enumerate_pykcs11(self) -> list[dict]:  # pragma: no cover — needs a real HSM
        import PyKCS11

        lib = PyKCS11.PyKCS11Lib()
        lib.load(self.config["module"])
        want_label = self.config.get("label")
        pin = self.config.get("pin")
        out: list[dict] = []
        for slot_id in lib.getSlotList(tokenPresent=True):
            info = lib.getTokenInfo(slot_id)
            token = (info.label or "").strip()
            if want_label and token != want_label:
                continue
            mechs = []
            try:
                mechs = [PyKCS11.CKM.get(m, str(m)) for m in lib.getMechanismList(slot_id)]
            except Exception:
                pass
            pubkeys: list[dict] = []
            session = None
            try:
                session = lib.openSession(slot_id)
                if pin:
                    session.login(str(pin))
                objs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])
                for o in objs:
                    attrs = session.getAttributeValue(
                        o, [PyKCS11.CKA_KEY_TYPE, PyKCS11.CKA_LABEL, PyKCS11.CKA_ID,
                            PyKCS11.CKA_MODULUS_BITS]
                    )
                    kt, label, kid, bits = attrs
                    pubkeys.append({
                        "key_type": PyKCS11.CKK.get(kt, str(kt)),
                        "label": label, "id": bytes(kid).hex() if kid else None,
                        "bits": bits or None,
                    })
            except Exception:
                pass
            finally:
                if session is not None:
                    try:
                        session.logout()
                    except Exception:
                        pass
                    try:
                        session.closeSession()
                    except Exception:
                        pass
            out.append({"slot_id": slot_id, "token": token,
                        "mechanisms": mechs, "public_keys": pubkeys})
        return out


def _dominant_mech(mechanisms: list[str]) -> str:
    joined = " ".join(mechanisms).lower()
    if "ml_kem" in joined or "mlkem" in joined:
        return "ML-KEM"
    if "ml_dsa" in joined or "mldsa" in joined:
        return "ML-DSA"
    if "rsa" in joined:
        return "RSA"
    if "ec" in joined:
        return "ECDSA"
    return "unknown"
