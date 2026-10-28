"""Certificate-store collector — filesystem cert files + the OS trust store.

Inventories X.509 certificates the external scanner never sees: service cert bundles on disk
and the host's trusted-root store. For each certificate it records the leaf public-key
algorithm/size, issuer and expiry as a `cert_store` observation. Read-only — it opens files
and the OS store for reading only; it never touches private keys (only public certs are parsed).

Config:
    paths: ["/etc/ssl/certs", "/etc/nginx/ssl"]   # dirs and/or files to scan
    include_os_trust: true                         # also enumerate the OS root store
    max_files: 2000                                # safety cap
"""

from __future__ import annotations

import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..observation import AssetObservation
from .base import SourcePlugin

_CERT_EXT = (".pem", ".crt", ".cer", ".der", ".cert")


class CertStorePlugin(SourcePlugin):
    key = "cert_store"

    def available(self) -> bool:
        return bool(self.config.get("paths")) or bool(self.config.get("include_os_trust"))

    def collect(self) -> list[AssetObservation]:
        obs: list[AssetObservation] = []
        seen: set[bytes] = set()  # dedupe identical certs across sources by DER fingerprint
        max_files = int(self.config.get("max_files", 2000))

        for path in self.config.get("paths") or []:
            for der, origin in self._iter_files(path, max_files):
                self._add(obs, seen, der, origin)

        if self.config.get("include_os_trust"):
            for der in self._os_trust_ders():
                self._add(obs, seen, der, "os-trust-store")

        return obs

    # ---------------------------------------------------------------- filesystem
    def _iter_files(self, path: str, max_files: int):
        collected = 0
        if os.path.isfile(path):
            files = [path]
        elif os.path.isdir(path):
            files = []
            for root, _dirs, names in os.walk(path):
                for n in names:
                    if n.lower().endswith(_CERT_EXT):
                        files.append(os.path.join(root, n))
        else:
            return
        for fp in files:
            if collected >= max_files:
                return
            for der in self._read_certs(fp):
                collected += 1
                yield der, fp

    @staticmethod
    def _read_certs(fp: str) -> list[bytes]:
        """Return the DER bytes of every certificate in a file (PEM may hold a chain)."""
        try:
            with open(fp, "rb") as f:
                data = f.read()
        except OSError:
            return []
        ders: list[bytes] = []
        if b"-----BEGIN CERTIFICATE-----" in data:
            try:
                for c in x509.load_pem_x509_certificates(data):
                    ders.append(c.public_bytes(_der()))
            except Exception:
                # Older cryptography: parse the first PEM cert only.
                try:
                    ders.append(x509.load_pem_x509_certificate(data).public_bytes(_der()))
                except Exception:
                    pass
        else:
            try:
                ders.append(x509.load_der_x509_certificate(data).public_bytes(_der()))
            except Exception:
                pass
        return ders

    # ---------------------------------------------------------------- OS trust store
    @staticmethod
    def _os_trust_ders() -> list[bytes]:
        ders: list[bytes] = []
        # Windows: ssl.enum_certificates enumerates the system stores.
        if hasattr(ssl, "enum_certificates"):
            for store in ("ROOT", "CA"):
                try:
                    for cert_bytes, enc, _trust in ssl.enum_certificates(store):
                        if enc == "x509_asn":
                            ders.append(cert_bytes)
                except Exception:
                    continue
        # POSIX: the default CA bundle, if present.
        try:
            paths = ssl.get_default_verify_paths()
            for bundle in (paths.cafile, paths.openssl_cafile):
                if bundle and os.path.isfile(bundle):
                    ders.extend(CertStorePlugin._read_certs(bundle))
                    break
        except Exception:
            pass
        return ders

    # ---------------------------------------------------------------- normalize
    def _add(self, obs: list, seen: set, der: bytes, origin: str) -> None:
        if not der or der in seen:
            return
        seen.add(der)
        try:
            cert = x509.load_der_x509_certificate(der)
            pub = cert.public_key()  # may raise on EC explicit params / unsupported key types
        except Exception:
            return
        if isinstance(pub, rsa.RSAPublicKey):
            alg, fam, size = "RSA", "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            alg, fam, size = "ECDSA", "ECC", pub.curve.key_size
        else:
            alg, fam, size = type(pub).__name__, "OTHER", None

        try:
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = None
        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            issuer = None
        try:
            expiry = cert.not_valid_after_utc.date().isoformat()
        except Exception:
            try:
                expiry = cert.not_valid_after.date().isoformat()
            except Exception:
                expiry = None

        # Natural key: the certificate subject (stable across copies); fall back to origin.
        asset_key = subject or origin
        obs.append(AssetObservation(
            asset_key=asset_key, asset_key_type="cert_subject", asset_type="certificate",
            asset_name=(subject or origin)[:500],
            location_type="cert_store",
            location_detail=f"{origin}",
            algorithm=alg, algorithm_family=fam, key_size=size,
            cert_expiry_date=expiry, cert_issuer=(issuer or "")[:500] or None,
            plugin=self.key,
        ))


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER
