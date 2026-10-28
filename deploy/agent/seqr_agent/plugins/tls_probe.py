"""TLS endpoint probe — the original collector, now a plugin.

Opens a real TLS connection to each configured target, reads the real X.509 leaf (issuer,
expiry, public-key algorithm + size) and the negotiated TLS version/cipher, and emits a
`tls_cert` observation (the presented certificate) plus a `tls_kex` observation (the negotiated
key-exchange group). Read-only: it never sends application data.

Config:
    targets:
      - {host: lb-01.internal, port: 443, role: load-balancer}
    timeout: 8            # optional, seconds
"""

from __future__ import annotations

import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..observation import AssetObservation
from .base import SourcePlugin

# Negotiated TLS 1.3 groups that carry a PQC KEM (hybrid). Used to tag the kex observation.
_HYBRID_KEX_HINTS = ("mlkem", "kyber")


class TLSProbePlugin(SourcePlugin):
    key = "tls"

    def available(self) -> bool:
        return bool(self._targets())

    def _targets(self) -> list[dict]:
        raw = self.config.get("targets") or []
        out = []
        for t in raw:
            if isinstance(t, dict) and t.get("host"):
                out.append({"host": t["host"], "port": int(t.get("port", 443)),
                            "role": t.get("role", "tls-endpoint")})
        return out

    def collect(self) -> list[AssetObservation]:
        timeout = float(self.config.get("timeout", 8))
        obs: list[AssetObservation] = []
        for t in self._targets():
            try:
                obs.extend(self._probe(t["host"], t["port"], t["role"], timeout))
            except Exception:  # noqa: BLE001 — one dead target must not abort the run.
                continue
        return obs

    def _probe(self, host: str, port: int, role: str, timeout: float) -> list[AssetObservation]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                tls_version = ss.version()
                cipher = ss.cipher()[0] if ss.cipher() else None

        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            alg, fam, size = "RSA", "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            alg, fam, size = "ECDSA", "ECC", pub.curve.key_size
        else:
            alg, fam, size = type(pub).__name__, "OTHER", None

        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            issuer = None
        try:
            expiry = cert.not_valid_after_utc.date().isoformat()
        except Exception:
            expiry = cert.not_valid_after.date().isoformat()

        base = dict(asset_key=host, asset_key_type="hostname", asset_type="host",
                    asset_name=f"{host} ({role})", plugin=self.key)

        cert_obs = AssetObservation(
            location_type="tls_cert",
            location_detail=f"{host}:{port} · {tls_version} · {cipher}",
            algorithm=alg, algorithm_family=fam, key_size=size,
            cert_expiry_date=expiry, cert_issuer=(issuer or "")[:500] or None,
            **base,
        )
        obs = [cert_obs]

        # The negotiated cipher suite name is the key-exchange signal for TLS 1.2; for TLS 1.3
        # the group is not exposed by the stdlib, so we record the suite verbatim and let the
        # classifier tag hybrids by name when the server advertised one.
        kex_name = cipher or "unknown"
        kex_obs = AssetObservation(
            location_type="tls_kex",
            location_detail=f"{host}:{port} · {tls_version} · {cipher}",
            algorithm=kex_name,
            quantum_status="hybrid" if any(h in kex_name.lower() for h in _HYBRID_KEX_HINTS) else None,
            **base,
        )
        obs.append(kex_obs)
        return obs
