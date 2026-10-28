"""SSH endpoint collector — offered key-exchange + host-key algorithms.

Reads a server's SSH_MSG_KEXINIT (sent before authentication) to inventory the crypto any
client would negotiate: whether the endpoint offers post-quantum key exchange
(mlkem768x25519-sha256, sntrup761x25519-sha512) and its host-key signature algorithm. No
credentials, no login attempt — purely the algorithm negotiation. Emits an `ssh_kex`
observation (the quantum-relevant key-exchange signal) plus an `ssh_hostkey` observation.

This reuses the shared scanner's KEXINIT logic (`scanner.ssh_scanner.scan_ssh`) so the agent
and the SaaS scanner classify SSH identically; the collector only normalizes the result into
the agent's observation shape.

Config:
    timeout: 10
    targets:
      - {host: bastion.internal, port: 22, role: bastion}
"""

from __future__ import annotations

from ..observation import AssetObservation
from .base import SourcePlugin


class SSHProbePlugin(SourcePlugin):
    key = "ssh"

    def available(self) -> bool:
        # Needs targets, and either an injected scanner (tests / simulation) or the shared
        # scanner's ssh module present. Mirrors pkcs11: skip cleanly when the dep is absent.
        if not self._targets():
            return False
        if callable(self.config.get("_scanner")):
            return True
        try:
            from scanner.ssh_scanner import scan_ssh  # noqa: F401
        except Exception:
            return False
        return True

    def _targets(self) -> list[dict]:
        out = []
        for t in self.config.get("targets") or []:
            if isinstance(t, dict) and t.get("host"):
                out.append({"host": t["host"], "port": int(t.get("port", 22)),
                            "role": t.get("role", "ssh-endpoint")})
        return out

    def collect(self) -> list[AssetObservation]:
        timeout = float(self.config.get("timeout", 10))
        scan = self.config.get("_scanner")
        if not callable(scan):
            from scanner.ssh_scanner import scan_ssh
            scan = lambda host, port: scan_ssh(host, port, timeout=timeout)  # noqa: E731

        obs: list[AssetObservation] = []
        for t in self._targets():
            try:
                res = scan(t["host"], t["port"])
            except Exception:  # noqa: BLE001 — one dead target must not abort the run
                continue
            obs.extend(self._normalize(t, res))
        return obs

    def _normalize(self, target: dict, res) -> list[AssetObservation]:
        # Accept either an SshScanResult-like object or a plain dict (test fixtures).
        get = (lambda k, d=None: getattr(res, k, d)) if not isinstance(res, dict) \
            else (lambda k, d=None: res.get(k, d))
        if not get("reachable", False):
            return []

        host, port, role = target["host"], target["port"], target["role"]
        kex_algs = list(get("kex_algorithms", []) or [])
        host_keys = list(get("host_key_algorithms", []) or [])
        pqc_methods = list(get("pqc_kex_methods", []) or [])
        pqc_supported = bool(get("pqc_kex_supported", False)) or bool(pqc_methods)
        banner = get("server_banner", "") or ""

        base = dict(asset_key=host, asset_key_type="hostname", asset_type="host",
                    asset_name=f"{host} ({role})", plugin=self.key)
        obs: list[AssetObservation] = []

        # Key exchange — the quantum-relevant signal. A hybrid PQC KEM upgrades the status.
        if pqc_supported:
            kex_alg, kex_fam, kex_status = (pqc_methods[0], "ML-KEM", "hybrid")
        elif kex_algs:
            kex_alg, kex_fam, kex_status = (kex_algs[0], "ECDH", "vulnerable")
        else:
            kex_alg, kex_fam, kex_status = ("unknown", None, "unknown")
        obs.append(AssetObservation(
            asset_key=host, asset_key_type="hostname", asset_type="host",
            asset_name=f"{host} ({role})", plugin=self.key,
            location_type="ssh_kex",
            location_detail=f"{host}:{port} · {banner}"[:200] or None,
            algorithm=kex_alg, algorithm_family=kex_fam, quantum_status=kex_status,
        ))

        # Host key — a signature; no standardized PQC SSH host key is deployed, so classical.
        if host_keys:
            hk = host_keys[0]
            fam = _hostkey_family(hk)
            obs.append(AssetObservation(
                **base,
                location_type="ssh_hostkey",
                location_detail=f"{host}:{port} · {', '.join(host_keys[:6])}",
                algorithm=hk, algorithm_family=fam,
                quantum_status=str(get("host_key_quantum_status", "vulnerable") or "vulnerable"),
            ))
        return obs


def _hostkey_family(alg: str) -> str:
    a = (alg or "").lower()
    if "rsa" in a:
        return "RSA"
    if "ed25519" in a or "ed448" in a or "ecdsa" in a:
        return "ECC"
    if "dss" in a or "dsa" in a:
        return "DSA"
    return "unknown"
