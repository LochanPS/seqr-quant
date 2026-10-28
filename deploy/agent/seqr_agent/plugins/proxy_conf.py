"""Reverse-proxy / load-balancer config collector — NGINX + HAProxy.

Parses TLS listener configuration (read-only) to inventory the crypto a proxy terminates:
protocols, cipher lists, ECDH curve/groups, and referenced certificate paths. Regex-based so
it needs no proxy running and no vendor library. Emits `tls_config` observations for the
negotiated crypto parameters (the KEX curve/group is the quantum-relevant signal).

Config:
    nginx: ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d"]
    haproxy: ["/etc/haproxy/haproxy.cfg"]
"""

from __future__ import annotations

import os
import re

from ..observation import AssetObservation
from .base import SourcePlugin

_NGINX_CONF_EXT = (".conf",)


class ProxyConfPlugin(SourcePlugin):
    key = "proxy_conf"

    def available(self) -> bool:
        return bool(self.config.get("nginx")) or bool(self.config.get("haproxy"))

    def collect(self) -> list[AssetObservation]:
        obs: list[AssetObservation] = []
        for f in self._files(self.config.get("nginx"), _NGINX_CONF_EXT):
            obs.extend(self._parse_nginx(f))
        for f in self._files(self.config.get("haproxy"), (".cfg", ".conf")):
            obs.extend(self._parse_haproxy(f))
        return obs

    # ---------------------------------------------------------------- file discovery
    @staticmethod
    def _files(entries, exts) -> list[str]:
        out: list[str] = []
        for e in entries or []:
            if os.path.isfile(e):
                out.append(e)
            elif os.path.isdir(e):
                for root, _d, names in os.walk(e):
                    out.extend(os.path.join(root, n) for n in names if n.lower().endswith(exts))
        return out

    @staticmethod
    def _read(fp: str) -> str:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    # ---------------------------------------------------------------- nginx
    def _parse_nginx(self, fp: str) -> list[AssetObservation]:
        text = self._read(fp)
        if not text:
            return []
        # Strip comments (whole-line and trailing).
        text = re.sub(r"#.*", "", text)
        server_name = _first(re.findall(r"\bserver_name\s+([^;]+);", text)) or os.path.basename(fp)
        server_name = server_name.split()[0] if server_name else fp

        protocols = _first(re.findall(r"\bssl_protocols\s+([^;]+);", text))
        ciphers = _first(re.findall(r"\bssl_ciphers\s+([^;]+);", text))
        curve = _first(re.findall(r"\bssl_ecdh_curve\s+([^;]+);", text))
        cert_paths = re.findall(r"\bssl_certificate\s+([^;]+);", text)

        return self._emit(
            asset_key=server_name, origin=fp, vendor="nginx",
            protocols=protocols, ciphers=ciphers, curve=curve, cert_paths=cert_paths,
        )

    # ---------------------------------------------------------------- haproxy
    def _parse_haproxy(self, fp: str) -> list[AssetObservation]:
        text = self._read(fp)
        if not text:
            return []
        text = re.sub(r"#.*", "", text)
        obs: list[AssetObservation] = []
        # Each `bind ... ssl ...` line is a TLS listener.
        for line in text.splitlines():
            line = line.strip()
            if not line.lower().startswith("bind") or "ssl" not in line.lower():
                continue
            addr = line.split()[1] if len(line.split()) > 1 else "haproxy-bind"
            ciphers = _first(re.findall(r"\bciphers?\s+(\S+)", line)) \
                or _first(re.findall(r"\bciphersuites\s+(\S+)", line))
            curve = _first(re.findall(r"\bcurves?\s+(\S+)", line))
            certs = re.findall(r"\bcrt\s+(\S+)", line)
            obs.extend(self._emit(
                asset_key=f"haproxy:{addr}", origin=fp, vendor="haproxy",
                protocols=None, ciphers=ciphers, curve=curve, cert_paths=certs,
            ))
        # Global default ciphers apply when a bind omits its own.
        gc = _first(re.findall(r"\bssl-default-bind-ciphers\s+(\S+)", text))
        gcurve = _first(re.findall(r"\bssl-default-bind-curves\s+(\S+)", text))
        if (gc or gcurve) and not obs:
            obs.extend(self._emit(asset_key=f"haproxy:{os.path.basename(fp)}", origin=fp,
                                  vendor="haproxy", protocols=None, ciphers=gc,
                                  curve=gcurve, cert_paths=[]))
        return obs

    # ---------------------------------------------------------------- normalize
    def _emit(self, *, asset_key, origin, vendor, protocols, ciphers, curve, cert_paths):
        # The ECDH curve / named group is the KEX signal. Absent an explicit hybrid group name,
        # a classical named curve (X25519/prime256v1/secp*) is quantum-vulnerable.
        algorithm = (curve or "").strip() or (ciphers or "").strip() or "tls-config"
        detail_bits = [f"{vendor}"]
        if protocols:
            detail_bits.append(f"protocols={protocols.strip()}")
        if ciphers:
            detail_bits.append(f"ciphers={ciphers.strip()[:120]}")
        if curve:
            detail_bits.append(f"curve={curve.strip()}")
        obs = [AssetObservation(
            asset_key=asset_key, asset_key_type="hostname", asset_type="reverse_proxy",
            asset_name=f"{asset_key} ({vendor})",
            location_type="tls_config",
            location_detail=" · ".join(detail_bits),
            algorithm=algorithm,
            confidence="medium",  # config-declared, not an observed handshake
            plugin=self.key,
        )]
        # Referenced certificate files, if we can read them, get a cert observation too.
        for cp in cert_paths:
            cp = cp.strip().strip('"')
            if cp and os.path.isfile(cp):
                for co in _cert_from_file(cp, asset_key, self.key):
                    obs.append(co)
        return obs


def _first(matches):
    return matches[0].strip() if matches else None


def _cert_from_file(fp: str, asset_key: str, plugin: str) -> list[AssetObservation]:
    """Parse a referenced cert file into an observation (reuses the cert_store logic)."""
    from .cert_store import CertStorePlugin
    out: list[AssetObservation] = []
    seen: set = set()
    for der in CertStorePlugin._read_certs(fp):
        CertStorePlugin(config={})._add(out, seen, der, fp)
    for o in out:
        o.plugin = plugin
        o.location_detail = f"referenced by {asset_key} ({fp})"
    return out
