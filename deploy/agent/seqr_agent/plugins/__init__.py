"""Source plugins — each inventories one class of internal crypto, read-only.

`REGISTRY` maps a plugin key to its class so the runtime can enable the set named in config.
"""

from .base import SourcePlugin
from .cert_store import CertStorePlugin
from .cloud import CloudPlugin
from .k8s import K8sPlugin
from .pkcs11 import PKCS11Plugin
from .proxy_conf import ProxyConfPlugin
from .ssh_probe import SSHProbePlugin
from .tls_probe import TLSProbePlugin

REGISTRY: dict[str, type[SourcePlugin]] = {
    p.key: p
    for p in (TLSProbePlugin, CertStorePlugin, ProxyConfPlugin, PKCS11Plugin,
              SSHProbePlugin, K8sPlugin, CloudPlugin)
}

__all__ = ["SourcePlugin", "REGISTRY"]
