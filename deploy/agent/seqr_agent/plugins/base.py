"""Plugin contract (PRD 15 §4). A plugin is a small read-only collector.

    class SourcePlugin:
        key: str                              # "tls" | "cert_store" | "proxy_conf" | "pkcs11"
        def available(self) -> bool: ...      # dependencies/permissions/targets present?
        def collect(self) -> list[AssetObservation]: ...   # read-only

The runtime enables the plugins named in config, skips any whose ``available()`` is False, and
isolates each ``collect()`` in a try/except so one bad source cannot abort the run.
"""

from __future__ import annotations

import abc

from ..observation import AssetObservation


class SourcePlugin(abc.ABC):
    #: stable identifier used in config `plugins:` and as the observation `plugin` tag.
    key: str = ""

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    @abc.abstractmethod
    def available(self) -> bool:
        """True iff this plugin has what it needs to run (targets configured, libs present)."""

    @abc.abstractmethod
    def collect(self) -> list[AssetObservation]:
        """Return normalized observations. Read-only; must never mutate the host."""
