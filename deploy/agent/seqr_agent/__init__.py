"""SeQr discovery agent (PRD 15) — read-only internal crypto-posture inventory.

A plugin-driven agent that inventories internal cryptography the external scanner cannot
see (cert stores, TLS listeners on reverse proxies / load balancers, HSM slots) and pushes
Ed25519-signed observations into the SeQr spine — either live (POST /agent/observations) or
as a signed air-gap envelope (POST /agent/import) with zero network egress.

Read-only everywhere: the agent never changes customer infrastructure.
"""

__version__ = "0.1.0"
