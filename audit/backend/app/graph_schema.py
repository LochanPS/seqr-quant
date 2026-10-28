"""Platform-spine graph schema version.

Bumped whenever the crypto-asset graph's structure changes in a way that could affect
how historical data is interpreted. Every attestation records the version it was produced
under so old attestations stay reproducible across future schema changes (PRD 13, fork B).
"""

GRAPH_SCHEMA_VERSION = 1
