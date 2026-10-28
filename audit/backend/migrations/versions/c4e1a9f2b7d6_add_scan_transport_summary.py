"""add scans.transport_summary

Revision ID: c4e1a9f2b7d6
Revises: b2f7a1c9d8e3
Create Date: 2026-06-28

Stores the scan-level transport posture (TLS version, cert, key exchange, active PQC
group, CDN, edge/origin) as JSON so the scan-detail page can show a posture header and
the edge/origin honesty card without re-deriving it from components.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4e1a9f2b7d6"
down_revision: Union[str, None] = "b2f7a1c9d8e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("transport_summary", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "transport_summary")
