"""add attestation artifact_json (persist exact signed certificate)

Revision ID: d5e8f1a2c3b4
Revises: a1b2c3d4e5f6
Create Date: 2026-07-16

The attestation row pinned the signed fields but not the exact signed artifact, so the
downloadable certificate could not be reproduced byte-for-byte after generate-time (the
signed created_at differed from the row's default created_at). Persist the full artifact
so download + offline verification always succeed.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d5e8f1a2c3b4"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("attestations", sa.Column("artifact_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("attestations", "artifact_json")
